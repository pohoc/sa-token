<?php

declare(strict_types=1);

namespace SaToken\Auth;

use SaToken\Exception\SaTokenException;
use SaToken\Security\SaAntiBruteUtil;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaApiKey
{
    protected string $keyHeaderName;

    protected string $secretHeaderName;

    /** @var callable(string, string): mixed|null */
    protected $validator = null;

    /** @var array<array-key, array{secret: string, loginId: mixed}> */
    protected array $keyRegistry = [];

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [])
    {
        $keyHeaderName = $config['headerName'] ?? null;
        $this->keyHeaderName = is_string($keyHeaderName) ? $keyHeaderName : 'api-key';
        $secretHeaderName = $config['secretHeaderName'] ?? null;
        $this->secretHeaderName = is_string($secretHeaderName) ? $secretHeaderName : 'api-secret';
    }

    public function checkApiKey(): void
    {
        if (SaTokenContext::hasMultipleHeaderValues($this->keyHeaderName)
            || SaTokenContext::hasMultipleHeaderValues($this->secretHeaderName)) {
            throw new SaTokenException('API Key 或 Secret Header 存在多个值');
        }

        $apiKey = SaTokenContext::getHeader($this->keyHeaderName);
        $apiSecret = SaTokenContext::getHeader($this->secretHeaderName);

        if ($apiKey === null || $apiSecret === null || trim($apiKey) === '' || trim($apiSecret) === '') {
            throw new SaTokenException('缺少 API Key 或 Secret');
        }

        SaAntiBruteUtil::checkAndThrow($apiKey, 'api-key');

        if ($this->validator !== null) {
            try {
                $loginId = ($this->validator)($apiKey, $apiSecret);
            } catch (\Throwable $exception) {
                SaAntiBruteUtil::recordFailure($apiKey, 'api-key');
                throw $exception;
            }
        } else {
            $loginId = $this->validateFromRegistry($apiKey, $apiSecret);
        }

        if ($loginId === null || is_bool($loginId) || !is_scalar($loginId) || $loginId === '') {
            SaAntiBruteUtil::recordFailure($apiKey, 'api-key');
            throw new SaTokenException('API Key 验证失败');
        }

        SaAntiBruteUtil::clearCurrentSourceFailures($apiKey, 'api-key');

        // 同一 Key 已存在有效会话时直接复用：每次请求全量 login() 会触发
        // 账号级分布式锁竞争、反复触发 onLogin 事件、并在多实例部署下互相踢线
        $deviceType = 'apikey:' . hash('sha256', $apiKey);
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $reuseToken = $this->findReusableToken($loginId, $apiKey);
            if ($reuseToken !== null) {
                StpUtil::getStpLogic()->writeTokenToResponse(
                    $reuseToken,
                    (new \SaToken\SaLoginParameter())->setWriteResponseCredentials(false)
                );
                SaTokenContext::setTokenOverride(StpUtil::getStpLogic()->getLoginType(), $reuseToken);
                return;
            }

            try {
                $result = StpUtil::login($loginId, (new \SaToken\SaLoginParameter())->setDeviceType($deviceType));
                SaTokenContext::setTokenOverride(
                    StpUtil::getStpLogic()->getLoginType(),
                    $result->getAccessToken()
                );
                return;
            } catch (SaTokenException $e) {
                // 冷启动并发：多个请求同时发现无可复用会话时，只有一个能拿到
                // 账号锁——其余短等后重查复用（赢家已建好会话）
                if (strpos($e->getMessage(), '正在处理中') === false || $attempt === 2) {
                    throw $e;
                }
                usleep(100000);
            }
        }
    }

    /**
     * 查找该身份下本 API Key 设备类型的有效 Token（可复用会话）
     */
    protected function findReusableToken(mixed $loginId, string $apiKey): ?string
    {
        $logic = StpUtil::getStpLogic();
        $deviceType = 'apikey:' . hash('sha256', $apiKey);
        $expectedLoginId = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $tokens = $logic->getTokenManager()->getTokenListByLoginId($loginId, $logic->getLoginType());
        foreach ($tokens as $item) {
            $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            $itemDevice = is_string($item['deviceType'] ?? null) ? $item['deviceType'] : '';
            if ($tokenValue !== ''
                && $itemDevice === $deviceType
                && $logic->getLoginIdByToken($tokenValue) === $expectedLoginId) {
                return $tokenValue;
            }
        }
        return null;
    }

    public function setValidator(callable $validator): static
    {
        $this->validator = $validator;
        return $this;
    }

    public function isApiKeyRequest(): bool
    {
        if (SaTokenContext::hasMultipleHeaderValues($this->keyHeaderName)
            || SaTokenContext::hasMultipleHeaderValues($this->secretHeaderName)) {
            return false;
        }

        $apiKey = SaTokenContext::getHeader($this->keyHeaderName);
        $apiSecret = SaTokenContext::getHeader($this->secretHeaderName);
        return $apiKey !== null && $apiSecret !== null;
    }

    public function registerKey(string $apiKey, string $apiSecret, mixed $loginId = null): void
    {
        if (trim($apiKey) === '' || trim($apiSecret) === '') {
            throw new SaTokenException('注册 API Key 必须提供非空 Key 和 Secret');
        }

        $this->keyRegistry[$apiKey] = [
            'secret'  => $apiSecret,
            'loginId' => $loginId,
        ];
    }

    /**
     * @param array<array-key, array{secret: string, loginId: mixed}> $registry
     */
    public function setKeyRegistry(array $registry): static
    {
        foreach ($registry as $apiKey => $entry) {
            if (trim((string) $apiKey) === '' || !is_array($entry)
                || !is_string($entry['secret'] ?? null) || trim($entry['secret']) === '') {
                throw new SaTokenException('API Key 注册表中的 Key 和 Secret 必须为非空字符串');
            }
        }

        $this->keyRegistry = $registry;
        return $this;
    }

    protected function validateFromRegistry(string $apiKey, string $apiSecret): mixed
    {
        if (!isset($this->keyRegistry[$apiKey])) {
            return null;
        }

        $entry = $this->keyRegistry[$apiKey];

        if (!hash_equals($entry['secret'], $apiSecret)) {
            return null;
        }

        return $entry['loginId'] ?? null;
    }
}
