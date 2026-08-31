<?php

declare(strict_types=1);

namespace SaToken\Auth;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaApiKey
{
    protected string $keyHeaderName;

    protected string $secretHeaderName;

    /** @var callable(string, string): mixed|null */
    protected $validator = null;

    /** @var array<string, array{secret: string, loginId: mixed}> */
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
        $apiKey = SaTokenContext::getHeader($this->keyHeaderName);
        $apiSecret = SaTokenContext::getHeader($this->secretHeaderName);

        if ($apiKey === null || $apiSecret === null) {
            throw new SaTokenException('缺少 API Key 或 Secret');
        }

        if ($this->validator !== null) {
            $loginId = ($this->validator)($apiKey, $apiSecret);
        } else {
            $loginId = $this->validateFromRegistry($apiKey, $apiSecret);
        }

        if ($loginId === null) {
            throw new SaTokenException('API Key 验证失败');
        }

        // 同一 Key 已存在有效会话时直接复用：每次请求全量 login() 会触发
        // 账号级分布式锁竞争、反复触发 onLogin 事件、并在多实例部署下互相踢线
        $deviceType = 'apikey:' . hash('sha256', $apiKey);
        for ($attempt = 0; $attempt < 3; $attempt++) {
            $reuseToken = $this->findReusableToken($loginId, $apiKey);
            if ($reuseToken !== null) {
                SaTokenContext::setHeader(SaToken::getConfig()->getTokenName(), $reuseToken);
                return;
            }

            try {
                StpUtil::login($loginId, (new \SaToken\SaLoginParameter())->setDeviceType($deviceType));
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
        $tokens = $logic->getTokenManager()->getTokenListByLoginId($loginId, $logic->getLoginType());
        foreach ($tokens as $item) {
            $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            $itemDevice = is_string($item['deviceType'] ?? null) ? $item['deviceType'] : '';
            if ($tokenValue !== '' && $itemDevice === $deviceType && $logic->getTokenManager()->isTokenValid($tokenValue)) {
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
        $apiKey = SaTokenContext::getHeader($this->keyHeaderName);
        $apiSecret = SaTokenContext::getHeader($this->secretHeaderName);
        return $apiKey !== null && $apiSecret !== null;
    }

    public function registerKey(string $apiKey, string $apiSecret, mixed $loginId = null): void
    {
        $this->keyRegistry[$apiKey] = [
            'secret'  => $apiSecret,
            'loginId' => $loginId,
        ];
    }

    /**
     * @param array<string, array{secret: string, loginId: mixed}> $registry
     */
    public function setKeyRegistry(array $registry): static
    {
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
