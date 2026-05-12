<?php

declare(strict_types=1);

namespace SaToken\Auth;

use SaToken\Exception\SaTokenException;
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

        StpUtil::login($loginId);
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
