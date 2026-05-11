<?php

declare(strict_types=1);

namespace SaToken\Sso;

/**
 * SSO 配置类
 *
 * 封装 SSO 单点登录所需的全部配置项
 *
 * 使用示例：
 *   $config = new SaSsoConfig([
 *       'loginUrl' => 'https://auth.example.com/login',
 *       'authUrl'  => 'https://auth.example.com/auth',
 *       'mode'     => 'cross-domain',
 *   ]);
 */
class SaSsoConfig
{
    // SSO 登录地址
    protected string $loginUrl = '';

    // SSO 认证中心 URL
    protected string $authUrl = '';

    // SSO 回调地址
    protected string $backUrl = '';

    // SSO ticket 校验地址
    protected string $checkTicketUrl = '';

    // SSO 单点注销地址
    protected string $sloUrl = '';

    // SSO 模式（same-domain / cross-domain / front-separate）
    protected string $mode = 'same-domain';

    // SSO Client ID
    protected string $clientId = '';

    // SSO Client Secret
    protected string $clientSecret = '';

    // SSO 允许的回调域名列表
    protected array $allowDomains = [];

    // 参数防丢 Cookie/Query 参数名
    protected string $paramName = 'sso_params';

    // 是否跨 Redis（SSO 客户端与服务端使用不同 Redis 实例）
    protected bool $crossRedis = false;

    // 跨 Redis ticket 校验地址
    protected string $crossRedisCheckUrl = '';

    public function __construct(array $config = [])
    {
        foreach ($config as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->$method($value);
            }
        }
    }

    public function getLoginUrl(): string
    {
        return $this->loginUrl;
    }

    public function setLoginUrl(string $loginUrl): static
    {
        $this->loginUrl = $loginUrl;
        return $this;
    }

    public function getAuthUrl(): string
    {
        return $this->authUrl;
    }

    public function setAuthUrl(string $authUrl): static
    {
        $this->authUrl = $authUrl;
        return $this;
    }

    public function getBackUrl(): string
    {
        return $this->backUrl;
    }

    public function setBackUrl(string $backUrl): static
    {
        $this->backUrl = $backUrl;
        return $this;
    }

    public function getCheckTicketUrl(): string
    {
        return $this->checkTicketUrl;
    }

    public function setCheckTicketUrl(string $checkTicketUrl): static
    {
        $this->checkTicketUrl = $checkTicketUrl;
        return $this;
    }

    public function getSloUrl(): string
    {
        return $this->sloUrl;
    }

    public function setSloUrl(string $sloUrl): static
    {
        $this->sloUrl = $sloUrl;
        return $this;
    }

    public function getMode(): string
    {
        return $this->mode;
    }

    public function setMode(string $mode): static
    {
        $this->mode = $mode;
        return $this;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function setClientId(string $clientId): static
    {
        $this->clientId = $clientId;
        return $this;
    }

    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    public function setClientSecret(string $clientSecret): static
    {
        $this->clientSecret = $clientSecret;
        return $this;
    }

    public function getAllowDomains(): array
    {
        return $this->allowDomains;
    }

    public function setAllowDomains(array $allowDomains): static
    {
        $this->allowDomains = $allowDomains;
        return $this;
    }

    public function getParamName(): string
    {
        return $this->paramName;
    }

    public function setParamName(string $paramName): static
    {
        $this->paramName = $paramName;
        return $this;
    }

    public function isCrossRedis(): bool
    {
        return $this->crossRedis;
    }

    public function setCrossRedis(bool $crossRedis): static
    {
        $this->crossRedis = $crossRedis;
        return $this;
    }

    public function getCrossRedisCheckUrl(): string
    {
        return $this->crossRedisCheckUrl;
    }

    public function setCrossRedisCheckUrl(string $crossRedisCheckUrl): static
    {
        $this->crossRedisCheckUrl = $crossRedisCheckUrl;
        return $this;
    }
}
