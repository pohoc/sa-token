<?php

declare(strict_types=1);

namespace SaToken\OAuth2;

/**
 * OAuth2 配置类
 *
 * 封装 OAuth2.0 所需的全部配置项
 *
 * 使用示例：
 *   $config = new SaOAuth2Config([
 *       'grantTypes' => ['authorization_code', 'password'],
 *       'codeTimeout' => 60,
 *       'accessTokenTimeout' => 7200,
 *   ]);
 */
class SaOAuth2Config
{
    // 支持的授权模式
    protected array $grantTypes = ['authorization_code'];

    // 授权码有效期（秒）
    protected int $codeTimeout = 60;

    // Access Token 有效期（秒）
    protected int $accessTokenTimeout = 7200;

    // Refresh Token 有效期（秒），-1 代表不刷新
    protected int $refreshTokenTimeout = -1;

    // 是否每次生成新的 Refresh Token
    protected bool $isNewRefreshToken = false;

    // 是否启用 OpenID Connect 模式
    protected bool $openIdMode = false;

    // id_token 签发者 URL
    protected string $issuer = '';

    public function __construct(array $config = [])
    {
        foreach ($config as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->$method($value);
            }
        }
    }

    public function getGrantTypes(): array
    {
        return $this->grantTypes;
    }

    public function setGrantTypes(array $grantTypes): static
    {
        $this->grantTypes = $grantTypes;
        return $this;
    }

    public function getCodeTimeout(): int
    {
        return $this->codeTimeout;
    }

    public function setCodeTimeout(int $codeTimeout): static
    {
        $this->codeTimeout = $codeTimeout;
        return $this;
    }

    public function getAccessTokenTimeout(): int
    {
        return $this->accessTokenTimeout;
    }

    public function setAccessTokenTimeout(int $accessTokenTimeout): static
    {
        $this->accessTokenTimeout = $accessTokenTimeout;
        return $this;
    }

    public function getRefreshTokenTimeout(): int
    {
        return $this->refreshTokenTimeout;
    }

    public function setRefreshTokenTimeout(int $refreshTokenTimeout): static
    {
        $this->refreshTokenTimeout = $refreshTokenTimeout;
        return $this;
    }

    public function isNewRefreshToken(): bool
    {
        return $this->isNewRefreshToken;
    }

    public function setIsNewRefreshToken(bool $isNewRefreshToken): static
    {
        $this->isNewRefreshToken = $isNewRefreshToken;
        return $this;
    }

    public function isOpenIdMode(): bool
    {
        return $this->openIdMode;
    }

    public function setOpenIdMode(bool $openIdMode): static
    {
        $this->openIdMode = $openIdMode;
        return $this;
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function setIssuer(string $issuer): static
    {
        $this->issuer = $issuer;
        return $this;
    }
}
