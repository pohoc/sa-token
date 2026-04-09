<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Data;

/**
 * OAuth2 刷新令牌数据类
 */
class SaOAuth2RefreshToken
{
    protected string $refreshToken = '';
    protected string $accessToken = '';
    protected string $clientId = '';
    protected mixed $loginId = null;
    protected string $scope = '';
    protected int $expiresIn = -1;
    protected int $createTime = 0;

    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->$method($value);
            }
        }
        $this->createTime = $data['createTime'] ?? time();
    }

    /**
     * 转换为数组（用于序列化存储）
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'refreshToken' => $this->refreshToken,
            'accessToken'  => $this->accessToken,
            'clientId'     => $this->clientId,
            'loginId'      => $this->loginId,
            'scope'        => $this->scope,
            'expiresIn'    => $this->expiresIn,
            'createTime'   => $this->createTime,
        ];
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(string $refreshToken): static
    {
        $this->refreshToken = $refreshToken;
        return $this;
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function setAccessToken(string $accessToken): static
    {
        $this->accessToken = $accessToken;
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

    public function getLoginId(): mixed
    {
        return $this->loginId;
    }

    public function setLoginId(mixed $loginId): static
    {
        $this->loginId = $loginId;
        return $this;
    }

    public function getScope(): string
    {
        return $this->scope;
    }

    public function setScope(string $scope): static
    {
        $this->scope = $scope;
        return $this;
    }

    public function getExpiresIn(): int
    {
        return $this->expiresIn;
    }

    public function setExpiresIn(int $expiresIn): static
    {
        $this->expiresIn = $expiresIn;
        return $this;
    }

    public function getCreateTime(): int
    {
        return $this->createTime;
    }

    public function setCreateTime(int $createTime): static
    {
        $this->createTime = $createTime;
        return $this;
    }
}
