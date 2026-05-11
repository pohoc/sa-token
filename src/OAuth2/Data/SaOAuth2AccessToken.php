<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Data;

/**
 * OAuth2 访问令牌数据类
 */
class SaOAuth2AccessToken
{
    protected string $accessToken = '';
    protected int $expiresIn = 7200;
    protected string $tokenType = 'Bearer';
    protected ?string $refreshToken = null;
    protected string $scope = '';
    protected mixed $loginId = null;
    protected string $clientId = '';
    protected int $createTime = 0;
    protected string $idToken = '';

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
            'accessToken'  => $this->accessToken,
            'expiresIn'    => $this->expiresIn,
            'tokenType'    => $this->tokenType,
            'refreshToken' => $this->refreshToken,
            'scope'        => $this->scope,
            'loginId'      => $this->loginId,
            'clientId'     => $this->clientId,
            'createTime'   => $this->createTime,
            'idToken'      => $this->idToken,
        ];
    }

    /**
     * 转换为 OAuth2 标准响应格式
     *
     * @return array
     */
    public function toResponseArray(): array
    {
        $result = [
            'access_token' => $this->accessToken,
            'expires_in'   => $this->expiresIn,
            'token_type'   => $this->tokenType,
            'scope'        => $this->scope,
        ];
        if ($this->refreshToken !== null) {
            $result['refresh_token'] = $this->refreshToken;
        }
        if ($this->idToken !== '') {
            $result['id_token'] = $this->idToken;
        }
        return $result;
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

    public function getExpiresIn(): int
    {
        return $this->expiresIn;
    }

    public function setExpiresIn(int $expiresIn): static
    {
        $this->expiresIn = $expiresIn;
        return $this;
    }

    public function getTokenType(): string
    {
        return $this->tokenType;
    }

    public function setTokenType(string $tokenType): static
    {
        $this->tokenType = $tokenType;
        return $this;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(?string $refreshToken): static
    {
        $this->refreshToken = $refreshToken;
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

    public function getLoginId(): mixed
    {
        return $this->loginId;
    }

    public function setLoginId(mixed $loginId): static
    {
        $this->loginId = $loginId;
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

    public function getCreateTime(): int
    {
        return $this->createTime;
    }

    public function setCreateTime(int $createTime): static
    {
        $this->createTime = $createTime;
        return $this;
    }

    public function getIdToken(): string
    {
        return $this->idToken;
    }

    public function setIdToken(string $idToken): static
    {
        $this->idToken = $idToken;
        return $this;
    }
}
