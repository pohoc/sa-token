<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Data;

/**
 * OAuth2 授权码数据类
 *
 * 授权码短时效（默认 60 秒）+ 一次性使用
 */
class SaOAuth2AuthorizationCode
{
    protected string $code = '';
    protected string $clientId = '';
    protected mixed $loginId = null;
    protected string $redirectUri = '';
    protected string $scope = '';
    protected int $expiresIn = 60;
    protected int $createTime = 0;
    protected bool $used = false;

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
            'code'        => $this->code,
            'clientId'    => $this->clientId,
            'loginId'     => $this->loginId,
            'redirectUri' => $this->redirectUri,
            'scope'       => $this->scope,
            'expiresIn'   => $this->expiresIn,
            'createTime'  => $this->createTime,
        ];
    }

    /**
     * 判断授权码是否已过期
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        return time() > $this->createTime + $this->expiresIn;
    }

    /**
     * 标记为已使用
     *
     * @return void
     */
    public function markUsed(): void
    {
        $this->used = true;
    }

    /**
     * 判断是否已使用
     *
     * @return bool
     */
    public function isUsed(): bool
    {
        return $this->used;
    }

    public function getCode(): string
    {
        return $this->code;
    }

    public function setCode(string $code): static
    {
        $this->code = $code;
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

    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    public function setRedirectUri(string $redirectUri): static
    {
        $this->redirectUri = $redirectUri;
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
