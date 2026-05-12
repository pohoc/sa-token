<?php

declare(strict_types=1);

namespace SaToken;

class SaLoginResult
{
    protected string $accessToken = '';
    protected int $accessExpire = 0;
    protected string $refreshToken = '';
    protected int $refreshExpire = 0;

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function setAccessToken(string $accessToken): static
    {
        $this->accessToken = $accessToken;
        return $this;
    }

    public function getAccessExpire(): int
    {
        return $this->accessExpire;
    }

    public function setAccessExpire(int $accessExpire): static
    {
        $this->accessExpire = $accessExpire;
        return $this;
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

    public function getRefreshExpire(): int
    {
        return $this->refreshExpire;
    }

    public function setRefreshExpire(int $refreshExpire): static
    {
        $this->refreshExpire = $refreshExpire;
        return $this;
    }

    public function hasRefreshToken(): bool
    {
        return $this->refreshToken !== '';
    }

    /**
     * @return array<string, int|string>
     */
    public function toArray(): array
    {
        $data = [
            'access_token'  => $this->accessToken,
            'access_expire' => $this->accessExpire,
        ];
        if ($this->hasRefreshToken()) {
            $data['refresh_token'] = $this->refreshToken;
            $data['refresh_expire'] = $this->refreshExpire;
        }
        return $data;
    }
}
