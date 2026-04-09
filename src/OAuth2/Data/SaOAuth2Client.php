<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Data;

/**
 * OAuth2 客户端信息数据类
 *
 * 封装 OAuth2 客户端的注册信息
 */
class SaOAuth2Client
{
    protected string $clientId = '';
    protected string $clientSecret = '';
    protected string $clientName = '';
    protected array $redirectUris = [];
    protected array $grantTypes = ['authorization_code'];
    protected array $scopes = [];

    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->$method($value);
            }
        }
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

    public function getClientName(): string
    {
        return $this->clientName;
    }

    public function setClientName(string $clientName): static
    {
        $this->clientName = $clientName;
        return $this;
    }

    public function getRedirectUris(): array
    {
        return $this->redirectUris;
    }

    public function setRedirectUris(array $redirectUris): static
    {
        $this->redirectUris = $redirectUris;
        return $this;
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

    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function setScopes(array $scopes): static
    {
        $this->scopes = $scopes;
        return $this;
    }
}
