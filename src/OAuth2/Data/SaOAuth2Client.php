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
    /** @var array<string> */
    protected array $redirectUris = [];

    /** @var array<string> */
    protected array $grantTypes = ['authorization_code'];

    /** @var array<string> */
    protected array $scopes = [];

    /**
     * @param array<string, mixed> $data
     */
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

    /**
     * @param array<string> $redirectUris
     */
    public function setRedirectUris(array $redirectUris): static
    {
        $this->redirectUris = $redirectUris;
        return $this;
    }

    /**
     * @return array<string>
     */
    public function getGrantTypes(): array
    {
        return $this->grantTypes;
    }

    /**
     * @param array<string> $grantTypes
     */
    public function setGrantTypes(array $grantTypes): static
    {
        $this->grantTypes = $grantTypes;
        return $this;
    }

    /**
     * @return array<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @param array<string> $scopes
     */
    public function setScopes(array $scopes): static
    {
        $this->scopes = $scopes;
        return $this;
    }
}
