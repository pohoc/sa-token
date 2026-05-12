<?php

declare(strict_types=1);

namespace SaToken\OAuth2;

use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\Data\SaOAuth2IdToken;
use SaToken\SaToken;

class SaOAuth2Manager
{
    protected SaOAuth2Config $config;
    protected SaOAuth2Handle $handle;

    /**
     * @param SaOAuth2Config|array<string, mixed>|null $config
     */
    public function __construct(SaOAuth2Config|array|null $config = null)
    {
        if ($config instanceof SaOAuth2Config) {
            $this->config = $config;
        } elseif (is_array($config)) {
            $this->config = new SaOAuth2Config($config);
        } else {
            $oauth2Config = SaToken::getConfig()->getOauth2();
            $this->config = new SaOAuth2Config($oauth2Config);
        }

        $this->handle = new SaOAuth2Handle($this->config);
    }

    public function registerClient(SaOAuth2Client $client): void
    {
        $this->handle->registerClient($client);
    }

    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode
    {
        return $this->handle->generateAuthorizationCode($clientId, $loginId, $redirectUri, $scope);
    }

    public function exchangeTokenByCode(string $code, string $clientId, string $clientSecret, string $redirectUri = ''): SaOAuth2AccessToken
    {
        return $this->handle->exchangeTokenByCode($code, $clientId, $clientSecret, $redirectUri);
    }

    public function refreshToken(string $refreshToken, string $clientId, string $clientSecret): SaOAuth2AccessToken
    {
        return $this->handle->refreshToken($refreshToken, $clientId, $clientSecret);
    }

    public function tokenByPassword(string $clientId, string $clientSecret, string $username, string $password, string $scope = ''): SaOAuth2AccessToken
    {
        return $this->handle->tokenByPassword($clientId, $clientSecret, $username, $password, $scope);
    }

    public function tokenByClientCredentials(string $clientId, string $clientSecret, string $scope = ''): SaOAuth2AccessToken
    {
        return $this->handle->tokenByClientCredentials($clientId, $clientSecret, $scope);
    }

    public function validateAccessToken(string $accessToken): ?SaOAuth2AccessToken
    {
        return $this->handle->validateAccessToken($accessToken);
    }

    public function revokeAccessToken(string $accessToken): void
    {
        $this->handle->revokeAccessToken($accessToken);
    }

    public function getConfig(): SaOAuth2Config
    {
        return $this->config;
    }

    public function getHandle(): SaOAuth2Handle
    {
        return $this->handle;
    }

    public function generateIdToken(string $clientId, mixed $loginId, string $scope = ''): SaOAuth2IdToken
    {
        return $this->handle->generateIdToken($clientId, $loginId, $scope);
    }
}
