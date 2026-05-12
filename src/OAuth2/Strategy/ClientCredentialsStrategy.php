<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\SaOAuth2Handle;

/**
 * 客户端凭证模式策略
 */
class ClientCredentialsStrategy implements GrantTypeStrategyInterface
{
    protected SaOAuth2Handle $handle;

    public function __construct(SaOAuth2Handle $handle)
    {
        $this->handle = $handle;
    }

    public function getGrantType(): string
    {
        return 'client_credentials';
    }

    public function validateRequest(array $params): void
    {
        if (empty($params['client_id'])) {
            throw new SaTokenException('缺少必需的参数: client_id');
        }
        if (empty($params['client_secret'])) {
            throw new SaTokenException('缺少必需的参数: client_secret');
        }
    }

    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode
    {
        throw new SaTokenException('客户端凭证模式不支持授权码');
    }

    public function execute(array $params): SaOAuth2AccessToken
    {
        /** @var string $clientId */
        $clientId = $params['client_id'];
        /** @var string $clientSecret */
        $clientSecret = $params['client_secret'];
        /** @var string $scope */
        $scope = $params['scope'] ?? '';

        return $this->handle->tokenByClientCredentials($clientId, $clientSecret, $scope);
    }
}
