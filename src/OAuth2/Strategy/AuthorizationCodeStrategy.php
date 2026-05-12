<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\SaOAuth2Handle;

/**
 * 授权码模式策略
 */
class AuthorizationCodeStrategy implements GrantTypeStrategyInterface
{
    protected SaOAuth2Handle $handle;

    public function __construct(SaOAuth2Handle $handle)
    {
        $this->handle = $handle;
    }

    public function getGrantType(): string
    {
        return 'authorization_code';
    }

    public function validateRequest(array $params): void
    {
        if (empty($params['code'])) {
            throw new SaTokenException('缺少必需的参数: code');
        }
        if (empty($params['client_id'])) {
            throw new SaTokenException('缺少必需的参数: client_id');
        }
        if (empty($params['client_secret'])) {
            throw new SaTokenException('缺少必需的参数: client_secret');
        }
    }

    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode
    {
        return $this->handle->generateAuthorizationCode($clientId, $loginId, $redirectUri, $scope);
    }

    public function execute(array $params): SaOAuth2AccessToken
    {
        /** @var string $code */
        $code = $params['code'];
        /** @var string $clientId */
        $clientId = $params['client_id'];
        /** @var string $clientSecret */
        $clientSecret = $params['client_secret'];
        /** @var string $redirectUri */
        $redirectUri = $params['redirect_uri'] ?? '';

        return $this->handle->exchangeTokenByCode($code, $clientId, $clientSecret, $redirectUri);
    }
}
