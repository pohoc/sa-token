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
        if (!is_string($params['code'] ?? null) || $params['code'] === '') {
            throw new SaTokenException('缺少必需的参数: code');
        }
        if (!is_string($params['client_id'] ?? null) || $params['client_id'] === '') {
            throw new SaTokenException('缺少必需的参数: client_id');
        }
        // 公开客户端没有 client_secret；核心处理器会强制其授权码绑定 PKCE。
        foreach (['client_secret', 'redirect_uri', 'code_verifier'] as $parameter) {
            if (array_key_exists($parameter, $params) && !is_string($params[$parameter])) {
                throw new SaTokenException("参数 {$parameter} 必须是字符串");
            }
        }
    }

    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode
    {
        return $this->handle->generateAuthorizationCode($clientId, $loginId, $redirectUri, $scope);
    }

    public function execute(array $params): SaOAuth2AccessToken
    {
        $code = is_string($params['code'] ?? null) ? $params['code'] : '';
        $clientId = is_string($params['client_id'] ?? null) ? $params['client_id'] : '';
        $clientSecret = is_string($params['client_secret'] ?? null) ? $params['client_secret'] : '';
        $redirectUri = is_string($params['redirect_uri'] ?? null) ? $params['redirect_uri'] : '';
        $codeVerifier = is_string($params['code_verifier'] ?? null) ? $params['code_verifier'] : '';

        return $this->handle->exchangeTokenByCode($code, $clientId, $clientSecret, $redirectUri, $codeVerifier);
    }
}
