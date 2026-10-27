<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\SaOAuth2Handle;

/**
 * 密码模式策略
 */
class PasswordStrategy implements GrantTypeStrategyInterface
{
    protected SaOAuth2Handle $handle;

    public function __construct(SaOAuth2Handle $handle)
    {
        $this->handle = $handle;
    }

    public function getGrantType(): string
    {
        return 'password';
    }

    public function validateRequest(array $params): void
    {
        foreach (['client_id', 'client_secret', 'username', 'password'] as $parameter) {
            if (!is_string($params[$parameter] ?? null)) {
                throw new SaTokenException("参数 {$parameter} 必须是字符串");
            }
            if ($params[$parameter] === '') {
                throw new SaTokenException("缺少必需的参数: {$parameter}");
            }
        }
        if (array_key_exists('scope', $params) && !is_string($params['scope'])) {
            throw new SaTokenException('参数 scope 必须是字符串');
        }
    }

    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode
    {
        throw new SaTokenException('密码模式不支持授权码');
    }

    public function execute(array $params): SaOAuth2AccessToken
    {
        /** @var string $clientId */
        $clientId = $params['client_id'];
        /** @var string $clientSecret */
        $clientSecret = $params['client_secret'];
        /** @var string $username */
        $username = $params['username'];
        /** @var string $password */
        $password = $params['password'];
        /** @var string $scope */
        $scope = $params['scope'] ?? '';

        return $this->handle->tokenByPassword($clientId, $clientSecret, $username, $password, $scope);
    }
}
