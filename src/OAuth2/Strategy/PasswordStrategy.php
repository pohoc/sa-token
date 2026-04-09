<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\SaOAuth2Handle;

/**
 * 密码模式策略
 *
 * 实现 OAuth2.0 密码模式（Resource Owner Password Credentials Grant）
 * 适用于高度信任的客户端，用户直接提供用户名和密码
 */
class PasswordStrategy
{
    protected SaOAuth2Handle $handle;

    public function __construct(SaOAuth2Handle $handle)
    {
        $this->handle = $handle;
    }

    /**
     * 通过用户名密码获取令牌
     *
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $username     用户名
     * @param  string              $password     密码
     * @param  string              $scope        权限范围
     * @return SaOAuth2AccessToken
     */
    public function token(string $clientId, string $clientSecret, string $username, string $password, string $scope = ''): SaOAuth2AccessToken
    {
        return $this->handle->tokenByPassword($clientId, $clientSecret, $username, $password, $scope);
    }
}
