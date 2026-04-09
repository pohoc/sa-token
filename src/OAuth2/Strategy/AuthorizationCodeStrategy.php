<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\SaOAuth2Handle;

/**
 * 授权码模式策略
 *
 * 实现 OAuth2.0 授权码模式（Authorization Code Grant）
 *
 * 流程：
 * 1. 客户端将用户重定向到授权端点
 * 2. 用户授权后，授权服务器返回授权码
 * 3. 客户端使用授权码向令牌端点请求访问令牌
 */
class AuthorizationCodeStrategy
{
    protected SaOAuth2Handle $handle;

    public function __construct(SaOAuth2Handle $handle)
    {
        $this->handle = $handle;
    }

    /**
     * 构建授权端点 URL
     *
     * @param  string      $clientId    客户端 ID
     * @param  string      $redirectUri 回调地址
     * @param  string      $scope       权限范围
     * @param  string|null $state       状态参数（防 CSRF）
     * @return string      授权端点 URL
     */
    public function buildAuthorizeUrl(string $clientId, string $redirectUri, string $scope = '', ?string $state = null): string
    {
        $params = [
            'response_type' => 'code',
            'client_id'     => $clientId,
            'redirect_uri'  => $redirectUri,
        ];

        if ($scope !== '') {
            $params['scope'] = $scope;
        }
        if ($state !== null) {
            $params['state'] = $state;
        }

        return '/oauth2/authorize?' . http_build_query($params);
    }

    /**
     * 处理授权请求（授权端点）
     *
     * @param  string                    $clientId    客户端 ID
     * @param  mixed                     $loginId     已登录用户 ID
     * @param  string                    $redirectUri 回调地址
     * @param  string                    $scope       权限范围
     * @return SaOAuth2AuthorizationCode
     */
    public function authorize(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode
    {
        return $this->handle->generateAuthorizationCode($clientId, $loginId, $redirectUri, $scope);
    }

    /**
     * 处理令牌请求（令牌端点）
     *
     * @param  string              $code         授权码
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $redirectUri  回调地址
     * @return SaOAuth2AccessToken
     */
    public function token(string $code, string $clientId, string $clientSecret, string $redirectUri = ''): SaOAuth2AccessToken
    {
        return $this->handle->exchangeTokenByCode($code, $clientId, $clientSecret, $redirectUri);
    }
}
