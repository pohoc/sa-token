<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\SaOAuth2Handle;

/**
 * 隐藏式模式策略
 *
 * 实现 OAuth2.0 隐藏式模式（Implicit Grant）
 * 适用于纯前端应用，直接在回调 URL 的 hash 片段中返回访问令牌
 */
class ImplicitStrategy
{
    protected SaOAuth2Handle $handle;

    public function __construct(SaOAuth2Handle $handle)
    {
        $this->handle = $handle;
    }

    /**
     * 构建授权端点 URL（隐藏式）
     *
     * @param  string      $clientId    客户端 ID
     * @param  string      $redirectUri 回调地址
     * @param  string      $scope       权限范围
     * @param  string|null $state       状态参数
     * @return string
     */
    public function buildAuthorizeUrl(string $clientId, string $redirectUri, string $scope = '', ?string $state = null): string
    {
        $params = [
            'response_type' => 'token',
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
     * 直接生成访问令牌（隐藏式，不经过授权码）
     *
     * @param  string              $clientId 客户端 ID
     * @param  mixed               $loginId  已登录用户 ID
     * @param  string              $scope    权限范围
     * @return SaOAuth2AccessToken
     */
    public function authorize(string $clientId, mixed $loginId, string $scope = ''): SaOAuth2AccessToken
    {
        return $this->handle->generateAccessToken($clientId, $loginId, $scope);
    }
}
