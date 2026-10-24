<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\Exception\SaTokenException;
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
    public function buildAuthorizeUrl(string $clientId, string $redirectUri, string $scope = '', ?string $state = null, ?string $nonce = null): string
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
        if ($nonce !== null) {
            $params['nonce'] = $nonce;
        }

        return '/oauth2/authorize?' . http_build_query($params);
    }

    /**
     * 直接生成访问令牌（隐藏式，不经过授权码）
     *
     * 隐式模式已被 OAuth 2.1 废弃（令牌经 URL 前端暴露，无法保护客户端身份），
     * 仅为向后兼容保留。调用会校验客户端存在、redirect_uri 已注册且
     * grant_type/scope 在客户端授权范围内
     *
     * @param  string              $clientId    客户端 ID
     * @param  mixed               $loginId     已登录用户 ID
     * @param  string              $scope       权限范围
     * @param  string              $redirectUri 回调地址（必须已注册）
     * @return SaOAuth2AccessToken
     * @throws SaTokenException
     */
    public function authorize(string $clientId, mixed $loginId, string $scope = '', string $redirectUri = '', string $nonce = ''): SaOAuth2AccessToken
    {
        $this->handle->validateGrantTypePublic($clientId, 'implicit');
        if ($redirectUri === '') {
            throw new SaTokenException('隐式授权必须提供已注册的 redirect_uri');
        }
        $this->handle->validateRedirectUriPublic($clientId, $redirectUri);
        $scopes = preg_split('/\s+/', trim($scope)) ?: [];
        $isOpenIdRequest = $this->handle->isOpenIdMode() && in_array('openid', $scopes, true);
        if ($isOpenIdRequest && $nonce === '') {
            throw new SaTokenException('OpenID Connect 隐式授权必须提供 nonce');
        }

        return $this->handle->generateAccessToken(
            $clientId,
            $loginId,
            $scope,
            '',
            false,
            $nonce,
            $isOpenIdRequest
        );
    }
}
