<?php

declare(strict_types=1);

namespace SaToken\OAuth2;

use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\SaToken;

/**
 * OAuth2 管理器
 *
 * OAuth2 模块的统一入口，客户端注册与令牌管理
 *
 * 使用示例：
 *   $manager = new SaOAuth2Manager();
 *   $manager->registerClient($client);
 *   $code = $manager->generateAuthorizationCode($clientId, $loginId, $redirectUri);
 *   $token = $manager->exchangeTokenByCode($code, $clientId, $secret, $redirectUri);
 */
class SaOAuth2Manager
{
    protected SaOAuth2Config $config;
    protected SaOAuth2Handle $handle;

    /**
     * @param SaOAuth2Config|array|null $config OAuth2 配置
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

    /**
     * 注册客户端
     *
     * @param  SaOAuth2Client $client 客户端信息
     * @return void
     */
    public function registerClient(SaOAuth2Client $client): void
    {
        $this->handle->registerClient($client);
    }

    /**
     * 生成授权码
     *
     * @param  string                    $clientId    客户端 ID
     * @param  mixed                     $loginId     资源所有者登录 ID
     * @param  string                    $redirectUri 回调地址
     * @param  string                    $scope       权限范围
     * @return SaOAuth2AuthorizationCode
     */
    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode
    {
        return $this->handle->generateAuthorizationCode($clientId, $loginId, $redirectUri, $scope);
    }

    /**
     * 通过授权码换取访问令牌
     *
     * @param  string              $code         授权码
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $redirectUri  回调地址
     * @return SaOAuth2AccessToken
     */
    public function exchangeTokenByCode(string $code, string $clientId, string $clientSecret, string $redirectUri = ''): SaOAuth2AccessToken
    {
        return $this->handle->exchangeTokenByCode($code, $clientId, $clientSecret, $redirectUri);
    }

    /**
     * 通过刷新令牌获取新的访问令牌
     *
     * @param  string              $refreshToken 刷新令牌
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @return SaOAuth2AccessToken
     */
    public function refreshToken(string $refreshToken, string $clientId, string $clientSecret): SaOAuth2AccessToken
    {
        return $this->handle->refreshToken($refreshToken, $clientId, $clientSecret);
    }

    /**
     * 密码模式获取令牌
     *
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $username     用户名
     * @param  string              $password     密码
     * @param  string              $scope        权限范围
     * @return SaOAuth2AccessToken
     */
    public function tokenByPassword(string $clientId, string $clientSecret, string $username, string $password, string $scope = ''): SaOAuth2AccessToken
    {
        return $this->handle->tokenByPassword($clientId, $clientSecret, $username, $password, $scope);
    }

    /**
     * 客户端凭证模式获取令牌
     *
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $scope        权限范围
     * @return SaOAuth2AccessToken
     */
    public function tokenByClientCredentials(string $clientId, string $clientSecret, string $scope = ''): SaOAuth2AccessToken
    {
        return $this->handle->tokenByClientCredentials($clientId, $clientSecret, $scope);
    }

    /**
     * 验证访问令牌
     *
     * @param  string                   $accessToken 访问令牌
     * @return SaOAuth2AccessToken|null
     */
    public function validateAccessToken(string $accessToken): ?SaOAuth2AccessToken
    {
        return $this->handle->validateAccessToken($accessToken);
    }

    /**
     * 撤销访问令牌
     *
     * @param  string $accessToken 访问令牌
     * @return void
     */
    public function revokeAccessToken(string $accessToken): void
    {
        $this->handle->revokeAccessToken($accessToken);
    }

    /**
     * 获取配置
     */
    public function getConfig(): SaOAuth2Config
    {
        return $this->config;
    }

    /**
     * 获取处理器
     */
    public function getHandle(): SaOAuth2Handle
    {
        return $this->handle;
    }
}
