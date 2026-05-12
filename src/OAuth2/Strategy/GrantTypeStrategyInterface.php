<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;

/**
 * OAuth2 授权类型策略接口
 */
interface GrantTypeStrategyInterface
{
    /**
     * 获取授权类型名称
     */
    public function getGrantType(): string;

    /**
     * 验证请求参数
     *
     * @param array<string, mixed> $params
     */
    public function validateRequest(array $params): void;

    /**
     * 生成授权码（仅授权码模式）
     *
     * @param  string                    $clientId    客户端ID
     * @param  mixed                     $loginId     用户登录ID
     * @param  string                    $redirectUri 回调地址
     * @param  string                    $scope       权限范围
     * @return SaOAuth2AuthorizationCode
     */
    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode;

    /**
     * 执行授权流程，生成访问令牌
     *
     * @param  array<string, mixed> $params
     * @return SaOAuth2AccessToken
     */
    public function execute(array $params): SaOAuth2AccessToken;
}
