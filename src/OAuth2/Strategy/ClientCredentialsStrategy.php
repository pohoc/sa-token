<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Strategy;

use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\SaOAuth2Handle;

/**
 * 客户端凭证模式策略
 *
 * 实现 OAuth2.0 客户端凭证模式（Client Credentials Grant）
 * 适用于服务器间通信，客户端以自己的名义请求访问令牌
 */
class ClientCredentialsStrategy
{
    protected SaOAuth2Handle $handle;

    public function __construct(SaOAuth2Handle $handle)
    {
        $this->handle = $handle;
    }

    /**
     * 通过客户端凭证获取令牌
     *
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $scope        权限范围
     * @return SaOAuth2AccessToken
     */
    public function token(string $clientId, string $clientSecret, string $scope = ''): SaOAuth2AccessToken
    {
        return $this->handle->tokenByClientCredentials($clientId, $clientSecret, $scope);
    }
}
