<?php

declare(strict_types=1);

namespace SaToken\Sso\Mode;

use SaToken\Sso\SaSsoConfig;
use SaToken\Sso\SaSsoHandle;

/**
 * SSO 模式二：跨域认证中心统一登录
 *
 * 适用于子系统与认证中心不同域的场景
 * 通过 HTTP 重定向 + ticket 校验实现跨域单点登录
 *
 * 使用示例：
 *   $mode = new SsoModeCrossDomain($ssoConfig);
 *   $loginUrl = $mode->buildLoginUrl($redirect);
 *   $loginId = $mode->doLoginCallback($ticket);
 */
class SsoModeCrossDomain
{
    protected SaSsoHandle $handle;

    public function __construct(SaSsoConfig $config)
    {
        $this->handle = new SaSsoHandle($config);
    }

    /**
     * 构建登录重定向 URL
     *
     * @param  string|null $redirect 登录后回调地址
     * @return string
     */
    public function buildLoginUrl(?string $redirect = null, ?string $currentUrl = null): string
    {
        return $this->handle->buildLoginUrl($redirect, $currentUrl);
    }

    /**
     * 处理跨域登录回调
     *
     * @param  string      $ticket SSO ticket
     * @param  string|null $state  防 CSRF state 参数（checkState 开启时必填）
     * @return mixed       登录 ID
     */
    public function doLoginCallback(string $ticket, ?string $state = null): mixed
    {
        return $this->handle->doLoginCallback($ticket, null, $state);
    }

    /**
     * @return array{loginId: mixed, redirect: ?string}
     */
    public function doLoginCallbackWithRedirect(string $ticket): array
    {
        $loginId = $this->handle->doLoginCallback($ticket);
        $redirect = $this->handle->restorePreLoginUrl();

        return [
            'loginId'  => $loginId,
            'redirect' => $redirect,
        ];
    }

    /**
     * 构建注销重定向 URL
     *
     * @param  string|null $redirect 注销后回调地址
     * @return string
     */
    public function buildSloUrl(?string $redirect = null): string
    {
        return $this->handle->buildSloUrl($redirect);
    }

    /**
     * 处理跨域单点注销回调
     *
     * @param  mixed                     $loginId 登录 ID
     * @param  array<string, mixed>|null $params  回调请求参数（配置了 clientSecret 时必须携带签名）
     * @return void
     */
    public function doSloCallback(mixed $loginId, ?array $params = null): void
    {
        $this->handle->doSloCallback($loginId, $params);
    }
}
