<?php

declare(strict_types=1);

namespace SaToken\Sso;

use SaToken\SaToken;

/**
 * SSO 管理器
 *
 * SSO 模块的统一入口，根据配置自动选择对应的 SSO 模式
 *
 * 使用示例：
 *   $manager = new SaSsoManager($ssoConfig);
 *   $loginUrl = $manager->buildLoginUrl();
 *   $loginId = $manager->doLoginCallback($ticket);
 */
class SaSsoManager
{
    /**
     * SSO 配置
     */
    protected SaSsoConfig $config;

    /**
     * SSO 处理器
     */
    protected SaSsoHandle $handle;

    /**
     * @param SaSsoConfig|array|null $config SSO 配置
     */
    public function __construct(SaSsoConfig|array|null $config = null)
    {
        if ($config instanceof SaSsoConfig) {
            $this->config = $config;
        } elseif (is_array($config)) {
            $this->config = new SaSsoConfig($config);
        } else {
            $ssoConfig = SaToken::getConfig()->getSso();
            $this->config = new SaSsoConfig($ssoConfig);
        }

        $this->handle = new SaSsoHandle($this->config);
    }

    /**
     * 构建登录 URL
     *
     * @param  string|null $redirect 登录后回调地址
     * @return string
     */
    public function buildLoginUrl(?string $redirect = null): string
    {
        return $this->handle->buildLoginUrl($redirect);
    }

    /**
     * 处理登录回调
     *
     * @param  string $ticket SSO ticket
     * @return mixed  登录 ID
     */
    public function doLoginCallback(string $ticket): mixed
    {
        return $this->handle->doLoginCallback($ticket);
    }

    /**
     * 构建注销 URL
     *
     * @param  string|null $redirect 注销后回调地址
     * @return string
     */
    public function buildSloUrl(?string $redirect = null): string
    {
        return $this->handle->buildSloUrl($redirect);
    }

    /**
     * 处理单点注销回调
     *
     * @param  mixed $loginId 登录 ID
     * @return void
     */
    public function doSloCallback(mixed $loginId): void
    {
        $this->handle->doSloCallback($loginId);
    }

    /**
     * 获取 SSO 配置
     *
     * @return SaSsoConfig
     */
    public function getConfig(): SaSsoConfig
    {
        return $this->config;
    }

    /**
     * 获取 SSO 处理器
     *
     * @return SaSsoHandle
     */
    public function getHandle(): SaSsoHandle
    {
        return $this->handle;
    }
}
