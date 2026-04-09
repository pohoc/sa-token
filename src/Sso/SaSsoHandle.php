<?php

declare(strict_types=1);

namespace SaToken\Sso;

use SaToken\Exception\SaTokenException;
use SaToken\StpUtil;
use SaToken\Util\SaFoxUtil;

/**
 * SSO 请求处理器
 *
 * 处理 SSO 登录回调、ticket 校验、单点注销等请求
 *
 * 使用示例：
 *   $handle = new SaSsoHandle($ssoConfig);
 *   // 处理登录回调
 *   $loginId = $handle->doLoginCallback($ticket, $redirect);
 *   // 处理单点注销
 *   $handle->doSloCallback($loginId);
 */
class SaSsoHandle
{
    /**
     * SSO 配置
     */
    protected SaSsoConfig $config;

    /**
     * HTTP 请求模板
     */
    protected SaSsoTemplate $template;

    /**
     * @param SaSsoConfig $config SSO 配置
     */
    public function __construct(SaSsoConfig $config)
    {
        $this->config = $config;
        $this->template = new SaSsoTemplate();
    }

    /**
     * 构建登录 URL
     *
     * @param  string|null $redirect 登录后回调地址
     * @return string      登录 URL
     */
    public function buildLoginUrl(?string $redirect = null): string
    {
        $loginUrl = $this->config->getLoginUrl();
        $backUrl = $redirect ?? $this->config->getBackUrl();

        $params = [];
        if ($backUrl !== '') {
            $params['redirect'] = $backUrl;
        }
        if ($this->config->getClientId() !== '') {
            $params['client_id'] = $this->config->getClientId();
        }

        if (!empty($params)) {
            $loginUrl .= (str_contains($loginUrl, '?') ? '&' : '?') . http_build_query($params);
        }

        return $loginUrl;
    }

    /**
     * 处理登录回调
     *
     * 验证 ticket 并完成当前系统登录
     *
     * @param  string           $ticket SSO ticket
     * @return mixed            登录 ID
     * @throws SaTokenException
     */
    public function doLoginCallback(string $ticket): mixed
    {
        if (SaFoxUtil::isEmpty($ticket)) {
            throw new SaTokenException('SSO ticket 不能为空');
        }

        // 校验 ticket
        $loginId = $this->checkTicket($ticket);
        if ($loginId === null) {
            throw new SaTokenException('SSO ticket 校验失败');
        }

        // 在当前系统完成登录
        StpUtil::login($loginId);

        return $loginId;
    }

    /**
     * 校验 ticket
     *
     * ticket 一次性使用，校验后即销毁，防重放攻击
     *
     * @param  string      $ticket SSO ticket
     * @return string|null 登录 ID，校验失败返回 null
     */
    protected function checkTicket(string $ticket): ?string
    {
        $checkUrl = $this->config->getCheckTicketUrl();
        if ($checkUrl === '') {
            throw new SaTokenException('SSO ticket 校验地址未配置');
        }

        $data = [
            'ticket'       => $ticket,
            'client_id'    => $this->config->getClientId(),
            'client_secret' => $this->config->getClientSecret(),
        ];

        try {
            $response = $this->template->post($checkUrl, $data);
            $data = json_decode($response, true);

            if (is_array($data) && isset($data['loginId'])) {
                return (string) $data['loginId'];
            }
            return null;
        } catch (SaTokenException) {
            return null;
        }
    }

    /**
     * 处理单点注销回调
     *
     * @param  mixed $loginId 登录 ID
     * @return void
     */
    public function doSloCallback(mixed $loginId): void
    {
        StpUtil::logoutByLoginId($loginId);
    }

    /**
     * 发起单点注销
     *
     * @param  string|null $redirect 注销后回调地址
     * @return string      注销 URL
     */
    public function buildSloUrl(?string $redirect = null): string
    {
        $sloUrl = $this->config->getSloUrl();

        $params = [];
        if ($this->config->getClientId() !== '') {
            $params['client_id'] = $this->config->getClientId();
        }
        if ($redirect !== null) {
            $params['redirect'] = $redirect;
        }

        if (!empty($params)) {
            $sloUrl .= (str_contains($sloUrl, '?') ? '&' : '?') . http_build_query($params);
        }

        return $sloUrl;
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
}
