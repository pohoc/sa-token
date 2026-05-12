<?php

declare(strict_types=1);

namespace SaToken\Sso;

use SaToken\Exception\SaTokenException;
use SaToken\StpUtil;
use SaToken\Util\SaFoxUtil;
use SaToken\Util\SaTokenContext;

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
    public function buildLoginUrl(?string $redirect = null, ?string $currentUrl = null): string
    {
        if ($currentUrl !== null) {
            $this->savePreLoginUrl($currentUrl);
        }

        $loginUrl = $this->config->getLoginUrl();
        $backUrl = $redirect ?? $this->config->getBackUrl();

        if ($backUrl !== '' && !$this->validateDomain($backUrl)) {
            throw new SaTokenException('SSO 回调域名不在允许列表中');
        }

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

    public function savePreLoginUrl(string $currentUrl): void
    {
        $encoded = base64_encode($currentUrl);
        SaTokenContext::setCookie($this->config->getParamName(), $encoded, 300);
    }

    public function restorePreLoginUrl(): string
    {
        $encoded = SaTokenContext::getCookie($this->config->getParamName());
        if ($encoded === null || $encoded === '') {
            return '';
        }

        $decoded = base64_decode($encoded, true);
        if ($decoded === false) {
            return '';
        }

        SaTokenContext::setCookie($this->config->getParamName(), '', -1);

        return $decoded;
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
    public function doLoginCallback(string $ticket, ?string $redirect = null): mixed
    {
        if (SaFoxUtil::isEmpty($ticket)) {
            throw new SaTokenException('SSO ticket 不能为空');
        }

        if ($redirect !== null && $redirect !== '' && !$this->validateDomain($redirect)) {
            throw new SaTokenException('SSO 回调域名不在允许列表中');
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
            'ticket'    => $ticket,
            'client_id' => $this->config->getClientId(),
            'timestamp' => (string) time(),
        ];

        $clientSecret = $this->config->getClientSecret();
        if ($clientSecret !== '') {
            $data = $this->template->signParams($data, $clientSecret);
        }

        try {
            $response = $this->template->post($checkUrl, $data);
            $data = json_decode($response, true);

            if (is_array($data) && isset($data['loginId']) && is_string($data['loginId'])) {
                return $data['loginId'];
            }
            return null;
        } catch (SaTokenException) {
            return null;
        }
    }

    public function checkTicketCrossRedis(string $ticket): mixed
    {
        $checkUrl = $this->config->getCrossRedisCheckUrl();
        if ($checkUrl === '') {
            throw new SaTokenException('跨 Redis ticket 校验地址未配置');
        }

        $data = [
            'ticket'    => $ticket,
            'client_id' => $this->config->getClientId(),
            'timestamp' => (string) time(),
        ];

        $clientSecret = $this->config->getClientSecret();
        if ($clientSecret !== '') {
            $data = $this->template->signParams($data, $clientSecret);
        }

        try {
            $response = $this->template->post($checkUrl, $data);
            $result = json_decode($response, true);

            if (is_array($result) && isset($result['loginId'])) {
                return $result['loginId'];
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
     * 校验回调域名是否在允许列表中
     *
     * @param  string $url 回调 URL
     * @return bool   是否合法
     */
    protected function validateDomain(string $url): bool
    {
        $allowDomains = $this->config->getAllowDomains();
        if (empty($allowDomains)) {
            return false;
        }

        $host = parse_url($url, PHP_URL_HOST);
        if ($host === null || $host === false) {
            return false;
        }

        foreach ($allowDomains as $pattern) {
            if ($pattern === $host) {
                return true;
            }
            if (str_starts_with($pattern, '*.')) {
                $suffix = substr($pattern, 2);
                if ($host === $suffix || str_ends_with($host, '.' . $suffix)) {
                    return true;
                }
            }
        }

        return false;
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
