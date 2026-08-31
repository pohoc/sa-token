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

        $state = bin2hex(random_bytes(16));
        $this->setSecureCookie($this->config->getParamName() . '_state', $state, 300);

        $params = [];
        if ($backUrl !== '') {
            $params['redirect'] = $backUrl;
        }
        if ($this->config->getClientId() !== '') {
            $params['client_id'] = $this->config->getClientId();
        }
        $params['state'] = $state;

        $loginUrl .= (str_contains($loginUrl, '?') ? '&' : '?') . http_build_query($params);

        return $loginUrl;
    }

    public function savePreLoginUrl(string $currentUrl): void
    {
        $encoded = base64_encode($currentUrl);
        $this->setSecureCookie($this->config->getParamName(), $encoded, 300);

        // 预登录 URL 用于登录后跳转，必须防止子域 Cookie 注入篡改（开放重定向）
        $clientSecret = $this->config->getClientSecret();
        if ($clientSecret !== '') {
            $this->setSecureCookie($this->config->getParamName() . '_sig', hash_hmac('sha256', $encoded, $clientSecret), 300);
        }
    }

    public function restorePreLoginUrl(): string
    {
        $encoded = SaTokenContext::getCookie($this->config->getParamName());
        if ($encoded === null || $encoded === '') {
            return '';
        }

        $clientSecret = $this->config->getClientSecret();
        if ($clientSecret !== '') {
            $sig = SaTokenContext::getCookie($this->config->getParamName() . '_sig');
            $expectedSig = hash_hmac('sha256', $encoded, $clientSecret);
            if ($sig === null || !hash_equals($expectedSig, $sig)) {
                $this->clearPreLoginCookies();
                return '';
            }
        }

        $decoded = base64_decode($encoded, true);
        if ($decoded === false || !$this->validateDomain($decoded)) {
            // 未通过白名单校验的预登录地址一律丢弃，绝不作为跳转目标返回
            $this->clearPreLoginCookies();
            return '';
        }

        $this->clearPreLoginCookies();

        return $decoded;
    }

    protected function clearPreLoginCookies(): void
    {
        $this->setSecureCookie($this->config->getParamName(), '', -1);
        $this->setSecureCookie($this->config->getParamName() . '_sig', '', -1);
    }

    /**
     * 以全局安全配置（Secure/HttpOnly/SameSite）写入 Cookie，
     * 避免 SSO 辅助 Cookie 绕过框架的 Cookie 安全标准
     */
    protected function setSecureCookie(string $name, string $value, int $timeout): void
    {
        $globalConfig = \SaToken\SaToken::getConfig();
        SaTokenContext::setCookie(
            $name,
            $value,
            $timeout,
            $globalConfig->getCookiePath(),
            $globalConfig->getCookieDomain(),
            $globalConfig->isCookieSecure(),
            $globalConfig->isCookieHttpOnly(),
            $globalConfig->getCookieSameSite()
        );
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
    public function doLoginCallback(string $ticket, ?string $redirect = null, ?string $state = null): mixed
    {
        if (SaFoxUtil::isEmpty($ticket)) {
            throw new SaTokenException('SSO ticket 不能为空');
        }

        $this->validateCallbackRequest($redirect, $state);

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
     * 校验回调请求的 state（防登录 CSRF）与 redirect 域名白名单。
     *
     * state 强制校验（checkState=true 默认）：state 必须存在且与
     * buildLoginUrl 时写入的 Cookie 一致——不传 state 即跳过校验等于没有 CSRF 防护。
     * 该方法同时供 SaSsoManager 的跨 Redis 分支调用，保证两条路径防护一致
     *
     * @throws SaTokenException
     */
    public function validateCallbackRequest(?string $redirect, ?string $state): void
    {
        if ($redirect !== null && $redirect !== '' && !$this->validateDomain($redirect)) {
            throw new SaTokenException('SSO 回调域名不在允许列表中');
        }

        if (!$this->config->isCheckState()) {
            return;
        }

        if ($state === null || $state === '') {
            throw new SaTokenException('SSO 回调缺少 state 参数（防 CSRF 必需），请通过 buildLoginUrl 发起登录');
        }

        $savedState = SaTokenContext::getCookie($this->config->getParamName() . '_state');
        if ($savedState === null || $savedState === '' || !hash_equals($savedState, $state)) {
            throw new SaTokenException('SSO state 参数校验失败，可能遭受 CSRF 攻击');
        }
        $this->setSecureCookie($this->config->getParamName() . '_state', '', -1);
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
        $this->validateHttpsEndpoint($checkUrl, 'checkTicketUrl');

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
        } catch (SaTokenException $e) {
            // 网络失败与配置错误都汇入校验失败，但不静默吞掉异常细节
            throw new SaTokenException('SSO ticket 校验请求失败：' . $e->getMessage(), 0, $e);
        }

        $result = json_decode($response, true);
        $loginId = is_array($result) ? ($result['loginId'] ?? null) : null;
        if (!is_string($loginId)) {
            return null;
        }

        // check-ticket 响应必须验签：不验证响应来源意味着中间人可伪造 loginId 直接接管任意账号。
        // 响应携带 timestamp 时校验时效（300 秒），携带 ticket 回显时校验请求绑定——
        // 否则一次截获的合法响应可对任意后续 ticket 校验离线重放（账号接管）
        if ($clientSecret !== '') {
            $scalarResult = self::normalizeScalarMap(is_array($result) ? $result : []);
            if (!isset($scalarResult['sign'])
                || !$this->template->verifySign($scalarResult, $clientSecret, 300)) {
                throw new SaTokenException('SSO check-ticket 响应签名验证失败（或已过期），拒绝信任该响应');
            }
            if (isset($result['ticket']) && is_string($result['ticket'])
                && !hash_equals($ticket, $result['ticket'])) {
                throw new SaTokenException('SSO check-ticket 响应与请求的 ticket 不匹配，拒绝信任该响应');
            }
        }

        return $loginId;
    }

    /**
     * 构建 check-ticket 响应（认证中心侧使用）。
     *
     * 客户端会验证响应签名与时效（300 秒）以及 ticket 回显绑定，
     * 认证中心的 checkTicket 端点应直接输出本方法返回的 JSON
     *
     * @return array<string, string>
     */
    public function buildCheckTicketResponse(string $ticket, mixed $loginId): array
    {
        $params = [
            'loginId'   => SaFoxUtil::toString($loginId),
            'ticket'    => $ticket,
            'timestamp' => (string) time(),
        ];

        $clientSecret = $this->config->getClientSecret();
        if ($clientSecret !== '') {
            $params = $this->template->signParams($params, $clientSecret);
        }

        return $params;
    }

    /**
     * 校验出站端点必须为 HTTPS（本地回环除外），
     * 明文传输 ticket/签名响应等于把会话建立过程暴露给中间人
     */
    protected function validateHttpsEndpoint(string $url, string $configName): void
    {
        $parsed = parse_url($url);
        $scheme = strtolower((string) ($parsed['scheme'] ?? ''));
        $host = strtolower((string) ($parsed['host'] ?? ''));
        $isLocal = $host === 'localhost' || $host === '127.0.0.1' || $host === '::1';
        if ($scheme !== 'https' && !$isLocal) {
            throw new SaTokenException("SSO {$configName} 必须使用 HTTPS 协议");
        }
    }

    public function checkTicketCrossRedis(string $ticket): ?string
    {
        $checkUrl = $this->config->getCrossRedisCheckUrl();
        if ($checkUrl === '') {
            throw new SaTokenException('跨 Redis ticket 校验地址未配置');
        }
        $this->validateHttpsEndpoint($checkUrl, 'crossRedisCheckUrl');

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
        } catch (SaTokenException $e) {
            throw new SaTokenException('SSO ticket 校验请求失败：' . $e->getMessage(), 0, $e);
        }

        $result = json_decode($response, true);
        if (!is_array($result) || !isset($result['loginId']) || !is_string($result['loginId'])) {
            return null;
        }

        if ($clientSecret !== '') {
            $scalarResult = self::normalizeScalarMap($result);
            if (!isset($scalarResult['sign'])
                || !$this->template->verifySign($scalarResult, $clientSecret)) {
                throw new SaTokenException('SSO check-ticket 响应签名验证失败，拒绝信任该响应');
            }
        }

        return $result['loginId'];
    }

    /**
     * 将 mixed 数组归一化为 string map（仅保留标量值），供签名规范化使用
     *
     * @param  array<array-key, mixed> $data
     * @return array<string, string>
     */
    protected static function normalizeScalarMap(array $data): array
    {
        $normalized = [];
        foreach ($data as $k => $v) {
            if (is_scalar($v)) {
                $normalized[(string) $k] = (string) $v;
            }
        }
        return $normalized;
    }

    /**
     * 处理单点注销回调
     *
     * 配置了 clientSecret 时强制验证请求签名（认证中心应使用
     * buildSloCallbackParams / SaSsoTemplate::signParams 生成带 sign 的参数），
     * 防止任何人伪造 loginId 强制注销全站用户
     *
     * @param  mixed                    $loginId 登录 ID
     * @param  array<string,mixed>|null $params  回调请求参数（含 sign），未传时仅在未配置密钥下放行
     * @return void
     * @throws SaTokenException
     */
    public function doSloCallback(mixed $loginId, ?array $params = null): void
    {
        $clientSecret = $this->config->getClientSecret();
        if ($clientSecret !== '') {
            if ($params === null || !isset($params['sign']) || !is_string($params['sign'])) {
                throw new SaTokenException('SSO 单点注销回调缺少签名，拒绝处理');
            }
            if (!$this->template->verifySign($params, $clientSecret, 300)) {
                throw new SaTokenException('SSO 单点注销回调签名验证失败（或已过期）');
            }
            $signedLoginId = isset($params['loginId']) && is_scalar($params['loginId']) ? (string) $params['loginId'] : null;
            if ($signedLoginId !== null && $signedLoginId !== SaFoxUtil::toString($loginId)) {
                throw new SaTokenException('SSO 单点注销回调 loginId 与签名数据不一致');
            }
        }

        StpUtil::logoutByLoginId($loginId);
    }

    /**
     * 构建单点注销回调参数（认证中心侧使用，自动附带签名）
     *
     * @return array<string, string>
     */
    public function buildSloCallbackParams(mixed $loginId): array
    {
        $params = [
            'loginId'   => SaFoxUtil::toString($loginId),
            'timestamp' => (string) time(),
        ];

        $clientSecret = $this->config->getClientSecret();
        if ($clientSecret !== '') {
            $params = $this->template->signParams($params, $clientSecret);
        }

        return $params;
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

        if ($redirect !== null && $redirect !== '' && !$this->validateDomain($redirect)) {
            throw new SaTokenException('SSO 注销回调域名不在允许列表中');
        }

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
        if ($allowDomains === [] || $allowDomains === ['']) {
            return false;
        }

        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['scheme'], $parsed['host']) || $parsed['host'] === '') {
            return false;
        }

        // scheme 白名单：javascript://、data:// 等伪协议的 host 可以与白名单匹配，
        // 一旦放行就会在浏览器中执行任意脚本（XSS），只允许 http/https
        $scheme = strtolower((string) $parsed['scheme']);
        if (!in_array($scheme, ['https', 'http'], true)) {
            return false;
        }

        // 大小写与尾点归一化（EXAMPLE.com. 与 example.com 是同一主机）
        $host = strtolower((string) $parsed['host']);
        $host = rtrim($host, '.');

        foreach ($allowDomains as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }
            $pattern = strtolower(rtrim($pattern, '.'));
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
