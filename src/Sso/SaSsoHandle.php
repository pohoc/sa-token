<?php

declare(strict_types=1);

namespace SaToken\Sso;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
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
    protected const SLO_CALLBACK_MAX_AGE = 300;

    /** Bound attacker-controlled SSO tickets before constructing outbound requests. */
    protected const MAX_TICKET_BYTES = 4096;

    /** Bound request-controlled redirects before parsing and allowlist matching. */
    protected const MAX_REDIRECT_BYTES = 4096;

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
        $loginUrl = $this->config->getLoginUrl();
        $this->validateHttpsEndpoint($loginUrl, 'loginUrl');

        if ($currentUrl !== null) {
            $this->savePreLoginUrl($currentUrl);
        }

        $backUrl = $redirect ?? $this->config->getBackUrl();

        if ($backUrl !== '' && !$this->validateDomain($backUrl)) {
            throw new SaTokenException('SSO 回调域名不在允许列表中');
        }

        $state = bin2hex(random_bytes(16));
        $this->setStateCookie($state, 300);

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
        $hmacKey = $this->getPreLoginUrlHmacKey();
        if ($hmacKey === null) {
            // The cookie may use a parent-domain scope. Never persist an
            // unsigned redirect target that a sibling subdomain can replace.
            $this->clearPreLoginCookies();
            return;
        }

        $encoded = base64_encode($currentUrl);
        $this->setSecureCookie($this->config->getParamName(), $encoded, 300);
        $this->setSecureCookie($this->config->getParamName() . '_sig', hash_hmac('sha256', $encoded, $hmacKey), 300);
    }

    public function restorePreLoginUrl(): string
    {
        $encoded = SaTokenContext::getCookie($this->config->getParamName());
        if ($encoded === null || $encoded === '') {
            return '';
        }

        $hmacKey = $this->getPreLoginUrlHmacKey();
        $sig = SaTokenContext::getCookie($this->config->getParamName() . '_sig');
        if ($hmacKey === null || $sig === null
            || !hash_equals(hash_hmac('sha256', $encoded, $hmacKey), $sig)) {
            $this->clearPreLoginCookies();
            return '';
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
     * Resolve a secret for signing the pre-login redirect cookie.
     *
     * @return string|null
     */
    protected function getPreLoginUrlHmacKey(): ?string
    {
        $clientSecret = $this->config->getClientSecret();
        $globalConfig = SaToken::getConfig();
        foreach ([
            $clientSecret,
            $globalConfig->getSignKey(),
            $globalConfig->getHmacKey(),
            $globalConfig->getTokenEncryptKey(),
            $globalConfig->getAesKey(),
        ] as $key) {
            if (strlen($key) >= 32) {
                return $key;
            }
        }

        return null;
    }

    /**
     * 以全局 Secure/HttpOnly 配置写入 SSO 短期辅助 Cookie。
     * SameSite 固定为 Lax，确保跨站顶级导航返回时浏览器会携带 state 和预登录 URL。
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
            'Lax'
        );
    }

    /**
     * Keep the login CSRF state cookie host-only. The __Host- prefix, Secure flag,
     * root path, and absent Domain attribute make browsers reject replacement by a
     * sibling subdomain's parent-domain cookie.
     */
    protected function getStateCookieName(): string
    {
        return '__Host-' . $this->config->getParamName() . '_state';
    }

    protected function setStateCookie(string $value, int $timeout): void
    {
        SaTokenContext::setCookie(
            $this->getStateCookieName(),
            $value,
            $timeout,
            '/',
            '',
            true,
            true,
            'Lax'
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
        // A failed SSO callback must not leave a previously authenticated
        // bearer or request-local identity usable if the application catches
        // the callback exception and continues processing this request.
        SaTokenContext::denyTokenFallback();

        if (SaFoxUtil::isEmpty($ticket)) {
            throw new SaTokenException('SSO ticket 不能为空');
        }
        $this->validateTicketLength($ticket);

        $this->validateCallbackRequest($redirect, $state);

        // 校验 ticket
        $loginId = $this->checkTicket($ticket);
        if ($loginId === null) {
            throw new SaTokenException('SSO ticket 校验失败');
        }

        // 在当前系统完成登录
        $loginResult = StpUtil::login($loginId);
        SaTokenContext::setTokenOverride(StpUtil::getStpLogic()->getLoginType(), $loginResult->getAccessToken());

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

        $savedState = SaTokenContext::getCookie($this->getStateCookieName());
        if ($savedState === null || $savedState === '' || !hash_equals($savedState, $state)) {
            throw new SaTokenException('SSO state 参数校验失败，可能遭受 CSRF 攻击');
        }
        $stateKey = 'satoken:sso:state:used:' . hash('sha256', $state);
        if (!SaToken::getDao()->setIfNotExists($stateKey, '1', 300)) {
            throw new SaTokenException('SSO state 已使用，拒绝重放回调');
        }
        $this->setStateCookie('', -1);
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

        $requestNonce = bin2hex(random_bytes(16));
        $data = [
            'ticket'    => $ticket,
            'client_id' => $this->config->getClientId(),
            'timestamp' => (string) time(),
            'nonce'     => $requestNonce,
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
        if (!is_string($loginId) || $loginId === '') {
            return null;
        }

        // check-ticket 响应必须验签并绑定本次随机 nonce；只绑定 ticket 仍允许
        // 截获的同一 ticket 响应在有效期内重放，绕过认证中心的一次性消费。
        if ($clientSecret !== '') {
            $scalarResult = self::normalizeScalarMap(is_array($result) ? $result : []);
            if (!isset($scalarResult['sign'])
                || !$this->template->verifySign($scalarResult, $clientSecret, 300)) {
                throw new SaTokenException('SSO check-ticket 响应签名验证失败（或已过期），拒绝信任该响应');
            }
        }
        if (!isset($result['ticket']) || !is_string($result['ticket'])
            || !hash_equals($ticket, $result['ticket'])) {
            throw new SaTokenException('SSO check-ticket 响应与请求的 ticket 不匹配，拒绝信任该响应');
        }
        if (!isset($result['request_nonce']) || !is_string($result['request_nonce'])
            || !hash_equals($requestNonce, $result['request_nonce'])) {
            throw new SaTokenException('SSO check-ticket 响应与本次请求 nonce 不匹配，拒绝重放');
        }

        return $loginId;
    }

    /**
     * 构建 check-ticket 响应（认证中心侧使用）。
     *
     * 客户端会验证响应签名、时效（300 秒）、ticket 与本次请求 nonce 回显，
     * 认证中心的 checkTicket 端点应直接输出本方法返回的 JSON
     *
     * @return array<string, string>
     */
    public function buildCheckTicketResponse(string $ticket, mixed $loginId, string $requestNonce): array
    {
        $this->validateTicketLength($ticket);
        if ($requestNonce === '') {
            throw new SaTokenException('构建 check-ticket 响应必须回显本次请求 nonce');
        }

        $params = [
            'loginId'   => SaFoxUtil::toString($loginId),
            'ticket'    => $ticket,
            'request_nonce' => $requestNonce,
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
        // The URL is parsed again by cURL or PHP's stream wrapper before the
        // request is sent. Reject syntax that can be interpreted differently
        // by those parsers, and URL components that are not meaningful for a
        // configured HTTP endpoint.
        if (!is_array($parsed)
            || preg_match('/[\\\\\x00-\x20\x7f]/', $url) === 1
            || array_key_exists('user', $parsed)
            || array_key_exists('pass', $parsed)
            || array_key_exists('fragment', $parsed)) {
            throw new SaTokenException("SSO {$configName} URL 格式无效");
        }

        $scheme = strtolower((string) ($parsed['scheme'] ?? ''));
        $host = strtolower(rtrim((string) ($parsed['host'] ?? ''), '.'));
        $isLocal = in_array(trim($host, '[]'), ['localhost', '127.0.0.1', '::1'], true);
        if (!isset($parsed['host']) || $host === ''
            || !in_array($scheme, ['https', 'http'], true)
            || ($scheme !== 'https' && !$isLocal)) {
            throw new SaTokenException("SSO {$configName} 必须使用 HTTPS 协议");
        }
    }

    protected function validateTicketLength(string $ticket): void
    {
        if (strlen($ticket) > self::MAX_TICKET_BYTES) {
            throw new SaTokenException('SSO ticket 长度不能超过 ' . self::MAX_TICKET_BYTES . ' 字节');
        }
    }

    public function checkTicketCrossRedis(string $ticket): ?string
    {
        $this->validateTicketLength($ticket);
        $clientSecret = $this->config->getClientSecret();
        if (strlen($clientSecret) < 32) {
            throw new SaTokenException('跨 Redis ticket 校验必须配置至少 32 字节的 clientSecret');
        }

        $checkUrl = $this->config->getCrossRedisCheckUrl();
        if ($checkUrl === '') {
            throw new SaTokenException('跨 Redis ticket 校验地址未配置');
        }
        $this->validateHttpsEndpoint($checkUrl, 'crossRedisCheckUrl');

        $requestNonce = bin2hex(random_bytes(16));
        $data = [
            'ticket'    => $ticket,
            'client_id' => $this->config->getClientId(),
            'timestamp' => (string) time(),
            'nonce'     => $requestNonce,
        ];

        $data = $this->template->signParams($data, $clientSecret);

        try {
            $response = $this->template->post($checkUrl, $data);
        } catch (SaTokenException $e) {
            throw new SaTokenException('SSO ticket 校验请求失败：' . $e->getMessage(), 0, $e);
        }

        $result = json_decode($response, true);
        if (!is_array($result) || !isset($result['loginId'])
            || !is_string($result['loginId']) || $result['loginId'] === '') {
            return null;
        }

        $scalarResult = self::normalizeScalarMap($result);
        if (!isset($scalarResult['sign'])
            || !$this->template->verifySign($scalarResult, $clientSecret, 300)) {
            throw new SaTokenException('SSO check-ticket 响应签名验证失败（或已过期），拒绝信任该响应');
        }
        // 跨 Redis 响应同样绑定本次 ticket 与随机 nonce，防止同一票据的
        // 旧响应被再次提交，绕过认证中心的一次性消费。
        if (!isset($result['ticket']) || !is_string($result['ticket'])
            || !hash_equals($ticket, $result['ticket'])) {
            throw new SaTokenException('SSO check-ticket 响应与请求的 ticket 不匹配，拒绝信任该响应');
        }
        if (!isset($result['request_nonce']) || !is_string($result['request_nonce'])
            || !hash_equals($requestNonce, $result['request_nonce'])) {
            throw new SaTokenException('SSO check-ticket 响应与本次请求 nonce 不匹配，拒绝重放');
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
     * 必须配置 clientSecret 并验证请求签名（认证中心应使用
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
        if ($clientSecret === '') {
            throw new SaTokenException('处理 SSO 单点注销回调必须配置 clientSecret');
        }
        if ($params === null || !isset($params['sign']) || !is_string($params['sign'])) {
            throw new SaTokenException('SSO 单点注销回调缺少签名，拒绝处理');
        }
        if (!$this->template->verifySign($params, $clientSecret, self::SLO_CALLBACK_MAX_AGE)) {
            throw new SaTokenException('SSO 单点注销回调签名验证失败（或已过期）');
        }
        $signedLoginId = isset($params['loginId']) && is_scalar($params['loginId']) ? (string) $params['loginId'] : null;
        if ($signedLoginId === null || $signedLoginId !== SaFoxUtil::toString($loginId)) {
            throw new SaTokenException('SSO 单点注销回调 loginId 与签名数据不一致');
        }

        $nonce = $params['nonce'] ?? null;
        if (!is_string($nonce) || $nonce === '') {
            throw new SaTokenException('SSO 单点注销回调缺少 nonce，拒绝处理');
        }
        $nonceKey = 'satoken:sso:slo:nonce:' . hash('sha256', $nonce);
        // Timestamp limits replay duration; atomic storage makes each valid,
        // signed callback one-time even when duplicate requests race.
        if (!SaToken::getDao()->setIfNotExists($nonceKey, '1', self::SLO_CALLBACK_MAX_AGE * 2 + 60)) {
            throw new SaTokenException('SSO 单点注销回调 nonce 已使用，拒绝重放');
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
        $clientSecret = $this->config->getClientSecret();
        if ($clientSecret === '') {
            throw new SaTokenException('生成 SSO 单点注销回调参数必须配置 clientSecret');
        }

        $params = [
            'loginId'   => SaFoxUtil::toString($loginId),
            'timestamp' => (string) time(),
            'nonce'     => bin2hex(random_bytes(16)),
        ];

        $params = $this->template->signParams($params, $clientSecret);

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
        $this->validateHttpsEndpoint($sloUrl, 'sloUrl');

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
        if (strlen($url) > self::MAX_REDIRECT_BYTES) {
            return false;
        }

        $allowDomains = $this->config->getAllowDomains();
        if ($allowDomains === [] || $allowDomains === ['']) {
            return false;
        }

        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['scheme'], $parsed['host']) || $parsed['host'] === '') {
            return false;
        }

        // parse_url and browser URL parsers interpret backslashes differently.
        // For example, PHP treats https://evil.example\\@app.example.com as
        // user-info on app.example.com while browsers navigate to evil.example.
        // Reject parser-ambiguous URL characters and user-info before host matching.
        if (preg_match('/[\\\\\x00-\x20\x7f]/', $url) === 1
            || array_key_exists('user', $parsed)
            || array_key_exists('pass', $parsed)
            || array_key_exists('fragment', $parsed)) {
            return false;
        }

        // scheme 白名单：javascript://、data:// 等伪协议的 host 可以与白名单匹配，
        // 一旦放行就会在浏览器中执行任意脚本（XSS），只允许 http/https。
        // SSO 回调会携带一次性 ticket，非本机 HTTP 会让链路观察者窃取并抢先兑换。
        $scheme = strtolower((string) $parsed['scheme']);
        if (!in_array($scheme, ['https', 'http'], true)) {
            return false;
        }

        // 大小写与尾点归一化（EXAMPLE.com. 与 example.com 是同一主机）
        $host = strtolower((string) $parsed['host']);
        $host = rtrim($host, '.');
        $isLocal = in_array(trim($host, '[]'), ['localhost', '127.0.0.1', '::1'], true);
        if ($scheme !== 'https' && !$isLocal) {
            return false;
        }

        $defaultPort = $scheme === 'https' ? 443 : 80;
        $port = isset($parsed['port']) ? (int) $parsed['port'] : $defaultPort;
        if ($port < 1 || $port > 65535) {
            return false;
        }

        foreach ($allowDomains as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }
            if ($this->matchesAllowedDomain($host, $port, $defaultPort, $isLocal, $pattern)) {
                return true;
            }
        }

        return false;
    }

    protected function matchesAllowedDomain(string $host, int $port, int $defaultPort, bool $isLocal, string $pattern): bool
    {
        $pattern = strtolower($pattern);
        $patternPort = null;
        if (str_starts_with($pattern, '[')) {
            $closingBracket = strpos($pattern, ']');
            if ($closingBracket === false) {
                return false;
            }
            $portSuffix = substr($pattern, $closingBracket + 1);
            if ($portSuffix !== '') {
                if (preg_match('/^:([0-9]{1,5})$/D', $portSuffix, $matches) !== 1) {
                    return false;
                }
                $patternPort = (int) $matches[1];
            }
            $patternHost = substr($pattern, 0, $closingBracket + 1);
        } elseif (preg_match('/^([^:]+):([0-9]{1,5})$/D', $pattern, $matches) === 1) {
            $patternHost = $matches[1];
            $patternPort = (int) $matches[2];
        } else {
            $patternHost = $pattern;
        }

        if ($patternPort !== null && ($patternPort < 1 || $patternPort > 65535 || $patternPort !== $port)) {
            return false;
        }
        if ($patternPort === null && !$isLocal && $port !== $defaultPort) {
            return false;
        }

        $patternHost = rtrim($patternHost, '.');
        if ($patternHost === $host) {
            return true;
        }
        if (str_starts_with($patternHost, '*.')) {
            $suffix = substr($patternHost, 2);
            return $suffix !== '' && str_ends_with($host, '.' . $suffix);
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
