<?php

declare(strict_types=1);

namespace SaToken\Util;

/**
 * 请求上下文抽象
 *
 * 封装 Cookie/Header 操作，提供协程安全的请求/响应上下文管理
 * 用户需在框架中间件中设置请求和响应对象
 *
 * 使用示例：
 *   SaTokenContext::setRequest($psr7Request);
 *   SaTokenContext::setResponse($psr7Response);
 *   $token = SaTokenContext::getHeader('satoken');
 */
class SaTokenContext
{
    /**
     * 请求对象存储（协程安全）
     * @var array<string, mixed>
     */
    protected static array $requestMap = [];

    /**
     * 响应对象存储（协程安全）
     * @var array<string, mixed>
     */
    protected static array $responseMap = [];

    /**
     * 延迟写入的响应头（按上下文隔离）
     * @var array<string, array<int, array{name: string, value: string}>>
     */
    protected static array $pendingHeadersMap = [];

    /**
     * 延迟写入的 Cookie（按上下文隔离）
     * @var array<string, array<int, array{name: string, value: string, timeout: int, path: string, domain: string, secure: bool, httpOnly: bool, sameSite: string}>>
     */
    protected static array $pendingCookiesMap = [];

    /**
     * Cookie 存储键前缀
     * @var string
     */
    protected static string $contextId = 'default';

    /**
     * 设置上下文 ID（用于协程隔离）
     *
     * @param  string $id 上下文 ID
     * @return void
     */
    public static function setContextId(string $id): void
    {
        self::$contextId = $id;
    }

    /**
     * 获取当前上下文 ID
     *
     * @return string
     */
    public static function getContextId(): string
    {
        if (class_exists(\Hyperf\Coroutine\Coroutine::class)) {
            $coroutineId = \Hyperf\Coroutine\Coroutine::id();
            if (is_int($coroutineId) && $coroutineId > 0) {
                return (string) $coroutineId;
            }
        }
        return self::$contextId;
    }

    /**
     * 设置请求对象
     *
     * @param  mixed $request 请求对象（PSR-7 ServerRequestInterface 或框架请求对象）
     * @return void
     */
    public static function setRequest(mixed $request): void
    {
        self::$requestMap[self::getContextId()] = $request;
    }

    /**
     * 获取请求对象
     *
     * @return mixed
     */
    public static function getRequest(): mixed
    {
        return self::$requestMap[self::getContextId()] ?? null;
    }

    /**
     * 设置响应对象
     *
     * @param  mixed $response 响应对象（PSR-7 ResponseInterface 或框架响应对象）
     * @return void
     */
    public static function setResponse(mixed $response): void
    {
        $id = self::getContextId();
        self::$responseMap[$id] = $response;
        self::flushPendingResponseMutations($id);
    }

    /**
     * 获取响应对象
     *
     * @return mixed
     */
    public static function getResponse(): mixed
    {
        return self::$responseMap[self::getContextId()] ?? null;
    }

    /**
     * 清除当前上下文的请求和响应
     *
     * @return void
     */
    public static function clear(): void
    {
        $id = self::getContextId();
        unset(
            self::$requestMap[$id],
            self::$responseMap[$id],
            self::$pendingHeadersMap[$id],
            self::$pendingCookiesMap[$id]
        );
    }

    /** @var array<string> */
    protected static array $trustedProxies = [];

    /**
     * @param array<string> $proxies
     */
    public static function setTrustedProxies(array $proxies): void
    {
        self::$trustedProxies = $proxies;
    }

    /**
     * @return array<string>
     */
    public static function getTrustedProxies(): array
    {
        return self::$trustedProxies;
    }

    public static function getClientIp(): ?string
    {
        $remoteAddr = null;
        $request = self::getRequest();
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $serverParams = $request->getServerParams();
            $addr = $serverParams['REMOTE_ADDR'] ?? null;
            $remoteAddr = is_string($addr) ? $addr : null;
        }

        if (empty(self::$trustedProxies)) {
            return $remoteAddr;
        }

        if ($remoteAddr === null || !in_array($remoteAddr, self::$trustedProxies, true)) {
            return $remoteAddr;
        }

        $forwarded = self::getHeader('X-Forwarded-For');
        if ($forwarded !== null && $forwarded !== '') {
            $ips = array_map('trim', explode(',', $forwarded));
            for ($i = count($ips) - 1; $i >= 0; $i--) {
                $ip = $ips[$i];
                if (!in_array($ip, self::$trustedProxies, true)) {
                    return $ip;
                }
            }
            // 链上全部为可信代理时，XFF 最左值是最初代理写入的、可能被
            // 伪造的字段；此时唯一可信的是直连地址 REMOTE_ADDR
            return $remoteAddr;
        }

        $realIp = self::getHeader('X-Real-IP');
        if ($realIp !== null && $realIp !== '') {
            return $realIp;
        }

        return $remoteAddr;
    }

    /**
     * 从请求 Header 中获取值
     *
     * @param  string      $name Header 名称
     * @return string|null
     */
    public static function getHeader(string $name): ?string
    {
        $request = self::getRequest();
        if ($request === null) {
            return null;
        }

        // PSR-7
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $headers = $request->getHeader($name);
            return !empty($headers) ? $headers[0] : null;
        }

        // 数组式访问
        if (is_object($request) && method_exists($request, 'header')) {
            $value = $request->header($name);
            return is_string($value) && $value !== '' ? $value : null;
        }

        if (is_object($request) && method_exists($request, 'getHeaderLine')) {
            $value = $request->getHeaderLine($name);
            return is_string($value) && $value !== '' ? $value : null;
        }

        return null;
    }

    /**
     * 从请求 Cookie 中获取值
     *
     * @param  string      $name Cookie 名称
     * @return string|null
     */
    public static function getCookie(string $name): ?string
    {
        $request = self::getRequest();
        if ($request === null) {
            return null;
        }

        // PSR-7
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $cookies = $request->getCookieParams();
            $value = $cookies[$name] ?? null;
            return is_string($value) ? $value : null;
        }

        if (is_object($request) && method_exists($request, 'cookie')) {
            $value = $request->cookie($name);
            return is_string($value) && $value !== '' ? $value : null;
        }

        return null;
    }

    /**
     * 从请求参数中获取值
     *
     * @param  string      $name 参数名
     * @return string|null
     */
    public static function getParam(string $name): ?string
    {
        $request = self::getRequest();
        if ($request === null) {
            return null;
        }

        // PSR-7
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $params = $request->getQueryParams();
            if (isset($params[$name]) && is_string($params[$name])) {
                return $params[$name];
            }
            $body = $request->getParsedBody();
            if (is_array($body) && isset($body[$name]) && is_string($body[$name])) {
                return $body[$name];
            }
            return null;
        }

        // 通用方法
        if (is_object($request) && method_exists($request, 'input')) {
            $value = $request->input($name);
            return is_string($value) ? $value : null;
        }
        if (is_object($request) && method_exists($request, 'param')) {
            $value = $request->param($name);
            return is_string($value) ? $value : null;
        }

        return null;
    }

    /**
     * 将 Token 值写入响应头
     *
     * @param  string $name  Header 名称
     * @param  string $value Header 值
     * @return void
     */
    public static function setHeader(string $name, string $value): void
    {
        // 头名/值中的 CR/LF/NUL 会让攻击者注入任意响应头（HTTP 响应拆分）。
        // 框架内部值均为服务端生成，但 setHeader 是公开 API——在入口统一剥离，
        // 集成方把用户可控数据写头时不再形成注入面
        $name = str_replace(["\r", "\n", "\0"], '', $name);
        $value = str_replace(["\r", "\n", "\0"], '', $value);

        $response = self::getResponse();
        if ($response === null) {
            $id = self::getContextId();
            self::$pendingHeadersMap[$id][] = [
                'name' => $name,
                'value' => $value,
            ];
            return;
        }

        self::$responseMap[self::getContextId()] = self::applyHeaderToResponse($response, $name, $value);
    }

    /**
     * 将 Token 值写入 Cookie
     *
     * @param  string $name     Cookie 名称
     * @param  string $value    Cookie 值
     * @param  int    $timeout  过期时间（秒）
     * @param  string $path     Cookie 路径
     * @param  string $domain   Cookie 域名
     * @param  bool   $secure   是否仅 HTTPS
     * @param  bool   $httpOnly 是否 HttpOnly
     * @param  string $sameSite SameSite 策略
     * @return void
     */
    public static function setCookie(
        string $name,
        string $value,
        int $timeout = 0,
        string $path = '/',
        string $domain = '',
        bool $secure = false,
        bool $httpOnly = false,
        string $sameSite = 'Lax'
    ): void {
        // 同 setHeader：Cookie 名/值/属性中的 CR/LF/NUL 会被剥离，
        // 防止经由 Set-Cookie 的响应头注入
        $name = str_replace(["\r", "\n", "\0"], '', $name);
        $value = str_replace(["\r", "\n", "\0"], '', $value);
        $path = str_replace(["\r", "\n", "\0"], '', $path);
        $domain = str_replace(["\r", "\n", "\0"], '', $domain);

        $response = self::getResponse();
        if ($response === null) {
            $id = self::getContextId();
            self::$pendingCookiesMap[$id][] = [
                'name' => $name,
                'value' => $value,
                'timeout' => $timeout,
                'path' => $path,
                'domain' => $domain,
                'secure' => $secure,
                'httpOnly' => $httpOnly,
                'sameSite' => $sameSite,
            ];
            return;
        }

        self::$responseMap[self::getContextId()] = self::applyCookieToResponse(
            $response,
            $name,
            $value,
            $timeout,
            $path,
            $domain,
            $secure,
            $httpOnly,
            $sameSite
        );
    }

    protected static function flushPendingResponseMutations(string $id): void
    {
        $response = self::$responseMap[$id] ?? null;
        if ($response === null) {
            return;
        }

        foreach (self::$pendingHeadersMap[$id] ?? [] as $header) {
            $response = self::applyHeaderToResponse($response, $header['name'], $header['value']);
        }

        foreach (self::$pendingCookiesMap[$id] ?? [] as $cookie) {
            $response = self::applyCookieToResponse(
                $response,
                $cookie['name'],
                $cookie['value'],
                $cookie['timeout'],
                $cookie['path'],
                $cookie['domain'],
                $cookie['secure'],
                $cookie['httpOnly'],
                $cookie['sameSite']
            );
        }

        self::$responseMap[$id] = $response;
        unset(self::$pendingHeadersMap[$id], self::$pendingCookiesMap[$id]);
    }

    protected static function applyHeaderToResponse(mixed $response, string $name, string $value): mixed
    {
        if ($response instanceof \Psr\Http\Message\ResponseInterface) {
            return $response->withHeader($name, $value);
        }

        if (is_object($response) && method_exists($response, 'header')) {
            $response->header($name, $value);
            return $response;
        }

        if (is_object($response) && isset($response->headers) && is_object($response->headers) && method_exists($response->headers, 'set')) {
            $response->headers->set($name, $value);
        }

        return $response;
    }

    protected static function applyCookieToResponse(
        mixed $response,
        string $name,
        string $value,
        int $timeout,
        string $path,
        string $domain,
        bool $secure,
        bool $httpOnly,
        string $sameSite
    ): mixed {
        if ($response instanceof \Psr\Http\Message\ResponseInterface) {
            $cookieStr = self::buildCookieString($name, $value, $timeout, $path, $domain, $secure, $httpOnly, $sameSite);
            return $response->withAddedHeader('Set-Cookie', $cookieStr);
        }

        if (is_object($response) && method_exists($response, 'cookie')) {
            $response->cookie($name, $value, $timeout > 0 ? time() + $timeout : 0, $path, $domain, $secure, $httpOnly);
            return $response;
        }

        if (
            is_object($response)
            && isset($response->headers)
            && is_object($response->headers)
            && method_exists($response->headers, 'setCookie')
            && class_exists(\Symfony\Component\HttpFoundation\Cookie::class)
        ) {
            $expire = $timeout > 0 ? time() + $timeout : 0;
            $cookie = new \Symfony\Component\HttpFoundation\Cookie(
                $name,
                $value,
                $expire > 0 ? $expire : 0,
                $path,
                $domain !== '' ? $domain : null,
                $secure,
                $httpOnly,
                false,
                $sameSite !== '' ? $sameSite : null
            );
            $response->headers->setCookie($cookie);
        }

        return $response;
    }

    /**
     * 构建 Cookie 字符串
     *
     * @param  string $name     Cookie 名称
     * @param  string $value    Cookie 值
     * @param  int    $timeout  过期时间（秒）
     * @param  string $path     Cookie 路径
     * @param  string $domain   Cookie 域名
     * @param  bool   $secure   是否仅 HTTPS
     * @param  bool   $httpOnly 是否 HttpOnly
     * @param  string $sameSite SameSite 策略
     * @return string
     */
    protected static function buildCookieString(
        string $name,
        string $value,
        int $timeout = 0,
        string $path = '/',
        string $domain = '',
        bool $secure = false,
        bool $httpOnly = false,
        string $sameSite = 'Lax'
    ): string {
        $parts = [$name . '=' . urlencode($value)];

        if ($timeout > 0) {
            $parts[] = 'Expires=' . gmdate('D, d M Y H:i:s T', time() + $timeout);
            $parts[] = 'Max-Age=' . $timeout;
        }

        if ($path !== '') {
            $parts[] = 'Path=' . $path;
        }

        if ($domain !== '') {
            $parts[] = 'Domain=' . $domain;
        }

        if ($secure) {
            $parts[] = 'Secure';
        }

        if ($httpOnly) {
            $parts[] = 'HttpOnly';
        }

        if ($sameSite !== '') {
            $parts[] = 'SameSite=' . $sameSite;
        }

        return implode('; ', $parts);
    }
}
