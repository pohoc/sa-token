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
        self::$responseMap[self::getContextId()] = $response;
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
        unset(self::$requestMap[$id], self::$responseMap[$id]);
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
        $response = self::getResponse();
        if ($response === null) {
            return;
        }

        // PSR-7
        if ($response instanceof \Psr\Http\Message\ResponseInterface) {
            $newResponse = $response->withHeader($name, $value);
            self::setResponse($newResponse);
            return;
        }

        // 通用方法
        if (is_object($response) && method_exists($response, 'header')) {
            $response->header($name, $value);
        }
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
        $response = self::getResponse();
        if ($response === null) {
            return;
        }

        if ($response instanceof \Psr\Http\Message\ResponseInterface) {
            $cookieStr = self::buildCookieString($name, $value, $timeout, $path, $domain, $secure, $httpOnly, $sameSite);
            $newResponse = $response->withAddedHeader('Set-Cookie', $cookieStr);
            self::setResponse($newResponse);
            return;
        }

        if (is_object($response) && method_exists($response, 'cookie')) {
            $response->cookie($name, $value, $timeout > 0 ? time() + $timeout : 0, $path, $domain, $secure, $httpOnly);
        }
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
