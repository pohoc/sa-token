<?php

declare(strict_types=1);

namespace SaToken\Util;

use SaToken\Exception\SaTokenException;

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

    /** @var array<string, array<string, string>> Request-scoped authentication token overrides by login type. */
    protected static array $tokenOverridesMap = [];

    /** @var array<string, true> Requests that must not fall back to native bearer credentials after auth failure. */
    protected static array $tokenFallbackDeniedMap = [];

    /** @var array<string, array<string, mixed>> Request-local extension state. */
    protected static array $requestScopedValuesMap = [];

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
                return 'hyperf:' . $coroutineId;
            }
        }

        if (class_exists(\Swoole\Coroutine::class)) {
            $coroutineId = \Swoole\Coroutine::getCid();
            if (is_int($coroutineId) && $coroutineId >= 0) {
                return 'swoole:' . $coroutineId;
            }
        }

        $fiber = \Fiber::getCurrent();
        if ($fiber !== null) {
            return 'fiber:' . spl_object_id($fiber);
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
        $contextId = self::getContextId();
        self::$requestMap[$contextId] = $request;
        // A reused context ID must not retain the previous request's response
        // or deferred headers/cookies, which could otherwise receive or expose
        // another user's authentication credentials.
        unset(
            self::$responseMap[$contextId],
            self::$pendingHeadersMap[$contextId],
            self::$pendingCookiesMap[$contextId],
            self::$tokenOverridesMap[$contextId],
            self::$tokenFallbackDeniedMap[$contextId],
            self::$requestScopedValuesMap[$contextId]
        );
        // SaRouter caches the normalized request path by context ID. A long-
        // running worker may reuse that ID even if cleanup was skipped after
        // an exception, so every new request starts with fresh route state.
        \SaToken\SaRouter::clearContext();
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
            self::$pendingCookiesMap[$id],
            self::$tokenOverridesMap[$id],
            self::$tokenFallbackDeniedMap[$id],
            self::$requestScopedValuesMap[$id]
        );
    }

    public static function setRequestScopedValue(string $key, mixed $value): void
    {
        self::$requestScopedValuesMap[self::getContextId()][$key] = $value;
    }

    public static function getRequestScopedValue(string $key, mixed $default = null): mixed
    {
        return self::$requestScopedValuesMap[self::getContextId()][$key] ?? $default;
    }

    public static function removeRequestScopedValue(string $key): void
    {
        $id = self::getContextId();
        unset(self::$requestScopedValuesMap[$id][$key]);
        if ((self::$requestScopedValuesMap[$id] ?? []) === []) {
            unset(self::$requestScopedValuesMap[$id]);
        }
    }

    public static function setTokenOverride(string $loginType, ?string $tokenValue): void
    {
        $id = self::getContextId();
        if ($tokenValue === null) {
            unset(self::$tokenOverridesMap[$id][$loginType]);
            if ((self::$tokenOverridesMap[$id] ?? []) === []) {
                unset(self::$tokenOverridesMap[$id]);
            }
            return;
        }

        self::$tokenOverridesMap[$id][$loginType] = $tokenValue;
    }

    public static function getTokenOverride(string $loginType): ?string
    {
        $id = self::getContextId();
        if (array_key_exists($loginType, self::$tokenOverridesMap[$id] ?? [])) {
            return self::$tokenOverridesMap[$id][$loginType];
        }

        return isset(self::$tokenFallbackDeniedMap[$id]) ? '' : null;
    }

    /** Prevent every login type in this request from falling back to native token sources. */
    public static function denyTokenFallback(): void
    {
        self::$tokenFallbackDeniedMap[self::getContextId()] = true;
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
        } elseif (is_object($request)) {
            // When the library has an explicit proxy allowlist, resolve the
            // forwarding chain from the raw peer address below. A framework's
            // getClientIp()/ip() may trust a different proxy configuration and
            // would otherwise bypass this allowlist entirely.
            if (method_exists($request, 'getServerParams')) {
                $serverParams = $request->getServerParams();
                $addr = is_array($serverParams) ? ($serverParams['REMOTE_ADDR'] ?? null) : null;
                $remoteAddr = is_string($addr) ? $addr : null;
            } else {
                // Symfony/Laravel request objects expose the raw peer address
                // through their server ParameterBag instead of getServerParams().
                $properties = get_object_vars($request);
                $server = $properties['server'] ?? null;
                if (is_array($server)) {
                    $addr = $server['REMOTE_ADDR'] ?? null;
                    $remoteAddr = is_string($addr) ? $addr : null;
                } elseif (is_object($server)) {
                    try {
                        if (method_exists($server, 'get')) {
                            $addr = $server->get('REMOTE_ADDR');
                            $remoteAddr = is_string($addr) ? $addr : null;
                        } elseif (method_exists($server, 'all')) {
                            $serverParams = $server->all();
                            $addr = is_array($serverParams) ? ($serverParams['REMOTE_ADDR'] ?? null) : null;
                            $remoteAddr = is_string($addr) ? $addr : null;
                        }
                    } catch (\Throwable) {
                        $remoteAddr = null;
                    }
                }
            }

            // Framework request wrappers commonly expose the resolved address
            // directly (Laravel/Symfony: getClientIp; ThinkPHP: ip). Prefer
            // that over forwarded headers, whose trust is adapter-specific.
            if (empty(self::$trustedProxies)) {
                foreach (['getClientIp', 'ip'] as $method) {
                    if (method_exists($request, $method)) {
                        $addr = $request->$method();
                        if (is_string($addr) && $addr !== '') {
                            $remoteAddr = $addr;
                            break;
                        }
                    }
                }
            }
        }

        if (empty(self::$trustedProxies)) {
            return $remoteAddr;
        }

        if ($remoteAddr === null || !self::isTrustedProxyIp($remoteAddr)) {
            return self::normalizeIpAddress($remoteAddr);
        }

        $forwarded = self::getForwardedHeader('X-Forwarded-For');
        if ($forwarded !== null && $forwarded !== '') {
            $ips = array_map('trim', explode(',', $forwarded));
            for ($i = count($ips) - 1; $i >= 0; $i--) {
                $ip = $ips[$i];
                if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                    // Never collapse malformed forwarded chains into the
                    // trusted proxy's shared address: that would let one
                    // client exhaust the brute-force bucket for every user
                    // behind the proxy.
                    return null;
                }
                if (!self::isTrustedProxyIp($ip)) {
                    return self::normalizeIpAddress($ip);
                }
            }
            // No client address can be established when every hop is itself
            // trusted. Returning the proxy address would share lockout state
            // across all clients behind that proxy.
            return null;
        }

        $realIp = self::getForwardedHeader('X-Real-IP');
        if ($realIp !== null) {
            return self::normalizeIpAddress($realIp);
        }

        // A trusted proxy without a usable client-address header cannot be
        // distinguished from every other client behind that proxy.
        return null;
    }

    /** Compare proxy addresses by their packed IP representation, not text form. */
    protected static function isTrustedProxyIp(string $ip): bool
    {
        $normalizedIp = self::normalizeIpAddress($ip);
        if ($normalizedIp === null) {
            return false;
        }

        foreach (self::$trustedProxies as $trustedProxy) {
            if (!is_string($trustedProxy)) {
                continue;
            }
            if ($normalizedIp === self::normalizeIpAddress($trustedProxy)) {
                return true;
            }
        }

        return false;
    }

    /** Return a canonical IPv4/IPv6 string; malformed adapter values fail closed. */
    protected static function normalizeIpAddress(?string $ip): ?string
    {
        if ($ip === null || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = inet_pton($ip);
        if ($packed === false) {
            return null;
        }

        $normalized = inet_ntop($packed);
        return is_string($normalized) ? strtolower($normalized) : null;
    }

    protected static function getForwardedHeader(string $name): ?string
    {
        $request = self::getRequest();
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $values = $request->getHeader($name);
            return $values !== [] ? implode(', ', $values) : null;
        }

        if (is_object($request) && method_exists($request, 'getHeaderLine')) {
            $value = $request->getHeaderLine($name);
            return is_string($value) && $value !== '' ? $value : null;
        }

        return self::getHeader($name);
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
     * 判断请求是否为指定 Header 提供了多个或被合并的值。
     * 认证凭据不允许依赖不同代理/框架对重复 Header 的选取顺序。
     */
    public static function hasMultipleHeaderValues(string $name, bool $rejectCombinedValues = false): bool
    {
        $request = self::getRequest();
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $values = $request->getHeader($name);
            return count($values) > 1
                || ($rejectCombinedValues && self::containsCombinedHeaderValue($values));
        }

        if (!is_object($request)) {
            return false;
        }

        // Laravel/Symfony expose the raw header values through a HeaderBag,
        // while their convenience header() methods typically return only the
        // first value. Inspect the bag before authenticating a credential.
        $properties = get_object_vars($request);
        $headerBag = $properties['headers'] ?? null;
        if (is_object($headerBag) && method_exists($headerBag, 'all')) {
            try {
                $values = $headerBag->all($name);
            } catch (\Throwable) {
                // If a header bag is present but cannot be inspected reliably,
                // fail closed for credentials rather than trusting header().
                return true;
            }

            if (is_array($values)) {
                if (array_is_list($values)) {
                    return count($values) > 1
                        || ($rejectCombinedValues && self::containsCombinedHeaderValue($values));
                }
                foreach ($values as $headerName => $headerValues) {
                    if (is_string($headerName) && strcasecmp($headerName, $name) === 0) {
                        return !is_array($headerValues)
                            || count($headerValues) > 1
                            || ($rejectCombinedValues && self::containsCombinedHeaderValue($headerValues));
                    }
                }
                return false;
            }

            return true;
        }

        if (method_exists($request, 'header')) {
            $values = $request->header($name);
            if (is_array($values)) {
                return count($values) > 1
                    || ($rejectCombinedValues && self::containsCombinedHeaderValue($values));
            }
            return $rejectCombinedValues && is_string($values) && str_contains($values, ',');
        }

        if (method_exists($request, 'getHeaderLine')) {
            $value = $request->getHeaderLine($name);
            return $rejectCombinedValues && is_string($value) && str_contains($value, ',');
        }

        return false;
    }

    /** @param array<array-key, mixed> $values */
    protected static function containsCombinedHeaderValue(array $values): bool
    {
        foreach ($values as $value) {
            if (!is_string($value) || str_contains($value, ',')) {
                return true;
            }
        }

        return false;
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

    /** Reject duplicate names in the raw Cookie header before trusting a parsed cookie map. */
    public static function hasMultipleCookieValues(string $name): bool
    {
        $header = self::getCookieHeader();
        if ($header === null || $header === '') {
            return false;
        }

        $count = 0;
        foreach (preg_split('/[;,]/', $header) ?: [] as $part) {
            $separator = strpos($part, '=');
            if ($separator === false || trim(substr($part, 0, $separator)) !== $name) {
                continue;
            }
            if (++$count > 1) {
                return true;
            }
        }

        return false;
    }

    protected static function getCookieHeader(): ?string
    {
        $request = self::getRequest();
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $values = $request->getHeader('Cookie');
            return self::joinCookieHeaderValues($values);
        }

        if (is_object($request)) {
            $properties = get_object_vars($request);
            $headerBag = $properties['headers'] ?? null;
            if (is_object($headerBag) && method_exists($headerBag, 'all')) {
                try {
                    $values = $headerBag->all('Cookie');
                } catch (\Throwable) {
                    return null;
                }
                if (is_array($values)) {
                    if (array_is_list($values)) {
                        return self::joinCookieHeaderValues($values);
                    }
                    foreach ($values as $headerName => $headerValues) {
                        if (is_string($headerName) && strcasecmp($headerName, 'Cookie') === 0
                            && is_array($headerValues)) {
                            return self::joinCookieHeaderValues($headerValues);
                        }
                    }
                    return null;
                }
                return null;
            }

            if (method_exists($request, 'getHeaderLine')) {
                $value = $request->getHeaderLine('Cookie');
                return is_string($value) && $value !== '' ? $value : null;
            }

            if (method_exists($request, 'header')) {
                $value = $request->header('Cookie');
                if (is_array($value)) {
                    return self::joinCookieHeaderValues($value);
                }
                return is_string($value) && $value !== '' ? $value : null;
            }
        }

        return null;
    }

    /** @param array<array-key, mixed> $values */
    protected static function joinCookieHeaderValues(array $values): ?string
    {
        if ($values === []) {
            return null;
        }

        $strings = [];
        foreach ($values as $value) {
            if (!is_string($value)) {
                return null;
            }
            $strings[] = $value;
        }

        return implode('; ', $strings);
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

    /** Reject ambiguous credentials supplied more than once through request parameters. */
    public static function hasConflictingParamValues(string $name): bool
    {
        $request = self::getRequest();
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $queryParams = $request->getQueryParams();
            $body = $request->getParsedBody();
            $rawQuery = $request->getUri()->getQuery();
        } elseif (is_object($request)) {
            // Laravel and Symfony expose their parsed query/body through public
            // ParameterBag instances, while input() may merge those sources
            // using framework-specific precedence rules.
            $properties = get_object_vars($request);
            $hasQueryBag = array_key_exists('query', $properties);
            $hasBodyBag = array_key_exists('request', $properties);
            if (!$hasQueryBag && !$hasBodyBag) {
                return false;
            }

            $queryParams = $hasQueryBag ? self::getParameterBagValues($properties['query']) : [];
            $body = $hasBodyBag ? self::getParameterBagValues($properties['request']) : [];
            if ($queryParams === null || $body === null) {
                return true;
            }

            $rawQuery = '';
            if (method_exists($request, 'getQueryString')) {
                try {
                    $queryString = $request->getQueryString();
                } catch (\Throwable) {
                    return true;
                }
                if (is_string($queryString)) {
                    $rawQuery = $queryString;
                }
            }
        } else {
            return false;
        }

        $hasQueryValue = array_key_exists($name, $queryParams);
        $hasBodyValue = is_array($body) && array_key_exists($name, $body);
        if (is_object($body) && property_exists($body, $name)) {
            return true;
        }

        if (($hasQueryValue && !is_string($queryParams[$name]))
            || ($hasBodyValue && !is_string($body[$name]))) {
            return true;
        }
        if ($hasQueryValue && $hasBodyValue && $queryParams[$name] !== $body[$name]) {
            return true;
        }

        // PSR-7 query parsing may collapse repeated keys to one value. Inspect
        // the raw query so `?token=a&token=b` cannot silently select a bearer.
        if ($rawQuery === '') {
            return false;
        }

        $queryValueCount = 0;
        foreach (preg_split('/[&;]/', $rawQuery) ?: [] as $pair) {
            $separator = strpos($pair, '=');
            $rawName = $separator === false ? $pair : substr($pair, 0, $separator);
            $parameterName = urldecode($rawName);
            if ($parameterName === $name || str_starts_with($parameterName, $name . '[')) {
                if (++$queryValueCount > 1 || $parameterName !== $name) {
                    return true;
                }
            }
        }

        return false;
    }

    /** @return array<array-key, mixed>|null */
    protected static function getParameterBagValues(mixed $bag): ?array
    {
        if (is_array($bag)) {
            return $bag;
        }
        if (!is_object($bag) || !method_exists($bag, 'all')) {
            return null;
        }

        try {
            $values = $bag->all();
        } catch (\Throwable) {
            return null;
        }

        return is_array($values) ? $values : null;
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

    /** Add one token to a comma-separated response header without discarding existing tokens. */
    public static function addHeaderToken(string $name, string $token): void
    {
        $id = self::getContextId();
        $existing = self::getResponseHeader($name);
        foreach (array_reverse(self::$pendingHeadersMap[$id] ?? []) as $pending) {
            if (strcasecmp($pending['name'], $name) === 0) {
                $existing = $pending['value'];
                break;
            }
        }

        $tokens = [];
        $normalizedTokens = [];
        foreach (explode(',', $existing ?? '') as $existingToken) {
            $existingToken = trim($existingToken);
            if ($existingToken === '*') {
                self::setHeader($name, '*');
                return;
            }
            $normalized = strtolower($existingToken);
            if ($existingToken !== '' && !isset($normalizedTokens[$normalized])) {
                $tokens[] = $existingToken;
                $normalizedTokens[$normalized] = true;
            }
        }
        $normalized = strtolower($token);
        if (!isset($normalizedTokens[$normalized])) {
            $tokens[] = $token;
        }

        self::setHeader($name, implode(', ', $tokens));
    }

    protected static function getResponseHeader(string $name): ?string
    {
        $response = self::getResponse();
        if ($response === null) {
            return null;
        }
        if ($response instanceof \Psr\Http\Message\ResponseInterface) {
            $value = $response->getHeaderLine($name);
            return $value !== '' ? $value : null;
        }
        if (is_object($response) && isset($response->headers)) {
            if (is_object($response->headers) && method_exists($response->headers, 'get')) {
                $value = $response->headers->get($name);
                return is_string($value) ? $value : null;
            }
            if (is_array($response->headers)) {
                foreach ($response->headers as $headerName => $value) {
                    if (is_string($headerName) && strcasecmp($headerName, $name) === 0) {
                        if (is_string($value)) {
                            return $value;
                        }
                        if (is_array($value)) {
                            $values = [];
                            foreach ($value as $item) {
                                if (is_scalar($item)) {
                                    $values[] = (string) $item;
                                }
                            }
                            return implode(', ', $values);
                        }
                        return null;
                    }
                }
            }
        }
        if (is_object($response) && method_exists($response, 'getHeaderLine')) {
            $value = $response->getHeaderLine($name);
            return is_string($value) && $value !== '' ? $value : null;
        }
        return null;
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

        if ($name === '' || preg_match('/[=;,\x00-\x20\x7f]/', $name) === 1) {
            throw new SaTokenException('Cookie 名称包含无效字符');
        }
        if (preg_match('/[;\x00-\x1f\x7f]/', $path) === 1) {
            throw new SaTokenException('Cookie Path 包含无效字符');
        }
        if ($domain !== '' && preg_match('/[;=,\x00-\x20\x7f]/', $domain) === 1) {
            throw new SaTokenException('Cookie Domain 包含无效字符');
        }
        if ($sameSite !== '' && !in_array(strtolower($sameSite), ['strict', 'lax', 'none'], true)) {
            throw new SaTokenException('Cookie SameSite 必须是 Strict、Lax、None 或空值');
        }

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

        if (
            is_object($response)
            && isset($response->headers)
            && is_object($response->headers)
            && method_exists($response->headers, 'setCookie')
            && class_exists(\Symfony\Component\HttpFoundation\Cookie::class)
        ) {
            $expire = $timeout > 0 ? time() + $timeout : ($timeout < 0 ? 1 : 0);
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
            return $response;
        }

        if (is_object($response) && method_exists($response, 'getCookie') && method_exists($response, 'cookie')) {
            // ThinkPHP Response::cookie() takes one options array; its Cookie
            // manager interprets numeric expire values as relative seconds.
            $response->cookie($name, $value, [
                'expire' => $timeout,
                'path' => $path,
                'domain' => $domain,
                'secure' => $secure,
                'httponly' => $httpOnly,
                'samesite' => $sameSite,
            ]);
            return $response;
        }

        if (is_object($response) && method_exists($response, 'cookie')) {
            // Laravel-style cookie() expects a lifetime in minutes, not an
            // absolute timestamp. Round positive second-based TTLs up so the
            // client cookie cannot expire before the server-side token.
            $minutes = $timeout > 0 ? (int) ceil($timeout / 60) : $timeout;
            $response->cookie($name, $value, $minutes, $path, $domain, $secure, $httpOnly, false, $sameSite !== '' ? $sameSite : null);
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

        if ($timeout !== 0) {
            $expiresAt = $timeout > 0 ? time() + $timeout : 1;
            $parts[] = 'Expires=' . gmdate('D, d M Y H:i:s T', $expiresAt);
            $parts[] = 'Max-Age=' . max(0, $timeout);
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
