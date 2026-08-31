<?php

declare(strict_types=1);

namespace SaToken\Middleware;

use SaToken\Util\SaTokenContext;

class SaGlobalFilter
{
    /** @var array<callable(): void> */
    protected array $beforeFilters = [];

    /** @var array<callable(): void> */
    protected array $afterFilters = [];

    /** @var array<string, mixed> */
    protected array $corsConfig = [];

    public function addBeforeFilter(callable $filter): static
    {
        $this->beforeFilters[] = $filter;
        return $this;
    }

    public function addAfterFilter(callable $filter): static
    {
        $this->afterFilters[] = $filter;
        return $this;
    }

    /**
     * @param array<string, mixed> $config
     */
    public function setCors(array $config): static
    {
        $this->corsConfig = $config;
        return $this;
    }

    public function execute(): void
    {
        foreach ($this->beforeFilters as $filter) {
            $filter();
        }

        $this->applyCorsHeaders();
        $this->applySecurityHeaders();

        foreach ($this->afterFilters as $filter) {
            $filter();
        }
    }

    public function applySecurityHeaders(): void
    {
        SaTokenContext::setHeader('X-Content-Type-Options', 'nosniff');
        SaTokenContext::setHeader('X-Frame-Options', 'SAMEORIGIN');
        SaTokenContext::setHeader('X-XSS-Protection', '1; mode=block');
        SaTokenContext::setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        // HSTS 在纯 HTTP 响应中被浏览器忽略，常驻 HTTPS 部署下强制后续走 TLS
        SaTokenContext::setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    public function applyCorsHeaders(): void
    {
        if (isset($this->corsConfig['allowOrigin'])) {
            $allowOrigin = $this->corsConfig['allowOrigin'];
            SaTokenContext::setHeader('Access-Control-Allow-Origin', is_string($allowOrigin) ? $allowOrigin : '');
            // Origin 值参与缓存决策：缺少 Vary 时共享缓存可能把 A 站的许可头
            // 缓存命中给 B 站的请求（缓存投毒）
            SaTokenContext::setHeader('Vary', 'Origin');
        }
        if (isset($this->corsConfig['allowMethods'])) {
            $allowMethods = $this->corsConfig['allowMethods'];
            SaTokenContext::setHeader('Access-Control-Allow-Methods', is_string($allowMethods) ? $allowMethods : '');
        }
        if (isset($this->corsConfig['allowHeaders'])) {
            $allowHeaders = $this->corsConfig['allowHeaders'];
            SaTokenContext::setHeader('Access-Control-Allow-Headers', is_string($allowHeaders) ? $allowHeaders : '');
        }
        if (isset($this->corsConfig['exposeHeaders'])) {
            $exposeHeaders = $this->corsConfig['exposeHeaders'];
            SaTokenContext::setHeader('Access-Control-Expose-Headers', is_string($exposeHeaders) ? $exposeHeaders : '');
        }
        if (isset($this->corsConfig['maxAge'])) {
            $maxAge = $this->corsConfig['maxAge'];
            SaTokenContext::setHeader('Access-Control-Max-Age', is_int($maxAge) ? (string) $maxAge : '');
        }
        if (isset($this->corsConfig['allowCredentials'])) {
            // 通配 Origin 与 credentials 组合违反 CORS 规范且被浏览器拒绝，
            // 静默下发只会让开发者误以为配置生效
            $allowOrigin = $this->corsConfig['allowOrigin'] ?? '';
            if ($this->corsConfig['allowCredentials'] && $allowOrigin === '*') {
                throw new \SaToken\Exception\SaTokenException('CORS 配置无效：allowCredentials=true 不允许与 allowOrigin=* 组合，请配置具体 Origin 列表');
            }
            $value = $this->corsConfig['allowCredentials'] ? 'true' : 'false';
            SaTokenContext::setHeader('Access-Control-Allow-Credentials', $value);
        }
    }

    public function isCorsRequest(): bool
    {
        $origin = SaTokenContext::getHeader('Origin');
        if ($origin === null) {
            return false;
        }

        $request = SaTokenContext::getRequest();
        if ($request === null) {
            if (isset($_SERVER['REQUEST_METHOD'])) {
                return $_SERVER['REQUEST_METHOD'] === 'OPTIONS';
            }
            return false;
        }
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            return $request->getMethod() === 'OPTIONS';
        }
        if (is_object($request) && method_exists($request, 'getMethod')) {
            $m = $request->getMethod();
            return is_string($m) && strtoupper($m) === 'OPTIONS';
        }

        return false;
    }

    public function handlePreflight(): void
    {
        $this->applyCorsHeaders();

        $response = SaTokenContext::getResponse();
        if ($response === null) {
            return;
        }
        if ($response instanceof \Psr\Http\Message\ResponseInterface) {
            $response = $response->withStatus(204);
            SaTokenContext::setResponse($response);
        } elseif (is_object($response) && method_exists($response, 'status')) {
            $response->status(204);
        }
    }
}
