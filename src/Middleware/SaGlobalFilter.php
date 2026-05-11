<?php

declare(strict_types=1);

namespace SaToken\Middleware;

use SaToken\Util\SaTokenContext;

class SaGlobalFilter
{
    protected array $beforeFilters = [];

    protected array $afterFilters = [];

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
    }

    public function applyCorsHeaders(): void
    {
        if (isset($this->corsConfig['allowOrigin'])) {
            SaTokenContext::setHeader('Access-Control-Allow-Origin', $this->corsConfig['allowOrigin']);
        }
        if (isset($this->corsConfig['allowMethods'])) {
            SaTokenContext::setHeader('Access-Control-Allow-Methods', $this->corsConfig['allowMethods']);
        }
        if (isset($this->corsConfig['allowHeaders'])) {
            SaTokenContext::setHeader('Access-Control-Allow-Headers', $this->corsConfig['allowHeaders']);
        }
        if (isset($this->corsConfig['exposeHeaders'])) {
            SaTokenContext::setHeader('Access-Control-Expose-Headers', $this->corsConfig['exposeHeaders']);
        }
        if (isset($this->corsConfig['maxAge'])) {
            SaTokenContext::setHeader('Access-Control-Max-Age', (string) $this->corsConfig['maxAge']);
        }
        if (isset($this->corsConfig['allowCredentials'])) {
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
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            return $request->getMethod() === 'OPTIONS';
        }
        if ($request !== null && method_exists($request, 'getMethod')) {
            return strtoupper($request->getMethod()) === 'OPTIONS';
        }
        if (isset($_SERVER['REQUEST_METHOD'])) {
            return $_SERVER['REQUEST_METHOD'] === 'OPTIONS';
        }

        return false;
    }

    public function handlePreflight(): void
    {
        $this->applyCorsHeaders();

        $response = SaTokenContext::getResponse();
        if ($response instanceof \Psr\Http\Message\ResponseInterface) {
            $response = $response->withStatus(204);
            SaTokenContext::setResponse($response);
        } elseif ($response !== null && method_exists($response, 'status')) {
            $response->status(204);
        }
    }
}
