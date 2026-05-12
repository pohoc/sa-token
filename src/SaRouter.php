<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Util\SaTokenContext;

class SaRouter
{
    protected static string $mode = 'match';

    /** @var array<string> */
    protected static array $patterns = [];

    protected static bool $isMatch = false;

    protected static bool $isStop = false;

    protected static ?string $currentPath = null;

    /** @var array<string, array{mode: string, patterns: array<string>, isMatch: bool, isStop: bool}> */
    protected static array $contextMap = [];

    protected static function getContextId(): string
    {
        if (class_exists(\Hyperf\Coroutine\Coroutine::class)) {
            $coroutineId = \Hyperf\Coroutine\Coroutine::id();
            if (is_int($coroutineId) && $coroutineId > 0) {
                return 'router_' . $coroutineId;
            }
        }
        $ctxId = SaTokenContext::getContextId();
        return 'router_' . $ctxId;
    }

    /**
     * @return array{mode: string, patterns: array<string>, isMatch: bool, isStop: bool}
     */
    protected static function &getState(): array
    {
        $id = self::getContextId();
        if (!isset(self::$contextMap[$id])) {
            self::$contextMap[$id] = [
                'mode' => 'match',
                'patterns' => [],
                'isMatch' => false,
                'isStop' => false,
            ];
        }
        return self::$contextMap[$id];
    }

    public static function match(string ...$patterns): static
    {
        $state = &self::getState();
        $state['mode'] = 'match';
        $state['patterns'] = $patterns;
        $state['isMatch'] = self::checkPatterns($patterns);
        $state['isStop'] = false;
        return new static();
    }

    public static function notMatch(string ...$patterns): static
    {
        $state = &self::getState();
        $state['mode'] = 'notMatch';
        $state['patterns'] = $patterns;
        $state['isMatch'] = !self::checkPatterns($patterns);
        $state['isStop'] = false;
        return new static();
    }

    public function check(callable $check): void
    {
        $state = &self::getState();
        if ($state['isStop']) {
            return;
        }
        if ($state['isMatch']) {
            $check();
        }
    }

    public function stop(): static
    {
        $state = &self::getState();
        $state['isStop'] = true;
        return $this;
    }

    public static function getCurrentPath(): string
    {
        if (self::$currentPath !== null) {
            return self::$currentPath;
        }

        $request = SaTokenContext::getRequest();
        if ($request === null) {
            if (isset($_SERVER['REQUEST_URI']) && is_string($_SERVER['REQUEST_URI'])) {
                $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
                self::$currentPath = is_string($uri) ? $uri : '/';
            } else {
                self::$currentPath = '/';
            }
            return self::$currentPath;
        }
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $uri = $request->getUri();
            self::$currentPath = $uri->getPath();
        } elseif (is_object($request)) {
            if (method_exists($request, 'getPathInfo')) {
                $pathInfo = $request->getPathInfo();
                self::$currentPath = is_string($pathInfo) ? $pathInfo : '/';
            } elseif (method_exists($request, 'path')) {
                $path = $request->path();
                self::$currentPath = is_string($path) ? $path : '/';
            } elseif (isset($_SERVER['REQUEST_URI']) && is_string($_SERVER['REQUEST_URI'])) {
                $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
                self::$currentPath = is_string($uri) ? $uri : '/';
            } else {
                self::$currentPath = '/';
            }
        } elseif (isset($_SERVER['REQUEST_URI']) && is_string($_SERVER['REQUEST_URI'])) {
            $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
            self::$currentPath = is_string($uri) ? $uri : '/';
        } else {
            self::$currentPath = '/';
        }

        return self::$currentPath ?? '/';
    }

    public static function setCurrentPath(string $path): void
    {
        self::$currentPath = $path;
    }

    /**
     * @param array<string> $patterns
     */
    protected static function checkPatterns(array $patterns): bool
    {
        $path = self::getCurrentPath();
        foreach ($patterns as $pattern) {
            if (self::isMatch($path, $pattern)) {
                return true;
            }
        }
        return false;
    }

    protected static function isMatch(string $path, string $pattern): bool
    {
        if ($pattern === $path) {
            return true;
        }

        $regex = self::patternToRegex($pattern);
        return (bool) preg_match($regex, $path);
    }

    protected static function patternToRegex(string $pattern): string
    {
        $regex = preg_quote($pattern, '#');
        $regex = str_replace('/\*\*', '(?:/.*)?', $regex);
        $regex = str_replace('\*\*', '.*', $regex);
        $regex = str_replace('\*', '[^/]*', $regex);
        return '#^' . $regex . '$#';
    }

    protected static function reset(): void
    {
        $id = self::getContextId();
        unset(self::$contextMap[$id]);
    }

    public static function fullReset(): void
    {
        self::$contextMap = [];
        self::$currentPath = null;
    }

    public static function clearContext(): void
    {
        $id = self::getContextId();
        unset(self::$contextMap[$id]);
    }
}
