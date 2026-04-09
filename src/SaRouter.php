<?php

declare(strict_types=1);

namespace SaToken;

/**
 * 路由鉴权匹配器
 *
 * 提供链式 API 进行路由匹配和鉴权拦截
 *
 * 使用示例：
 *   SaRouter::match('/user/**')->check(fn() => StpUtil::checkLogin());
 *   SaRouter::match('/admin/**')->check(fn() => StpUtil::checkRole('admin'));
 *   SaRouter::notMatch('/public/**')->match('**')->check(fn() => StpUtil::checkLogin());
 */
class SaRouter
{
    /**
     * 当前匹配模式（match / notMatch）
     */
    protected static string $mode = 'match';

    /**
     * 匹配规则列表
     * @var array<string>
     */
    protected static array $patterns = [];

    /**
     * 是否已匹配
     */
    protected static bool $isMatch = false;

    /**
     * 是否已停止
     */
    protected static bool $isStop = false;

    /**
     * 当前请求路径
     */
    protected static ?string $currentPath = null;

    /**
     * 匹配指定路由模式
     *
     * @param  string ...$patterns 路由模式，支持通配符 ** 和 *
     * @return static
     */
    public static function match(string ...$patterns): static
    {
        self::reset();
        self::$mode = 'match';
        self::$patterns = $patterns;
        self::$isMatch = self::checkPatterns($patterns);
        return new static();
    }

    /**
     * 排除指定路由模式
     *
     * @param  string ...$patterns 路由模式
     * @return static
     */
    public static function notMatch(string ...$patterns): static
    {
        self::reset();
        self::$mode = 'notMatch';
        self::$patterns = $patterns;
        self::$isMatch = !self::checkPatterns($patterns);
        return new static();
    }

    /**
     * 执行鉴权检查
     *
     * @param  callable $check 鉴权回调函数，返回 void
     * @return void
     */
    public function check(callable $check): void
    {
        if (self::$isStop) {
            return;
        }
        if (self::$isMatch) {
            $check();
        }
    }

    /**
     * 停止后续匹配
     *
     * @return static
     */
    public function stop(): static
    {
        self::$isStop = true;
        return $this;
    }

    /**
     * 获取当前请求路径
     *
     * @return string
     */
    public static function getCurrentPath(): string
    {
        if (self::$currentPath !== null) {
            return self::$currentPath;
        }

        // 从上下文获取请求路径
        $request = \SaToken\Util\SaTokenContext::getRequest();
        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $uri = $request->getUri();
            self::$currentPath = $uri->getPath();
        } elseif ($request !== null && method_exists($request, 'getPathInfo')) {
            self::$currentPath = $request->getPathInfo();
        } elseif ($request !== null && method_exists($request, 'path')) {
            self::$currentPath = $request->path();
        } elseif (isset($_SERVER['REQUEST_URI'])) {
            $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
            self::$currentPath = $uri ?: '/';
        } else {
            self::$currentPath = '/';
        }

        return self::$currentPath;
    }

    /**
     * 设置当前请求路径（用于测试）
     *
     * @param  string $path 请求路径
     * @return void
     */
    public static function setCurrentPath(string $path): void
    {
        self::$currentPath = $path;
    }

    /**
     * 检查路径是否匹配模式列表
     *
     * @param  array<string> $patterns 模式列表
     * @return bool          任一模式匹配即返回 true
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

    /**
     * 判断路径是否匹配单个模式
     *
     * 支持通配符：
     * - ** 匹配任意多级路径
     * - * 匹配单级路径
     *
     * @param  string $path    请求路径
     * @param  string $pattern 路由模式
     * @return bool
     */
    protected static function isMatch(string $path, string $pattern): bool
    {
        // 完全匹配
        if ($pattern === $path) {
            return true;
        }

        // 将路由模式转换为正则表达式
        $regex = self::patternToRegex($pattern);
        return (bool) preg_match($regex, $path);
    }

    /**
     * 将路由模式转换为正则表达式
     *
     * @param  string $pattern 路由模式
     * @return string 正则表达式
     */
    protected static function patternToRegex(string $pattern): string
    {
        // 转义正则特殊字符（除 * 外）
        $regex = preg_quote($pattern, '#');

        // ** 匹配任意多级路径（包括空路径）
        // /path/** 应匹配 /path、/path/、/path/a、/path/a/b
        $regex = str_replace('/\*\*', '(?:/.*)?', $regex);
        $regex = str_replace('\*\*', '.*', $regex);

        // * 匹配单级路径（不含 /）
        $regex = str_replace('\*', '[^/]*', $regex);

        return '#^' . $regex . '$#';
    }

    /**
     * 重置状态
     *
     * @return void
     */
    protected static function reset(): void
    {
        self::$patterns = [];
        self::$isMatch = false;
        self::$isStop = false;
        self::$mode = 'match';
    }

    /**
     * 完全重置（包括路径）
     *
     * @return void
     */
    public static function fullReset(): void
    {
        self::reset();
        self::$currentPath = null;
    }
}
