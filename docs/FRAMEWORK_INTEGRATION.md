# sa-token PHP 框架集成指南

本指南说明如何将 sa-token 与主流 PHP 框架集成。

> 注意：当前仓库提供的是框架无关核心库，不包含 Laravel ServiceProvider 或 Symfony Bundle。
> 因此集成方式以手动配置和中间件/监听器接线为主。

## 目录
- [ThinkPHP](#thinkphp)
- [Laravel](#laravel)
- [Symfony](#symfony)
- [Hyperf](#hyperf)
- [Swoole](#swoole)

## 核心设计

sa-token 通过 `SaTokenContext` 提供跨框架兼容层，支持以下请求/响应方法：

### 请求生命周期要求

无论接入哪个框架，都建议遵守同一条生命周期约束：

1. 请求进入时尽早执行 `SaToken::init(...)`，并将 request 注入 `SaTokenContext::setRequest(...)`
2. 控制器或业务逻辑执行完成后，将 response 注入 `SaTokenContext::setResponse(...)`
3. 返回响应前，优先返回 `SaTokenContext::getResponse()`，因为登录、登出、刷新 Token 可能已经改写了 Header / Cookie
4. 请求结束时调用 `SaToken::clearContext()`，避免常驻内存或协程场景下的上下文泄漏

如果只做了第 1 步，没有把 response 回写到 `SaTokenContext`，那么 `isWriteCookie`、`isWriteHeader`、RefreshToken 响应头等能力都不会生效。

### 请求方法
- `getHeader(name)` - PSR-7 标准
- `header(name)` - ThinkPHP/Laravel 风格
- `getHeaderLine(name)` - Symfony/Laravel 风格

- `getCookieParams()` - PSR-7 标准
- `cookie(name)` - ThinkPHP/Laravel 风格

- `getQueryParams()` / `getParsedBody()` - PSR-7 标准
- `param(name)` - ThinkPHP 风格
- `input(name)` - Laravel 风格

### 响应方法
- `withHeader(name, value)` / `withAddedHeader(name, value)` - PSR-7 标准
- `header(name, value)` - ThinkPHP/Laravel 风格
- `cookie(name, value, ...)` - 通用风格

---

## ThinkPHP

### 安装

```bash
composer require pohoc/sa-token
```

### 配置

创建 `config/sa_token.php`：

```php
<?php
return [
    'tokenName'       => 'satoken',
    'timeout'         => 2592000, // 30天
    'concurrent'      => true,
    'isShare'         => true,
    'maxLoginCount'   => -1,
];
```

### 中间件

创建 `app/middleware/SaTokenMiddleware.php`：

```php
<?php

namespace app\middleware;

use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;
use think\Request;
use think\Response;

class SaTokenMiddleware
{
    public function handle(Request $request, \Closure $next)
    {
        if (!SaToken::isInitialized()) {
            SaToken::init();
        }

        SaTokenContext::setRequest($request);
        try {
            $response = $next($request);
            SaTokenContext::setResponse($response);
            return SaTokenContext::getResponse() ?? $response;
        } finally {
            SaToken::clearContext();
        }
    }
}
```

### 使用示例

```php
<?php

namespace app\controller;

use SaToken\StpUtil;
use think\facade\Route;

class AuthController
{
    public function login()
    {
        $userId = 1001;
        $result = StpUtil::login($userId);
        return json(['code' => 0, 'msg' => '登录成功', 'data' => $result->toArray()]);
    }

    public function logout()
    {
        StpUtil::logout();
        return json(['code' => 0, 'msg' => '登出成功']);
    }

    public function isLogin()
    {
        return json(['code' => 0, 'isLogin' => StpUtil::isLogin()]);
    }

    public function getUserInfo()
    {
        StpUtil::checkLogin();
        $userId = StpUtil::getLoginId();
        return json(['code' => 0, 'userId' => $userId]);
    }

    public function refreshToken()
    {
        $refreshToken = request()->header('satoken-refresh', '');
        if ($refreshToken === '') {
            return json(['code' => 401, 'msg' => '缺少 RefreshToken']);
        }
        try {
            $result = StpUtil::refreshToken($refreshToken);
            return json([
                'code' => 0,
                'msg' => '刷新成功',
                'data' => $result->toArray(),
            ]);
        } catch (\Exception $e) {
            return json(['code' => 401, 'msg' => 'RefreshToken 无效或已过期']);
        }
    }
}

// 路由定义
Route::post('/auth/login', 'AuthController/login');
Route::post('/auth/logout', 'AuthController/logout');
Route::get('/auth/isLogin', 'AuthController/isLogin');
Route::get('/auth/userInfo', 'AuthController/getUserInfo');
Route::post('/auth/refresh', 'AuthController/refreshToken');
```

---

## Laravel

### 安装

```bash
composer require pohoc/sa-token
```

### 配置

当前仓库不提供 Laravel `ServiceProvider`，因此不能使用 `vendor:publish` 自动发布配置。

请手动创建 `config/sa_token.php`：

```php
<?php
return [
    'tokenName'       => 'satoken',
    'timeout'         => 2592000,
    'concurrent'      => true,
    'isShare'         => true,
];
```

### 中间件

创建 `app/Http/Middleware/SaTokenMiddleware.php`：

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaTokenMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        if (!SaToken::isInitialized()) {
            SaToken::init(config('sa_token'));
        }

        SaTokenContext::setRequest($request);
        try {
            $response = $next($request);
            SaTokenContext::setResponse($response);
            return SaTokenContext::getResponse() ?? $response;
        } finally {
            SaToken::clearContext();
        }
    }
}
```

### 控制器示例

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use SaToken\StpUtil;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $userId = $request->input('userId', 1001);
        $result = StpUtil::login($userId);
        return response()->json([
            'code' => 0,
            'msg' => '登录成功',
            'data' => $result->toArray(),
        ]);
    }

    public function logout()
    {
        StpUtil::logout();
        return response()->json(['code' => 0, 'msg' => '登出成功']);
    }

    public function getUserInfo()
    {
        StpUtil::checkLogin();
        return response()->json([
            'code' => 0,
            'userId' => StpUtil::getLoginId()
        ]);
    }

    public function refreshToken(Request $request)
    {
        $refreshToken = $request->header('satoken-refresh', '');
        if ($refreshToken === '') {
            return response()->json(['code' => 401, 'msg' => '缺少 RefreshToken'], 401);
        }
        try {
            $result = StpUtil::refreshToken($refreshToken);
            return response()->json([
                'code' => 0,
                'msg' => '刷新成功',
                'data' => $result->toArray(),
            ]);
        } catch (\Exception $e) {
            return response()->json(['code' => 401, 'msg' => 'RefreshToken 无效或已过期'], 401);
        }
    }
}
```

---

## Symfony

### 安装

```bash
composer require pohoc/sa-token
```

### 配置

当前仓库不提供 Symfony Bundle，也不会自动读取 `config/packages/*.yaml`。

请在项目根目录手动创建 `config/sa_token.php`：

```php
<?php

return [
    'tokenName'       => 'satoken',
    'timeout'         => 2592000,
    'concurrent'      => true,
    'isShare'         => true,
];
```

### 事件监听器

创建 `src/EventListener/SaTokenListener.php`：

```php
<?php

namespace App\EventListener;

use SaToken\SaToken;
use SaToken\Util\SaTokenContext;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

class SaTokenListener
{
    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        if (!SaToken::isInitialized()) {
            SaToken::init(require dirname(__DIR__, 2) . '/config/sa_token.php');
        }

        SaTokenContext::setRequest($event->getRequest());
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        SaTokenContext::setResponse($event->getResponse());
        $event->setResponse(SaTokenContext::getResponse() ?? $event->getResponse());
        SaToken::clearContext();
    }
}
```

### 控制器示例

```php
<?php

namespace App\Controller;

use SaToken\StpUtil;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;

class AuthController extends AbstractController
{
    #[Route('/auth/login', methods: ['POST'])]
    public function login(): JsonResponse
    {
        $userId = 1001;
        $result = StpUtil::login($userId);
        return $this->json([
            'code' => 0,
            'msg' => '登录成功',
            'token' => $result->getAccessToken()
        ]);
    }

    #[Route('/auth/logout', methods: ['POST'])]
    public function logout(): JsonResponse
    {
        StpUtil::logout();
        return $this->json(['code' => 0, 'msg' => '登出成功']);
    }

    #[Route('/auth/userInfo', methods: ['GET'])]
    public function getUserInfo(): JsonResponse
    {
        StpUtil::checkLogin();
        return $this->json([
            'code' => 0,
            'userId' => StpUtil::getLoginId()
        ]);
    }
}
```

---

## Hyperf

### 安装

```bash
composer require pohoc/sa-token
```

### 中间件

创建 `app/Middleware/SaTokenMiddleware.php`：

```php
<?php

namespace App\Middleware;

use Hyperf\Context\Context;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaTokenMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!SaToken::isInitialized()) {
            SaToken::init();
        }

        $coroutineId = (string) Context::get('coroutine.id', 'default');
        SaTokenContext::setContextId($coroutineId);
        SaTokenContext::setRequest($request);
        try {
            $response = $handler->handle($request);
            SaTokenContext::setResponse($response);
            $resolved = SaTokenContext::getResponse();
            return $resolved instanceof ResponseInterface ? $resolved : $response;
        } finally {
            SaToken::clearContext();
        }
    }
}
```

### 协程安全注意事项

Hyperf/Swoole 是协程化框架，sa-token 已内置协程支持：

```php
<?php

use SaToken\SaToken;
use SaToken\Util\SaTokenContext;
use Hyperf\Coroutine\Coroutine;

// 协程内使用
go(function () {
    $coroutineId = (string) Coroutine::id();
    SaTokenContext::setContextId($coroutineId);

    // 登录等操作...
    StpUtil::login(1001);
});
```

---

## Swoole

### 安装

```bash
composer require pohoc/sa-token
```

### 使用示例

```php
<?php

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

require __DIR__ . '/vendor/autoload.php';

// 初始化
SaToken::init();

$server = new Server('0.0.0.0', 9501);

$server->on('request', function (Request $request, Response $response) {
    // 设置上下文 ID（协程安全）
    $coroutineId = (string) Swoole\Coroutine::getCid();
    SaTokenContext::setContextId($coroutineId);
    SaTokenContext::setResponse($response);

    // 适配 Request
    $wrappedRequest = new class($request) {
        protected $request;
        public function __construct($request) {
            $this->request = $request;
        }
        public function header($name) {
            return $this->request->header[$name] ?? null;
        }
        public function cookie($name) {
            return $this->request->cookie[$name] ?? null;
        }
    };

    SaTokenContext::setRequest($wrappedRequest);
    try {
        $path = $request->server['request_uri'];

        if ($path === '/auth/login') {
            $result = StpUtil::login(1001);
            $response->header('Content-Type', 'application/json');
            $response->end(json_encode([
                'code' => 0,
                'msg' => '登录成功',
                'token' => $result->getAccessToken()
            ]));
            return;
        }

        if ($path === '/auth/userInfo') {
            try {
                StpUtil::checkLogin();
                $response->header('Content-Type', 'application/json');
                $response->end(json_encode([
                    'code' => 0,
                    'userId' => StpUtil::getLoginId()
                ]));
            } catch (\Exception $e) {
                $response->status(401);
                $response->end(json_encode([
                    'code' => 401,
                    'msg' => '未登录'
                ]));
            }
            return;
        }

        $response->status(404);
        $response->end('Not Found');
    } finally {
        SaToken::clearContext();
    }
});

$server->start();
```

---

## 存储适配器配置

### Redis 存储（推荐生产环境）

```php
<?php
use SaToken\SaToken;
use SaToken\Dao\SaTokenDaoRedis;

// 创建 Redis 连接
$redis = new \Redis();
$redis->connect('127.0.0.1', 6379);

// 配置
SaToken::setDao(new SaTokenDaoRedis($redis));
SaToken::init();
```

### PSR-16 缓存适配器

```php
<?php
use SaToken\SaToken;
use SaToken\Dao\SaTokenDaoPsr16;
use Cache\Adapter\Filesystem\FilesystemCachePool;
use League\Flysystem\Filesystem;
use League\Flysystem\Local\LocalFilesystemAdapter;

// 创建 PSR-16 缓存
$adapter = new LocalFilesystemAdapter(__DIR__ . '/cache');
$filesystem = new Filesystem($adapter);
$cache = new FilesystemCachePool($filesystem);

// 配置
SaToken::setDao(new SaTokenDaoPsr16($cache));
SaToken::init();
```

---

## 高并发与刷新注意事项

- **同账号并发登录**：同一账号的并发登录请求会抛出 `SaTokenException('同账号登录正在处理中，请勿重复提交')`（基于分布式锁，TTL 5 秒）。登录/刷新接口应捕获该异常并做短重试，或返回友好提示让用户稍后重试。
- **RefreshToken 重放**：重放已消费的 RefreshToken 会触发"令牌家族撤销"安全机制（撤销跨代全家族令牌，含派生 RefreshToken）并抛出异常。应与普通 401 区分处理——将其视为安全事件（如记录审计日志、通知用户重新登录），而非简单的登录过期。

---

## 完整功能对照表

| 功能 | 说明 |
|-----|-----|
| ✅ 登录/登出 | 标准认证流程 |
| ✅ Token 验证 | Cookie/Header/Param 三种方式 |
| ✅ 会话管理 | 基于 Redis/内存/PSR-16 |
| ✅ 权限/角色 | `checkPermission` / `checkRole` |
| ✅ 踢人下线 | `kickout` / `kickoutByTokenValue` |
| ✅ 身份切换 | `switchTo` / `endSwitch` |
| ✅ 二级认证 | `openSafe` / `checkSafe` |
| ✅ 账号封禁 | `disable` / `checkDisable` |
| ✅ 防暴力破解 | `SaAntiBruteUtil` |
| ✅ Refresh Token | 双 Token 机制 + Token 轮换 |
| ✅ JWT 支持 | `jwtStateless` / `jwtMixed` |
| ✅ 国密加密 | SM2/SM3/SM4 支持 |
| ✅ OAuth2.0 | 标准授权流程 |
| ✅ SSO 单点登录 | 多种模式 |
| ✅ 审计日志 | `SaAuditLog` |
| ✅ IP 异常检测 | `SaIpAnomalyDetector` |
