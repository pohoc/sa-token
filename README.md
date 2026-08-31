# Sa-Token PHP

<p align="center">
<img src="https://img.shields.io/badge/PHP-8.1%20~%208.5-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP Version">
<img src="https://img.shields.io/github/license/pohoc/sa-token?style=flat-square&label=License" alt="License">
</p>

适用于 PHP 生态的轻量级权限认证框架，灵感源自 [sa-token](https://sa-token.cc)。

> **致谢与声明**：本项目参考了 Java 生态 [dromara/sa-token](https://github.com/dromara/sa-token)（Apache-2.0）的 API 设计理念，
> 代码为独立 PHP 实现。感谢原项目作者与社区。

> **v0.1.3 安全加固说明**：本版本修复了安全审计发现的多处高危问题，部分行为为有意收紧（详见 [CHANGELOG.md](CHANGELOG.md)）：
> OAuth2 换 token 必须携带 redirect_uri、SSO 回调强制校验 state、客户端注册必须配置非空 secret、
> `SaSign` 强制 timestamp/nonce 且移除 MD5、加密插件密文格式升级（兼容读取旧格式）。升级前请阅读变更日志。

## 特性一览

- **登录认证** — 单端/多端登录、同端互斥登录、记住我、踢人下线、账号封禁、临时 Token
- **权限认证** — 角色/权限校验、路由拦截鉴权、二级认证、身份切换
- **Token 安全** — Token 内容加密（AES-256-CBC / SM4-CBC）、防内容泄露
- **Refresh Token** — AccessToken + RefreshToken 双 Token 机制、Token 轮换、无感刷新
- **国密全链路** — `cryptoType=sm` 时自动切换 SM4 加密 + HMAC-SM3 签名 + SM3 JWT
- **SSO 单点登录** — 同域 / 跨域 / 前后端分离 / 无 SDK 四种模式，域名校验，参数防丢
- **OAuth2.0** — 授权码 / 隐藏式 / 密码 / 客户端凭证 + OpenID Connect + Scope 校验
- **JWT 集成** — 扩展参数、无状态模式、混合模式、HS256 / HMAC-SM3 双算法
- **Http 认证** — Basic / Digest 一行代码接入
- **参数签名** — 跨系统 API 调用签名校验，防篡改、防重放
- **API Key** — 第三方接入秘钥授权
- **全局过滤器** — CORS、安全响应头、前后置过滤器
- **持久层** — 内存 / 文件 / Redis / PSR-16 任意适配，配置驱动自动装配，独立 Redis 分离
- **密码加密** — MD5 / SHA1 / SHA256 / HMAC / bcrypt
- **多账号体系** — 不同 type 的 StpLogic 实例独立鉴权
- **协程安全** — SaRouter 支持协程上下文隔离（Swoole / Hyperf）
- **框架无关** — 纯 PHP 实现，PSR-7 / PSR-16 适配，适用于任意框架
- **防暴力破解** — 登录失败计数、账号自动锁定、手动解锁
- **IP 异常检测** — 登录 IP 历史记录、异地登录告警
- **设备管理** — 登录设备注册/踢出、UA 自动解析
- **敏感操作验证** — OTP 验证码、安全令牌、场景化验证
- **审计日志** — 登录/登出/踢人/封禁/身份切换全链路记录
- **RPC 上下文** — 微服务间 Token 透传与验证、拦截器模式
- **健康检查工具** — DAO 连接、配置项、Token 状态一键检查
- **性能指标收集** — 登录/登出/鉴权/查询性能指标
- **Token 指纹绑定** — IP + User-Agent 哈希绑定，防止 Token 盗用
- **Token 黑名单** — 手动拉黑 Token，无需等待过期
- **配置构建器** — 链式调用 API 配置 SaToken

## 环境要求

- PHP >= 8.1
- ext-openssl
- ext-redis（可选：使用 Redis 存储适配器时需要）

## 安装

```bash
composer require pohoc/sa-token
```

## 快速开始

### 1. 配置

在项目根目录创建 `config/sa_token.php`：

```php
return [
    'tokenName'       => 'satoken',
    'timeout'         => 86400,
    'activityTimeout' => -1,
    'isReadHeader'    => true,
    'isReadCookie'    => true,
    'isReadBody'      => false,
    'isWriteCookie'   => true,
    'isWriteHeader'   => false,
    'concurrent'      => true,
    'isShare'         => true,
    'maxLoginCount'   => 12,
    'cryptoType'      => 'intl',
];
```

完整配置项参见 [配置参考](#配置参考)。

### 2. 初始化

```php
use SaToken\SaToken;

SaToken::init();

SaToken::init([
    'tokenName' => 'my-token',
    'timeout'   => 7200,
]);
```

#### 使用配置构建器（推荐）

链式调用 API 配置 SaToken，更具可读性和类型安全：

```php
use SaToken\Config\SaTokenConfigBuilder;

$config = (new SaTokenConfigBuilder())
    ->tokenName('my-token')
    ->timeout(7200)
    ->activityTimeout(1800)
    ->concurrent(true)
    ->maxLoginCount(12)
    ->tokenEncrypt(true)
    ->cryptoType('intl')
    ->signAlg('sha256')
    ->tokenFingerprint(true)
    ->build();

SaToken::init($config);
```

### 3. 健康检查与性能指标

一键检查 SaToken 状态，收集性能指标：

```php
use SaToken\Util\SaHealthCheck;
use SaToken\Util\SaMetrics;

// 健康检查
$health = SaHealthCheck::checkAll();
// $health = [
//     'dao_connected' => true,
//     'config_valid' => true,
//     'token_test' => true,
//     'overall' => 'healthy'
// ]

// 性能指标收集
// 在任意操作后
SaMetrics::recordLogin(10001, 1.2); // 登录耗时 ms
SaMetrics::recordCheckLogin(0.05);  // 鉴权耗时 ms
SaMetrics::recordQuery(0.1);        // 查询耗时 ms
SaMetrics::recordDelete(0.08);       // 删除操作耗时 ms

// 获取统计数据
$stats = SaMetrics::getStats();
// $stats = [
//     'login_count' => 100,
//     'login_avg_ms' => 1.1,
//     'check_login_count' => 2000,
//     'check_login_avg_ms' => 0.04,
//     ...
// ]

// 重置统计
SaMetrics::reset();
```

### 4. Token 安全增强

#### Token 指纹绑定（IP + User-Agent）

防止 Token 被盗用，绑定客户端特征：

```php
// 配置开启
$config = (new SaTokenConfigBuilder())
    ->tokenFingerprint(true)
    ->build();

// 登录时自动记录当前 IP + User-Agent
$result = StpUtil::login(10001);

// 访问时自动验证指纹，不匹配则强制重新登录
StpUtil::checkLogin(); // 指纹不匹配时抛出异常
```

#### Token 黑名单

手动拉黑 Token，无需等待过期：

```php
// 拉黑指定 Token，有效期内无法使用
StpUtil::addToBlacklist($tokenValue, 3600);

// 检查是否在黑名单
$isBlacklisted = StpUtil::isInBlacklist($tokenValue);

// 从黑名单移除
StpUtil::removeFromBlacklist($tokenValue);

// 查询所有黑名单 Token
$tokens = StpUtil::getBlacklistTokens();
```

### 5. 登录认证

```php
use SaToken\StpUtil;

$result = StpUtil::login(10001);
$token = $result->getAccessToken();

$param = new \SaToken\SaLoginParameter();
$param->setDeviceType('PC')->setIsLastingCookie(true)->setTimeout(7200);
$result = StpUtil::login(10001, $param);
$token = $result->getAccessToken();

StpUtil::checkLogin();
$isLogin = StpUtil::isLogin();

$loginId = StpUtil::getLoginId();
$loginId = StpUtil::getLoginIdAsNotNull();

$tokenValue = StpUtil::getTokenValue();
$tokenInfo = StpUtil::getTokenInfo();

StpUtil::logout();
StpUtil::logoutByLoginId(10001);
```

### 6. 踢人下线

```php
StpUtil::kickoutByTokenValue($tokenValue);
StpUtil::kickout(10001);
```

### 5. 权限校验

实现 `SaTokenActionInterface` 提供权限/角色数据：

```php
use SaToken\Action\SaTokenActionInterface;
use SaToken\SaToken;

class MyAction implements SaTokenActionInterface
{
    public function getPermissionList(mixed $loginId, string $loginType): array
    {
        return ['user:add', 'user:delete', 'user:update'];
    }

    public function getRoleList(mixed $loginId, string $loginType): array
    {
        return ['admin', 'super-admin'];
    }

    public function generateTokenValue(mixed $loginId, string $loginType): ?string
    {
        return null;
    }
}

SaToken::setAction(new MyAction());
```

校验权限和角色：

```php
StpUtil::checkPermission('user:add');
StpUtil::checkPermissionAnd(['user:add', 'user:delete']);
StpUtil::checkPermissionOr(['user:add', 'user:delete']);
$has = StpUtil::hasPermission('user:add');

StpUtil::checkRole('admin');
StpUtil::checkRoleAnd(['admin', 'super-admin']);
StpUtil::checkRoleOr(['admin', 'super-admin']);
$has = StpUtil::hasRole('admin');
```

### 6. 路由鉴权

```php
use SaToken\SaRouter;
use SaToken\StpUtil;

SaRouter::match('/user/**')->check(fn() => StpUtil::checkLogin());
SaRouter::match('/admin/**', '/system/**')->check(fn() => StpUtil::checkRole('admin'));
SaRouter::notMatch('/public/**')->match('**')->check(fn() => StpUtil::checkLogin());
SaRouter::match('/api/**')->check(fn() => StpUtil::checkLogin())->stop();
```

通配符：`**` 匹配任意多级路径，`*` 匹配单级路径。

### 7. 账号封禁

```php
StpUtil::disable(10001, 'comment');
StpUtil::disable(10001, 'comment', 3, 86400);

$isDisable = StpUtil::isDisable(10001, 'comment');
StpUtil::checkDisable(10001, 'comment');
$level = StpUtil::getDisableLevel(10001, 'comment');

StpUtil::untieDisable(10001, 'comment');
```

### 8. 二级认证

```php
StpUtil::openSafe(120);
StpUtil::openSafe(300, 'payment');

StpUtil::checkSafe();
$isSafe = StpUtil::isSafe();
StpUtil::checkSafe('payment');

StpUtil::closeSafe();
StpUtil::closeSafe('payment');
```

### 9. 身份切换

```php
StpUtil::switchTo(20002);
$isSwitch = StpUtil::isSwitch();
StpUtil::endSwitch();
```

### 10. 会话管理

```php
$session = StpUtil::getSession();
$session = StpUtil::getSessionByLoginId(10001);
$tokenSession = StpUtil::getTokenSession();

$session->set('name', '张三');
$name = $session->get('name');
$name = $session->get('age', 18);
$has = $session->has('name');
$session->delete('name');
$session->update(['key1' => 'v1', 'key2' => 'v2']);
$data = $session->getDataMap();
$session->clear();
$session->destroy();
```

### 11. Token 管理

```php
$timeout = StpUtil::getTokenTimeout();
StpUtil::renewTimeout(3600);
$tempToken = StpUtil::createTempToken(10001, 600);
$device = StpUtil::getLoginDeviceType();
$terminals = StpUtil::getTerminalListByLoginId(10001);
```

### 12. Refresh Token

AccessToken + RefreshToken 双 Token 机制，AccessToken 短期有效，RefreshToken 长期有效，用于无感刷新：

```php
SaToken::init([
    'timeout'              => 7200,       // AccessToken 有效期 2 小时
    'refreshToken'         => true,       // 启用 RefreshToken
    'refreshTokenTimeout'  => 2592000,    // RefreshToken 有效期 30 天
    'refreshTokenRotation' => true,       // 刷新时轮换 RefreshToken
]);
```

登录时自动创建 RefreshToken（通过响应头 `satoken-refresh` 返回）：

```php
$result = StpUtil::login(10001);
$accessToken = $result->getAccessToken();
$refreshToken = $result->getRefreshToken(); // refreshToken=true 时有值
$accessExpire = $result->getAccessExpire();
$refreshExpire = $result->getRefreshExpire();
```

手动创建 RefreshToken：

```php
$refreshToken = StpUtil::createRefreshToken($accessToken);
```

AccessToken 过期后，用 RefreshToken 换取新 Token 对：

```php
$result = StpUtil::refreshToken($refreshToken);
$newAccessToken = $result->getAccessToken();
$newRefreshToken = $result->getRefreshToken(); // rotation=true 时有值
```

撤销 RefreshToken：

```php
StpUtil::revokeRefreshToken($refreshToken);
StpUtil::revokeRefreshTokenByAccessToken($accessToken);
```

查询 RefreshToken：

```php
$isValid = StpUtil::isRefreshTokenValid($refreshToken);
$refreshToken = StpUtil::getRefreshTokenByAccessToken($accessToken);
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `refreshToken` | bool | `false` | 是否启用 RefreshToken |
| `refreshTokenTimeout` | int | `2592000` | RefreshToken 有效期（秒） |
| `refreshTokenRotation` | bool | `true` | 刷新时是否同时轮换 RefreshToken |

安全特性：
- RefreshToken 一次性使用，用完即销毁
- Rotation 模式下每次刷新生成新 RefreshToken，旧 Token 立即失效
- 刷新时检查账号封禁状态
- 登出自动清除关联的 RefreshToken

### 12.1 实际应用中的常见问题

以下配置在示例里可以直接运行，但在生产环境通常需要按部署形态重新评估：

| 场景 | 默认/常见写法 | 实际风险 | 建议 |
|------|---------------|----------|------|
| 前后端分离、跨子域登录 | `cookieSameSite='Strict'` | 浏览器不会在跨站跳转、第三方回调、部分 iframe 场景携带 Cookie，表现为“明明登录了却丢会话” | 同站应用优先保留 `Strict`；跨站场景改为 `None`，同时开启 `cookieSecure=true`，并明确 `cookieDomain` |
| 多实例部署 | 内存 DAO / 单机配置直接上线 | 踢人下线、黑名单、RefreshToken、SSO、登录态同步会在不同节点之间失效 | 至少使用 Redis 或共享缓存；多节点场景不要依赖默认内存存储 |
| 移动网络、代理网络、企业出口 | 开启 `tokenFingerprint=true` | IP 频繁变化、代理层统一出口、UA 被网关改写时会误判盗用，导致用户被频繁踢下线 | 只在高风险后台启用，或改为基于稳定设备标识/代理透传 IP 的策略 |
| RefreshToken 落地 | 刷新令牌直接暴露给前端脚本 | 一旦前端存储或日志泄漏，攻击者可长期续签 AccessToken | 浏览器端优先用 HttpOnly Cookie 承载 RefreshToken；若前端自行持有，必须配合轮换、失效回收和最短必要有效期 |
| RefreshToken 轮换 | 服务端返回新 RefreshToken，客户端异步更新 | 并发请求或旧令牌覆盖新令牌时会造成“刷新一次后全部失效” | 客户端原子更新 token 对；刷新接口避免并发调用；服务端日志中区分 AccessToken 失效和 Rotation 冲突 |
| 登录策略 | 沿用 `concurrent=true`、`isShare=true` | 无法满足“新登录挤掉旧登录”或“同设备唯一会话”等业务要求 | 明确产品语义后再组合 `concurrent`、`isShare`、`maxLoginCount`，不要直接沿用示例值 |
| Token 加密 | 仅开启 `tokenEncrypt=true` | 只能降低 DAO 中内容裸露风险，不能替代 HTTPS、密钥托管、日志脱敏 | 生产环境同时配置 `aesKey`/`sm4Key` 或 `tokenEncryptKey`，并做好密钥轮换与日志审计 |
| 多机时间差 | 默认 `signTimestampGap=600` | 节点时钟漂移过大时会出现签名偶发失败 | 所有节点做 NTP 校时；按链路延迟调整 `signTimestampGap`，不要单纯无限放大 |

如果你的接入场景是 SSO、跨域前后端分离或多节点部署，建议先从 Cookie 策略、共享存储、RefreshToken 保存方式三项开始排查，而不是直接按快速开始配置上线。

### 12.2 框架接入约束

当前仓库提供的是框架无关核心库，不是 Laravel ServiceProvider / Symfony Bundle 这类原生框架插件。因此在实际接入时，需要明确遵守以下生命周期约束：

1. 请求进入时完成 `SaToken::init(...)`，并立刻调用 `SaTokenContext::setRequest(...)`
2. 控制器或业务逻辑执行后，将响应对象回写到 `SaTokenContext::setResponse(...)`
3. 最终返回响应时，优先返回 `SaTokenContext::getResponse()`，因为登录、登出、RefreshToken 续签可能已经改写 Header / Cookie
4. 请求结束时执行 `SaToken::clearContext()`，避免常驻内存、协程或复用 worker 场景下的上下文串用

如果只注入 request，没有把 response 回写到 `SaTokenContext`，那么 `isWriteCookie`、`isWriteHeader` 和 `satoken-refresh` 响应头都可能失效。

### 12.3 当前验证状态

当前仓库已完成以下验证：

- PHPUnit 全量通过：`739` tests / `1578` assertions / `3` skipped
- PHPStan 通过：`No errors`
- PHP-CS-Fixer dry-run 通过：无待修复格式问题
- 已补真实 Redis 集成测试；在配置 `REDIS_HOST` / `REDIS_PORT` 且安装 `ext-redis` 时会执行真实连通与 TTL 校验

建议在 CI 中至少保留三类检查：基础 PHP 版本矩阵、带 Redis 扩展和 Redis 服务容器的测试任务、`phpstan + cs-check` 质量门禁。

### 13. 多账号体系

```php
use SaToken\StpLogic;
use SaToken\SaToken;

$adminLogic = new StpLogic('admin');
SaToken::registerStpLogic($adminLogic);

$adminLogic = SaToken::getStpLogic('admin');
$adminLogic->login(10001);
$adminLogic->checkLogin();
$adminLogic->logout();
```

### 14. 会话查询

```php
use SaToken\TokenManager;

$tokens = TokenManager::searchTokenValue('keyword', 0, 10);
$sessionIds = TokenManager::searchSessionId('keyword', 0, 10);
$tokenSessionIds = TokenManager::searchTokenSessionId('keyword', 0, 10);
```

## Token 风格

支持 6 种内置风格 + 自定义生成策略：

| 风格 | 说明 | 示例 |
|------|------|------|
| `uuid` | 标准 UUID（默认） | `623368f0-ae24-4f...` |
| `simple-random` | 32 位随机字符串 | `a1b2c3d4e5f6...` |
| `random-64` | 64 位随机字符串 | `a1b2...64chars` |
| `random-128` | 128 位随机字符串 | `a1b2...128chars` |
| `random-256` | 256 位随机字符串 | `a1b2...256chars` |
| `tiket` | 20 位纯数字 | `837492017364...` |

自定义生成策略：

```php
class MyAction implements SaTokenActionInterface
{
    public function generateTokenValue(mixed $loginId, string $loginType): ?string
    {
        return 'custom-' . $loginId . '-' . bin2hex(random_bytes(16));
    }
}
```

## Token 内容加密

防止 Token 存储内容泄露，DAO 层透明加解密：

```php
SaToken::init([
    'tokenEncrypt'    => true,
    'tokenEncryptKey' => 'your-secret-key-at-least-32-bytes',
]);
```

- 国际算法：AES-256-CBC + HMAC-SHA256
- 国密算法：SM4-CBC + HMAC-SM3（需 `cryptoType => 'sm'`）

## 国密全链路

配置 `cryptoType => 'sm'` 后，以下环节自动切换国密算法：

| 环节 | 国际算法 | 国密算法 |
|------|---------|---------|
| Token 内容加密 | AES-256-CBC | SM4-CBC |
| 加密签名 | HMAC-SHA256 | HMAC-SM3 |
| SSO 参数签名 | HMAC-SHA256 | HMAC-SM3 |
| JWT 签名 | HS256 | SM3 |

## JWT 集成

### 基本用法

```php
use SaToken\Plugin\SaTokenJwt;

$jwt = new SaTokenJwt('your-secret-key');
$token = $jwt->createToken(10001, 'login');
$payload = $jwt->parseToken($token);
```

### 扩展参数

```php
$token = $jwt->createToken(10001, 'login', null, [
    'role' => 'admin',
    'dept' => 'IT',
]);

$extra = $jwt->getExtraClaims($token);
```

### 无状态模式

Token 自包含所有信息，无需 DAO 存储：

```php
SaToken::init([
    'jwtSecretKey' => 'your-secret-key',
    'jwtStateless' => true,
]);

$token = StpUtil::loginStateless(10001);
```

### SM3 签名

```php
$jwt = new SaTokenJwt('your-secret-key', 'sm');
$token = $jwt->createToken(10001, 'login');
```

## SSO 单点登录

### 配置

```php
SaToken::init([
    'sso' => [
        'loginUrl'     => 'https://sso.example.com/login',
        'authUrl'      => 'https://sso.example.com/auth',
        'backUrl'      => 'https://app.example.com/callback',
        'checkTicketUrl' => 'https://sso.example.com/checkTicket',
        'sloUrl'       => 'https://sso.example.com/logout',
        'mode'         => 'cross-domain',
        'clientId'     => 'your-client-id',
        'clientSecret' => 'your-client-secret',
        'allowDomains' => ['*.example.com', 'app.mycompany.cn'],
        'checkState'   => true,   // 强制校验回调 state 防 CSRF（默认 true，不推荐关闭）
        'crossRedis'   => false,  // 认证中心与客户端是否跨 Redis 部署
        'crossRedisCheckUrl' => '', // 跨 Redis 模式的 check-ticket 端点，必须 HTTPS（localhost 豁免）
    ],
]);
```

### 四种模式

| 模式 | 适用场景 | 类 |
|------|---------|-----|
| `same-domain` | 前端同域 + 后端同 Redis | `SsoModeSameDomain` |
| `cross-domain` | 前端不同域 + 后端同 Redis | `SsoModeCrossDomain` |
| `front-separate` | 前后端分离 | `SsoModeFrontSeparate` |
| `no-sdk` | 认证中心对接未引入 SDK 的客户端 | `SsoModeNoSdk` |

### 使用

```php
use SaToken\Sso\SaSsoManager;

$sso = SaToken::getSsoManager();

$loginUrl = $sso->buildLoginUrl();

// $ticket、$redirect、$state 均来自回调请求参数；
// $state 会与 buildLoginUrl 写入的 state Cookie 比对校验（checkState 默认开启，缺失/不匹配直接抛异常；
// 确需关闭可在 SSO 配置中设置 'checkState' => false，不推荐）
$loginId = $sso->doLoginCallback($ticket, $redirect, $state);
```

### 域名校验

配置 `allowDomains` 后，SSO 回调会校验 redirect 域名是否在白名单内，防止开放重定向攻击。支持通配符（如 `*.example.com`）。

### 参数防丢

登录前 URL 参数自动保存，登录成功后精准回传：

```php
// buildLoginUrl 只有一个参数，携带当前 URL 请通过模式处理器调用
$loginUrl = $sso->getModeHandler()->buildLoginUrl(null, $currentUrl);

$result = $sso->getModeHandler()->doLoginCallbackWithRedirect($ticket);
$loginId = $result['loginId'];
$redirect = $result['redirect'];
```

注意：`restorePreLoginUrl` 恢复登录前 URL 时会强制过 `allowDomains` 白名单（未配置 `allowDomains` 时返回空串）；配置 `clientSecret` 后预登录 URL Cookie 附带 HMAC 签名防篡改。

### 单点注销回调

```php
// 认证中心侧：生成带签名的注销回调参数
$params = $sso->buildSloCallbackParams($loginId);

// 客户端侧：处理注销回调
$sso->doSloCallback($loginId, $params);
```

配置 `clientSecret` 后，`doSloCallback` 会强制验签（回调参数必须包含 `sign`），防止伪造注销请求。

## OAuth2.0

### 配置

```php
SaToken::init([
    // 签发 id_token（OpenID Connect）必需
    'jwtSecretKey' => 'your-jwt-secret-key',
    'oauth2' => [
        'grantTypes'           => ['authorization_code', 'password'],
        'codeTimeout'          => 60,
        'accessTokenTimeout'   => 7200,
        'refreshTokenTimeout'  => 2592000,
        'isNewRefreshToken'    => false,
        'openIdMode'           => true,
        'issuer'               => 'https://auth.example.com',
    ],
]);
```

### 四种授权模式

| 模式 | 说明 |
|------|------|
| `authorization_code` | 授权码模式（推荐） |
| `implicit` | 隐藏式 |
| `password` | 密码模式 |
| `client_credentials` | 客户端凭证模式 |

### 使用

使用前必须先注册客户端（clientId/clientSecret 强制非空，redirectUris 必须 HTTPS 且在白名单内，grantTypes/scopes 为白名单）：

```php
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\SaOAuth2Manager;

$oauth2 = SaToken::getOAuth2Manager();

$oauth2->registerClient(new SaOAuth2Client([
    'clientId'     => 'your-client-id',
    'clientSecret' => 'your-client-secret',
    'redirectUris' => ['https://app.example.com/callback'],
    'grantTypes'   => ['authorization_code', 'refresh_token'],
    'scopes'       => ['user:read', 'user:write'],
]));

// 注意：换 token 必须传与授权请求一致的 redirect_uri；
// 请求 scope 不得超出注册白名单；grant_type 必须在客户端注册列表中
$code = $oauth2->generateAuthorizationCode($clientId, $loginId, $redirectUri, $scope);

$accessToken = $oauth2->exchangeTokenByCode($code, $clientId, $clientSecret, $redirectUri);
```

### PKCE

公开客户端（注册时不配置 clientSecret 且 grantTypes 仅 `authorization_code`）强制使用 PKCE：

```php
// 第 5/6 参数为 codeChallenge/codeChallengeMethod，仅支持 S256，challenge 长度 43-128 字符
$code = $oauth2->generateAuthorizationCode($clientId, $loginId, $redirectUri, $scope, $codeChallenge, 'S256');

// 第 5 参数为 codeVerifier
$accessToken = $oauth2->exchangeTokenByCode($code, $clientId, $clientSecret, $redirectUri, $codeVerifier);
```

### OpenID Connect

配置 `openIdMode => true` 且请求 scope 必须包含 `openid` 时，响应中自动包含 `id_token`（依赖 `jwtSecretKey` 配置）：

```php
$accessToken = $oauth2->exchangeTokenByCode($code, $clientId, $clientSecret, $redirectUri);
$idToken = $accessToken->getIdToken();
```

### Scope 校验

```php
$oauth2->checkScopeAndThrow($accessTokenValue, 'user:read');

$hasScope = $oauth2->hasScope($accessTokenValue, 'user:write');
```

## Http Basic / Digest 认证

```php
use SaToken\SaToken;

$auth = SaToken::getHttpAuth();

$auth->setBasicValidator(function (string $username, string $password): mixed {
    if ($username === 'admin' && $password === '123456') {
        return 10001;
    }
    return null;
});

$auth->checkBasic('My Realm');
```

Digest 认证：

```php
$auth->setDigestValidator(function (string $username): ?string {
    $users = ['admin' => md5('admin:My Realm:123456')];
    return $users[$username] ?? null;
});

$auth->checkDigest('My Realm');
```

Digest 流程：服务端先返回 `401` + `WWW-Authenticate` 响应头（含服务端签发的一次性 nonce，TTL 300 秒），客户端携带该 nonce 完成认证；nonce 在认证成功后立即作废，重放直接拒绝。手搓 Digest 头调试时，必须先触发 challenge 获取服务端签发的 nonce。

## 参数签名校验（SaSign）

跨系统 API 调用签名，防参数篡改、防请求重放。使用前需先在配置中设置 `signKey`：

```php
use SaToken\SaToken;

$sign = SaToken::getSign();

$params = ['userId' => '10001', 'action' => 'query'];
$signed = $sign->signParams($params);

$isValid = $sign->verifySign($signed);
```

防重放默认内置：nonce 一次性存储基于 DAO 原子 `setIfNotExists` 实现，`verifySign` 强制要求 `timestamp` 与 `nonce`，缺失即拒绝；`signParams` / `verifySign` 支持可选 `method` / `path` 参数将 HTTP 方法与路径纳入签名，Web 场景建议传入：

```php
$signed = $sign->signParams($params, 'POST', '/api/order');

$isValid = $sign->verifySign($signed, 'POST', '/api/order');
```

也可通过 `setNonceValidator` 接入自定义 nonce 存储。注意不要使用 `Cache::has` 这类"先查后写"的校验器——它存在并发重放窗口，推荐使用内置存储。

签名算法仅支持 `sha256`（MD5 因碰撞风险已移除）：

```php
$sign->setSignAlg('sha256');
```

## API Key 秘钥授权

```php
use SaToken\SaToken;

$apiKey = SaToken::getApiKey();

$apiKey->registerKey('ak-123456', 'sk-abcdef', 10001);
$apiKey->registerKey('ak-789012', 'sk-ghijkl', 10002);

$apiKey->checkApiKey();
```

自定义验证器：

```php
$apiKey->setValidator(function (string $apiKey, string $apiSecret): mixed {
    $user = Db::table('api_keys')->where('api_key', $apiKey)->first();
    if ($user && hash_equals($user->api_secret, $apiSecret)) {
        return $user->id;
    }
    return null;
});
```

## 全局过滤器

```php
use SaToken\SaToken;

$filter = SaToken::getGlobalFilter();

$filter->setCors([
    'allowOrigin'      => 'https://example.com',
    'allowMethods'     => 'GET, POST, PUT, DELETE',
    'allowHeaders'     => 'Content-Type, Authorization',
    'allowCredentials' => 'true',
    'maxAge'           => '3600',
]);

$filter->addBeforeFilter(function () {
    SaRouter::match('/api/**')->check(fn() => StpUtil::checkLogin());
});

$filter->addAfterFilter(function () {
    // 日志记录等
});

$filter->execute();
```

CORS 预检请求自动处理：

```php
if ($filter->isCorsRequest()) {
    $filter->handlePreflight();
    return;
}
```

## 自定义存储

### 内存存储（默认）

```php
use SaToken\SaToken;

SaToken::setDao(new \SaToken\Dao\SaTokenDaoMemory());
```

### 文件存储

单机部署、无 Redis 环境时使用本地文件存储（flock 保证单机多进程原子性，不支持 NFS 等网络文件系统）：

```php
use SaToken\Dao\SaTokenDaoFile;
use SaToken\SaToken;

SaToken::setDao(new SaTokenDaoFile(['path' => __DIR__ . '/runtime/sa-token']));
```

### Redis 存储

```php
use SaToken\Dao\SaTokenDaoRedis;
use SaToken\SaToken;

SaToken::setDao(new SaTokenDaoRedis());
```

### 独立 Redis

权限缓存与业务缓存分离：

```php
$dao = SaTokenDaoRedis::createWithSeparateRedis(
    ['host' => '127.0.0.1', 'port' => 6379, 'db' => 0],
    ['host' => '127.0.0.1', 'port' => 6379, 'db' => 1],
);
SaToken::setDao($dao);
```

### PSR-16 适配

```php
use SaToken\Dao\SaTokenDaoPsr16;
use SaToken\SaToken;

$psr16Cache = new SomePsr16Cache();
SaToken::setDao(new SaTokenDaoPsr16($psr16Cache));
```

### 配置驱动自动装配

在 `config/sa_token.php` 中声明 `storage` 段，`SaToken::init()` 会自动构造存储层（无需再调用 `setDao`；显式 `setDao` 的优先级更高）：

```php
return [
    // 文件存储（单机）
    'storage' => [
        'type'     => 'file',
        'path'     => runtime_path() . '/sa-token',  // 数据目录，默认 sys_get_temp_dir()/sa-token
        'scanLimit'=> 10000,                          // search 扫描文件数上限
    ],

    // 或 Redis 存储（分布式部署）
    // 'storage' => [
    //     'type'     => 'redis',
    //     'host'     => '127.0.0.1',
    //     'port'     => 6379,
    //     'password' => '',
    //     'database' => 0,
    //     'timeout'  => 0,
    // ],
];
```

选型建议：`memory` 仅适合单进程/测试；`file` 适合单机小规模生产（无外部依赖，但 search 为目录扫描，规模大时建议 Redis）；`redis` 适合多实例部署与分布式锁场景。

### 自定义 DAO

实现 `SaTokenDaoInterface`：

```php
use SaToken\Dao\SaTokenDaoInterface;

class MyDao implements SaTokenDaoInterface
{
    public function get(string $key): ?string { /* ... */ }
    public function set(string $key, string $value, ?int $timeout = null): void { /* ... */ }
    public function update(string $key, string $value): void { /* ... */ }
    public function delete(string $key): void { /* ... */ }
    public function exists(string $key): bool { /* ... */ }
    public function getTimeout(string $key): int { /* ... */ }
    public function expire(string $key, int $timeout): void { /* ... */ }
    public function getAndExpire(string $key, int $timeout): ?string { /* ... */ }
    public function getAndDelete(string $key): ?string { /* ... */ }
    public function size(): int { /* ... */ }
    public function search(string $prefix, string $keyword, int $start, int $size): array { /* ... */ }
    public function deleteMultiple(array $keys): void { /* ... */ } // 批量删除
    public function searchKeys(string $prefix, string $keyword, int $start, int $size): array { /* ... */ } // 仅返回键名列表
    public function setIfNotExists(string $key, string $value, ?int $timeout = null): bool { /* ... */ } // 仅当 key 不存在时设置（登录锁/签名防重放依赖）
    public function increment(string $key, int $amount = 1, ?int $timeout = null): int { /* ... */ } // 原子计数（防爆破/OTP 依赖）
}
```

## 密码加密工具

```php
use SaToken\Plugin\SaTokenCrypto;

$hash = SaTokenCrypto::md5('password');
$hash = SaTokenCrypto::sha1('password');
$hash = SaTokenCrypto::sha256('password');

$hmac = SaTokenCrypto::hmacSha256('data', 'key');
$hmac = SaTokenCrypto::hmacSha1('data', 'key');

$bcrypt = SaTokenCrypto::bcryptHash('password', 12);
$valid = SaTokenCrypto::bcryptVerify('password', $bcrypt);
```

AES / RSA / SM2 / SM3 / SM4 等加解密功能参见 `SaTokenCrypto` 类。

## 防暴力破解

登录失败次数记录与账号自动锁定：

```php
StpUtil::checkAntiBrute('user@example.com');

StpUtil::recordAntiBruteFailure('user@example.com');

$isLocked = StpUtil::isAccountLocked('user@example.com');
$remaining = StpUtil::getRemainingLockTime('user@example.com');

StpUtil::unlockAccount('user@example.com');

$info = StpUtil::getAntiBruteInfo('user@example.com');
// ['failCount' => 3, 'isLocked' => false, 'remainingLockTime' => 0, ...]
```

配置：

```php
SaToken::init([
    'antiBruteMaxFailures'  => 5,
    'antiBruteLockDuration' => 600,
]);
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `antiBruteMaxFailures` | int | `0` | 最大失败次数，`0` 不限制 |
| `antiBruteLockDuration` | int | `600` | 锁定时长（秒） |

## IP 异常检测

记录登录 IP 历史，检测异地登录异常：

```php
$info = StpUtil::getLoginInfo(10001);
// ['currentIp' => '192.168.1.1', 'lastLoginIp' => '10.0.0.1', 'anomalyCount' => 2, ...]

$count = StpUtil::getAnomalyCount(10001);
$history = StpUtil::getIpHistory(10001);

StpUtil::clearLoginHistory(10001);
```

配置：

```php
SaToken::init([
    'ipAnomalyDetection'   => true,
    'ipAnomalySensitivity' => 3,
]);
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `ipAnomalyDetection` | bool | `false` | 是否启用 IP 异常检测 |
| `ipAnomalySensitivity` | int | `3` | 灵敏度（历史同网段 IP 数 ≥ 此值视为正常） |

## 设备管理

登录设备注册与踢出：

```php
$devices = StpUtil::getDeviceList(10001);
$count = StpUtil::getDeviceCount(10001);

StpUtil::kickoutDevice(10001, 'device-id-xxx');

$kickedCount = StpUtil::kickoutAllDevices(10001, $currentToken);

$device = StpUtil::findDevice(10001, 'device-id-xxx');
```

配置：

```php
SaToken::init([
    'deviceManagement' => true,
]);
```

设备信息自动检测（User-Agent 解析）：设备类型（PC/Mobile/Tablet）、设备名称（微信/钉钉/支付宝/Web）、操作系统、浏览器。

## 敏感操作验证

OTP 验证码与安全令牌：

```php
$code = StpUtil::generateOtpCode('payment');
$code = StpUtil::sendOtpCode('payment');

StpUtil::verifyOtpCode('payment', '123456');

$isVerified = StpUtil::isSensitiveVerified('payment');
$remaining = StpUtil::getSensitiveVerifyRemainingAttempts('payment');
StpUtil::clearSensitiveVerify('payment');

$token = StpUtil::openSensitiveVerify('payment', 600);
StpUtil::checkSensitiveVerify('payment', $token);
```

## 审计日志

记录登录、登出、踢人、封禁、身份切换等操作：

```php
$logs = StpUtil::getAuditLogs(50);
$log = StpUtil::getAuditLog('log-id-xxx');

SaAuditLog::logLogin(10001);
SaAuditLog::logLogout(10001);
SaAuditLog::logKickout(10001);
SaAuditLog::logDisable(10001, 'login', '违规操作');
SaAuditLog::logSwitchTo(10001, 20002);

$recentLogs = SaAuditLog::getRecentLogs('login', 100);
$logsByIp = SaAuditLog::getLogsByIp('192.168.1.1');
$logsByEvent = SaAuditLog::getLogsByEvent('login');

SaAuditLog::clearLogs();
```

配置：

```php
SaToken::init([
    'auditLog'            => true,
    'auditLogMaxEntries'  => 1000,
    'auditLogTtlDays'     => 30,
]);
```

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `auditLog` | bool | `false` | 是否启用审计日志 |
| `auditLogMaxEntries` | int | `1000` | 每种登录类型最大日志条数 |
| `auditLogTtlDays` | int | `30` | 日志保留天数 |

## RPC 上下文传播

微服务间 Token 透传与验证：

```php
use SaToken\Rpc\SaRpcContext;
use SaToken\Rpc\SaRpcInterceptor;

// 发送端：将认证信息注入请求头
$headers = SaRpcContext::attachToHeaders(['X-Custom' => 'value']);
$psr7Request = SaRpcContext::attachToRequest($request);

// 接收端：提取并验证
SaRpcContext::extractAndValidate();

$loginId = SaRpcContext::getForwardedLoginId();
$token = SaRpcContext::getForwardedToken();
$loginType = SaRpcContext::getForwardedLoginType();

$isRpc = SaRpcContext::isRpcRequest();
```

拦截器模式：

```php
$interceptor = new SaRpcInterceptor();
$interceptor->setValidateToken(true)
    ->setAutoLogin(true)
    ->setLoginType('login');

$interceptor->handleIncoming();
$outHeaders = $interceptor->handleOutgoing();
```

## 事件监听

```php
use SaToken\Listener\SaTokenListenerInterface;
use SaToken\SaToken;

class MyListener implements SaTokenListenerInterface
{
    public function onLogin(string $loginType, mixed $loginId, string $tokenValue, array $extra = []): void
    {
    }

    public function onLogout(string $loginType, mixed $loginId, string $tokenValue, array $extra = []): void
    {
    }

    public function onKickout(string $loginType, mixed $loginId, string $tokenValue, array $extra = []): void
    {
    }

    public function onReplaced(string $loginType, mixed $loginId, string $tokenValue, array $extra = []): void
    {
    }
}

SaToken::addListener(new MyListener());
```

## 异常处理

所有异常均继承 `SaToken\Exception\SaTokenException`：

| 异常类 | 触发场景 |
|--------|----------|
| `NotLoginException` | 未登录 / Token 无效 / Token 已过期 / Token 已被踢出 |
| `NotPermissionException` | 权限校验不通过 |
| `NotRoleException` | 角色校验不通过 |
| `DisableServiceException` | 账号被封禁 |
| `NotSafeException` | 二级认证校验不通过 |

```php
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotPermissionException;

try {
    StpUtil::checkPermission('user:add');
} catch (NotPermissionException $e) {
    echo $e->getPermission();
} catch (NotLoginException $e) {
    echo $e->getType();
}
```

## 配置参考

### 核心配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `tokenName` | string | `satoken` | Token 名称（Cookie/Header/参数名） |
| `tokenPrefix` | string | `''` | Token 前缀，如 `Bearer` |
| `tokenStyle` | string | `uuid` | Token 风格：`uuid` / `simple-random` / `random-64` / `random-128` / `random-256` / `tiket` |
| `timeout` | int | `86400` | Token 有效期（秒），`-1` 永不过期 |
| `activityTimeout` | int | `-1` | 最低活动频率（秒），`-1` 不限制 |
| `concurrent` | bool | `true` | 是否允许多端同时登录 |
| `isShare` | bool | `true` | 同端是否复用 Token |
| `maxLoginCount` | int | `12` | 同账号最大登录数，`-1` 不限制 |
| `maxTryTimes` | int | `12` | 创建 Token 最高循环次数 |
| `isReadHeader` | bool | `true` | 从 Header 读取 Token |
| `isReadCookie` | bool | `true` | 从 Cookie 读取 Token |
| `isReadBody` | bool | `false` | 从请求体读取 Token |
| `isWriteCookie` | bool | `true` | 登录后写入 Cookie |
| `isWriteHeader` | bool | `false` | 登录后写入响应头 |
| `cookieDomain` | string | `''` | Cookie 作用域 |
| `cookiePath` | string | `'/'` | Cookie 路径 |
| `cookieSecure` | bool | `true` | Cookie 仅 HTTPS 传输 |
| `cookieHttpOnly` | bool | `true` | Cookie HttpOnly |
| `cookieSameSite` | string | `'Strict'` | Cookie SameSite：`Strict` / `Lax` / `None` |
| `tokenFingerprint` | bool | `false` | 是否启用 Token 指纹绑定（IP + User-Agent） |
| `storage` | array | `['type' => 'memory']` | 存储层配置，`type`: `memory` / `file` / `redis`；`file` 可配 `path`、`scanLimit`，`redis` 可配 `host` / `port` / `password` / `database` / `timeout`；PSR-16 请用 `SaToken::setDao()` |

### 加密配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `cryptoType` | string | `'intl'` | 加密类型：`intl` / `sm` |
| `tokenEncrypt` | bool | `false` | 是否启用 Token 内容加密 |
| `tokenEncryptKey` | string | `''` | Token 加密密钥 |
| `aesKey` | string | `''` | AES 密钥（16/24/32 字节） |
| `rsaPrivateKey` | string | `''` | RSA 私钥 |
| `rsaPublicKey` | string | `''` | RSA 公钥 |
| `hmacKey` | string | `''` | HMAC 密钥 |
| `sm2PrivateKey` | string | `''` | SM2 私钥 |
| `sm2PublicKey` | string | `''` | SM2 公钥 |
| `sm4Key` | string | `''` | SM4 密钥（16 字节） |
| `jwtSecretKey` | string | `''` | JWT 密钥 |
| `jwtStateless` | bool | `false` | JWT 无状态模式 |

### 签名配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `signKey` | string | `''` | 参数签名密钥 |
| `signTimestampGap` | int | `600` | 签名时间戳容差（秒） |
| `signAlg` | string | `'sha256'` | 签名算法：仅支持 `sha256`（MD5 因碰撞风险已移除） |

### API Key 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `apiKeyHeader` | string | `'api-key'` | API Key 请求头名 |
| `apiSecretHeader` | string | `'api-secret'` | API Secret 请求头名 |

### Redis 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `separateRedis` | bool | `false` | 是否使用独立 Redis |
| `separateRedisConfig` | array | `[]` | 独立 Redis 连接配置 |

### 其他配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `tokenSessionCheckLogin` | bool | `true` | TokenSession 是否校验登录 |
| `refreshToken` | bool | `false` | 是否启用 RefreshToken |
| `refreshTokenTimeout` | int | `2592000` | RefreshToken 有效期（秒） |
| `refreshTokenRotation` | bool | `true` | 刷新时是否轮换 RefreshToken |

### SSO 配置

| 键名 | 默认值 | 说明 |
|------|--------|------|
| `loginUrl` | `''` | SSO 登录地址 |
| `authUrl` | `''` | 认证中心 URL |
| `backUrl` | `''` | 回调地址 |
| `checkTicketUrl` | `''` | Ticket 校验地址 |
| `sloUrl` | `''` | 单点注销地址 |
| `mode` | `'same-domain'` | SSO 模式：`same-domain` / `cross-domain` / `front-separate` / `no-sdk` |
| `clientId` | `''` | Client ID |
| `clientSecret` | `''` | Client Secret |
| `allowDomains` | `[]` | 允许的回调域名白名单（支持通配符 `*`） |
| `paramName` | `'sso_params'` | 参数防丢 Cookie 名 |
| `checkState` | `true` | 强制校验回调 state 防 CSRF |
| `crossRedis` | `false` | 认证中心与客户端是否跨 Redis 部署 |
| `crossRedisCheckUrl` | `''` | 跨 Redis 模式的 check-ticket 端点，必须 HTTPS（localhost 豁免） |

### OAuth2 配置

| 键名 | 默认值 | 说明 |
|------|--------|------|
| `grantTypes` | `['authorization_code']` | 支持的授权模式 |
| `codeTimeout` | `60` | 授权码有效期（秒） |
| `accessTokenTimeout` | `7200` | Access Token 有效期（秒） |
| `refreshTokenTimeout` | `-1` | Refresh Token 有效期（秒），`-1` 不刷新 |
| `isNewRefreshToken` | `false` | 是否每次生成新 Refresh Token |
| `openIdMode` | `false` | 是否启用 OpenID Connect |
| `issuer` | `''` | OpenID 签发者 URL |
| `clientSecretMaxFailures` | `10` | 密钥连续失败临时锁定阈值 |
| `clientFailureWindow` | `300` | 失败计数窗口（秒） |

## 项目结构

```
src/
├── Action/                         # 业务行为接口
│   └── SaTokenActionInterface.php
├── Auth/                           # 认证扩展
│   ├── SaHttpAuth.php              # Http Basic / Digest
│   └── SaApiKey.php                # API Key 秘钥授权
├── Config/
│   └── SaTokenConfig.php           # 核心配置类
├── Dao/                            # 持久层
│   ├── SaTokenDaoInterface.php     # DAO 接口
│   ├── SaTokenDaoMemory.php        # 内存存储
│   ├── SaTokenDaoRedis.php         # Redis 存储（支持独立 Redis）
│   └── SaTokenDaoPsr16.php         # PSR-16 适配
├── Exception/                      # 异常类
│   ├── SaTokenException.php
│   ├── NotLoginException.php
│   ├── NotPermissionException.php
│   ├── NotRoleException.php
│   ├── DisableServiceException.php
│   └── NotSafeException.php
├── Listener/                       # 事件监听
│   ├── SaTokenEvent.php
│   └── SaTokenListenerInterface.php
├── Middleware/                      # 中间件
│   └── SaGlobalFilter.php          # 全局过滤器（CORS + 安全头）
├── OAuth2/                         # OAuth2.0 模块
│   ├── Data/                       # 数据对象
│   │   ├── SaOAuth2AccessToken.php
│   │   ├── SaOAuth2AuthorizationCode.php
│   │   ├── SaOAuth2Client.php
│   │   ├── SaOAuth2RefreshToken.php
│   │   └── SaOAuth2IdToken.php
│   ├── Strategy/                   # 策略模式
│   │   ├── AuthorizationCodeStrategy.php
│   │   ├── ImplicitStrategy.php
│   │   ├── PasswordStrategy.php
│   │   └── ClientCredentialsStrategy.php
│   ├── SaOAuth2Config.php
│   ├── SaOAuth2Handle.php
│   └── SaOAuth2Manager.php
├── Plugin/                         # 插件
│   ├── SaTokenCrypto.php           # 加密工具（AES/RSA/HMAC/MD5/SHA/bcrypt/SM）
│   ├── SaTokenJwt.php              # JWT（HS256/HMAC-SM3 + 扩展参数 + 无状态）
│   └── SaTokenSmCrypto.php         # 国密插件（SM2 签名验签 + SM3 哈希 + SM4 加解密）
├── Rpc/                            # 微服务 RPC
│   ├── SaRpcContext.php            # RPC 上下文（Token 透传 + 验证）
│   └── SaRpcInterceptor.php       # RPC 拦截器（自动验证 + 自动登录）
├── Security/                       # 安全模块
│   ├── SaAntiBruteUtil.php         # 防暴力破解（失败计数 + 账号锁定）
│   ├── SaAuditLog.php              # 审计日志（登录/登出/踢人/封禁/切换）
│   ├── SaIpAnomalyDetector.php     # IP 异常检测（异地登录告警）
│   ├── SaLoginDeviceManager.php    # 设备管理（注册/踢出/UA 解析）
│   └── SaSensitiveVerify.php       # 敏感操作验证（OTP + 安全令牌）
├── Session/                        # 会话维护
│   └── SaSessionCleaner.php        # 过期会话清理
├── Sign/                           # 参数签名
│   └── SaSign.php                  # 签名校验（防篡改 + 防重放）
├── Sso/                            # SSO 单点登录
│   ├── Mode/                       # 三种模式
│   │   ├── SsoModeSameDomain.php
│   │   ├── SsoModeCrossDomain.php
│   │   └── SsoModeFrontSeparate.php
│   ├── SaSsoConfig.php
│   ├── SaSsoHandle.php
│   └── SaSsoManager.php
├── Util/                           # 工具类
│   ├── SaFoxUtil.php               # 通用工具
│   ├── SaTokenContext.php           # 请求上下文
│   └── SaTokenEncryptor.php        # Token 加解密器
├── SaLoginParameter.php            # 登录参数类
├── SaRouter.php                    # 路由鉴权匹配器（协程安全）
├── SaSession.php                   # 会话管理
├── SaTerminalInfo.php              # 终端信息
├── SaToken.php                     # 核心入口类
├── SaTokenInfo.php                 # Token 信息
├── StpLogic.php                    # 底层鉴权逻辑
├── StpUtil.php                     # 静态鉴权入口
└── TokenManager.php                # Token 管理器
```

## 依赖

| 依赖 | 用途 |
|------|------|
| `ext-openssl` | AES/RSA/HMAC 等加密算法 |
| `ext-redis` | 可选，Redis 分布式会话存储 |
| `firebase/php-jwt` | JWT Token 模式 |
| `pohoc/crypto-sm` | 国密 SM2/SM3/SM4 算法 |
| `psr/http-message` | PSR-7 HTTP 消息接口 |
| `psr/simple-cache` | PSR-16 缓存适配 |

## License

MIT
