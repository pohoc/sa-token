# Sa-Token

<p align="center">
<img src="https://img.shields.io/badge/PHP-8.1%20~%208.4-777BB4?style=flat-square&logo=php&logoColor=white" alt="PHP Version">
<img src="https://img.shields.io/github/license/pohoc/sa-token?style=flat-square&label=License" alt="License">
<img src="https://img.shields.io/github/actions/workflow/status/pohoc/sa-token/php.yml?branch=main&style=flat-square&label=CI" alt="CI Status">
</p>

适用于 PHP 生态的轻量级权限认证框架。

## 特性

- **登录认证**：单端/多端登录、同端互斥登录、记住我模式、踢人下线、账号封禁、临时 Token
- **多账号体系**：不同 type 的 StpLogic 实例（如 User/Admin 独立登录体系）
- **二级认证**：敏感操作二次验证（openSafe / checkSafe / closeSafe）
- **身份切换**：管理员临时切换身份排查问题（switchTo / endSwitch）
- **权限校验**：角色/权限验证、路由式鉴权（SaRouter 链式匹配）
- **会话管理**：SaSession 键值对存储、TokenSession、会话搜索、超时续期
- **加密双轨**：国际算法（AES/RSA/HMAC-SHA256）+ 国密算法（SM2/SM3/SM4）
- **SSO 单点登录**：同域 Cookie / 跨域认证中心 / 前后端分离三种模式
- **OAuth2.0**：授权码 / 隐藏式 / 密码 / 客户端凭证四种模式
- **框架无关**：纯静态调用入口，支持 ThinkPHP、Laravel、Hyperf 等任意框架

## 环境要求

- PHP >= 8.1
- OpenSSL 扩展

## 安装

```bash
composer require pohoc/sa-token
```

## 快速开始

### 1. 配置

在项目根目录创建 `config/sa_token.php`：

```php
return [
    'tokenName'       => 'satoken',      // Token 名称（Cookie/Header/参数名）
    'timeout'         => 86400,           // Token 有效期（秒），-1 永不过期
    'activityTimeout' => -1,              // 最低活动频率（秒），-1 不限制
    'isReadHeader'    => true,            // 从 Header 读取 Token
    'isReadCookie'    => true,            // 从 Cookie 读取 Token
    'isReadBody'      => false,           // 从请求体读取 Token
    'isWriteCookie'   => true,            // 登录后写入 Cookie
    'isWriteHeader'   => false,           // 登录后写入响应头
    'concurrent'      => true,            // 允许多端同时登录
    'isShare'         => true,            // 同端复用 Token
    'maxLoginCount'   => 12,              // 同账号最大登录数，-1 不限制
    'cryptoType'      => 'intl',          // 加密类型：intl / sm
];
```

完整配置项参见 [配置参考](#配置参考)。

### 2. 初始化

```php
use SaToken\SaToken;

// 自动加载 config/sa_token.php
SaToken::init();

// 或手动传入配置
SaToken::init([
    'tokenName' => 'my-token',
    'timeout'   => 7200,
]);
```

### 3. 登录认证

```php
use SaToken\StpUtil;

// 登录（返回 Token 值）
$token = StpUtil::login(10001);

// 带参数登录：指定设备类型 + 记住我 + 自定义超时
$param = new \SaToken\SaLoginParameter();
$param->setDeviceType('PC')->setIsLastingCookie(true)->setTimeout(7200);
$token = StpUtil::login(10001, $param);

// 检查是否已登录
StpUtil::checkLogin();       // 未登录抛出异常
$isLogin = StpUtil::isLogin(); // 返回 bool

// 获取登录 ID
$loginId = StpUtil::getLoginId();           // 未登录返回 null
$loginId = StpUtil::getLoginIdAsNotNull();  // 未登录抛出异常

// 获取当前 Token
$tokenValue = StpUtil::getTokenValue();

// 获取 Token 信息
$tokenInfo = StpUtil::getTokenInfo();

// 注销
StpUtil::logout();                  // 当前 Token 注销
StpUtil::logoutByLoginId(10001);    // 指定账号全部注销
```

### 4. 踢人下线

```php
// 踢出指定 Token（对方再次访问会抛出 NotLoginException）
StpUtil::kickoutByTokenValue($tokenValue);

// 踢出指定账号的所有会话
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
}

SaToken::setAction(new MyAction());
```

校验权限和角色：

```php
// 校验单个权限（不通过抛出 NotPermissionException）
StpUtil::checkPermission('user:add');

// 校验多个权限 — 全部满足
StpUtil::checkPermissionAnd(['user:add', 'user:delete']);

// 校验多个权限 — 任一满足
StpUtil::checkPermissionOr(['user:add', 'user:delete']);

// 是否有指定权限（返回 bool）
$has = StpUtil::hasPermission('user:add');

// 校验角色
StpUtil::checkRole('admin');
StpUtil::checkRoleAnd(['admin', 'super-admin']);
StpUtil::checkRoleOr(['admin', 'super-admin']);
$has = StpUtil::hasRole('admin');
```

### 6. 路由鉴权

```php
use SaToken\SaRouter;
use SaToken\StpUtil;

// 匹配路径，校验登录
SaRouter::match('/user/**')->check(fn() => StpUtil::checkLogin());

// 匹配多个路径
SaRouter::match('/admin/**', '/system/**')->check(fn() => StpUtil::checkRole('admin'));

// 排除路径 — 除 /public 外全部校验
SaRouter::notMatch('/public/**')->match('**')->check(fn() => StpUtil::checkLogin());

// 停止后续匹配
SaRouter::match('/api/**')->check(fn() => StpUtil::checkLogin())->stop();
```

通配符说明：
- `**` 匹配任意多级路径（包括空路径）
- `*` 匹配单级路径（不含 `/`）

### 7. 账号封禁

```php
// 封禁账号（默认永久封禁，level=1）
StpUtil::disable(10001, 'comment');

// 定时封禁（86400 秒 = 1 天）
StpUtil::disable(10001, 'comment', 1, 86400);

// 分级封禁（不同 level 代表不同封禁程度）
StpUtil::disable(10001, 'comment', 3, 86400);

// 检查是否被封禁
$isDisable = StpUtil::isDisable(10001, 'comment');  // 返回 bool
StpUtil::checkDisable(10001, 'comment');             // 被封禁抛出 DisableServiceException

// 获取封禁等级
$level = StpUtil::getDisableLevel(10001, 'comment'); // -1 表示未封禁

// 解除封禁
StpUtil::untieDisable(10001, 'comment');
```

### 8. 二级认证

```php
// 开启安全窗口（120 秒内免二次验证）
StpUtil::openSafe(120);

// 指定服务标识
StpUtil::openSafe(300, 'payment');

// 校验是否在安全窗口内
StpUtil::checkSafe();                  // 不在窗口内抛出 NotSafeException
$isSafe = StpUtil::isSafe();           // 返回 bool
StpUtil::checkSafe('payment');
$isSafe = StpUtil::isSafe('payment');

// 关闭安全窗口
StpUtil::closeSafe();
StpUtil::closeSafe('payment');
```

### 9. 身份切换

```php
// 临时切换到目标身份
StpUtil::switchTo(20002);

// 判断是否处于切换状态
$isSwitch = StpUtil::isSwitch();

// 结束切换，恢复原身份
StpUtil::endSwitch();
```

### 10. 会话管理

```php
// 获取当前账号会话
$session = StpUtil::getSession();

// 获取指定账号会话
$session = StpUtil::getSessionByLoginId(10001);

// 获取 Token 独享会话
$tokenSession = StpUtil::getTokenSession();

// 会话数据操作
$session->set('name', '张三');
$name = $session->get('name');           // '张三'
$name = $session->get('age', 18);        // 不存在时返回默认值 18
$has = $session->has('name');            // true
$session->delete('name');
$session->update(['key1' => 'v1', 'key2' => 'v2']);  // 批量设置
$data = $session->getDataMap();          // 获取全部数据
$session->clear();                       // 清空数据
$session->destroy();                     // 销毁会话
```

### 11. Token 管理

```php
// 获取 Token 剩余有效期
$timeout = StpUtil::getTokenTimeout();

// 续期 Token
StpUtil::renewTimeout(3600);

// 创建临时 Token（与登录无关，有过期时间）
$tempToken = StpUtil::createTempToken(10001, 600); // 600 秒有效

// 获取当前登录设备类型
$device = StpUtil::getLoginDeviceType();

// 获取指定账号的所有终端信息
$terminals = StpUtil::getTerminalListByLoginId(10001);
```

### 12. 多账号体系

```php
use SaToken\StpLogic;
use SaToken\SaToken;

// 创建独立登录体系
$adminLogic = new StpLogic('admin');
SaToken::registerStpLogic($adminLogic);

// 或通过 SaToken 获取（自动创建）
$adminLogic = SaToken::getStpLogic('admin');

// 使用
$adminLogic->login(10001);
$adminLogic->checkLogin();
$adminLogic->logout();
```

不同 `type` 的 StpLogic 拥有完全独立的登录态、Token、Session，互不干扰。

## 自定义存储

框架默认使用内存存储（`SaTokenDaoMemory`），重启即丢失。生产环境需替换为持久化存储。

### Redis 存储

```php
use SaToken\Dao\SaTokenDaoRedis;
use SaToken\SaToken;

SaToken::setDao(new SaTokenDaoRedis());
```

依赖 `predis/predis`（或 `ext-redis`）。

### PSR-16 适配

```php
use SaToken\Dao\SaTokenDaoPsr16;
use SaToken\SaToken;

$psr16Cache = new SomePsr16Cache();  // 任意 PSR-16 实现
SaToken::setDao(new SaTokenDaoPsr16($psr16Cache));
```

依赖 `psr/simple-cache`。

### 自定义 DAO

实现 `SaTokenDaoInterface`：

```php
use SaToken\Dao\SaTokenDaoInterface;

class MyDao implements SaTokenDaoInterface
{
    public function get(string $key): ?string { /* ... */ }
    public function set(string $key, string $value, ?int $timeout = null): void { /* ... */ }
    public function delete(string $key): void { /* ... */ }
    public function exists(string $key): bool { /* ... */ }
    public function getTimeout(string $key): int { /* ... */ }
    public function expire(string $key, int $timeout): void { /* ... */ }
}
```

## 事件监听

```php
use SaToken\Listener\SaTokenListenerInterface;
use SaToken\SaToken;

class MyListener implements SaTokenListenerInterface
{
    public function onLogin(string $loginType, mixed $loginId, string $tokenValue, array $extra = []): void
    {
        // 登录事件
    }

    public function onLogout(string $loginType, mixed $loginId, string $tokenValue, array $extra = []): void
    {
        // 注销事件
    }

    public function onKickout(string $loginType, mixed $loginId, string $tokenValue, array $extra = []): void
    {
        // 踢人下线事件
    }

    public function onReplaced(string $loginType, mixed $loginId, string $tokenValue, array $extra = []): void
    {
        // 被顶下线事件
    }
}

SaToken::addListener(new MyListener());
```

## 加密

### 国际算法（默认）

```php
// AES 加解密（需配置 aesKey，16/24/32 字节对应 AES-128/192/256）
$encrypted = SaCrypto::aesEncrypt('hello');
$decrypted = SaCrypto::aesDecrypt($encrypted);

// RSA 加解密（需配置 rsaPrivateKey / rsaPublicKey）
$encrypted = SaCrypto::rsaEncrypt('hello');
$decrypted = SaCrypto::rsaDecrypt($encrypted);

// HMAC-SHA256 签名（需配置 hmacKey）
$sign = SaCrypto::hmacSign('hello');
$valid = SaCrypto::hmacVerify('hello', $sign);
```

### 国密算法

需配置 `cryptoType => 'sm'` 及对应密钥：

```php
// SM2 加解密/签名
$encrypted = SaCrypto::sm2Encrypt('hello');
$decrypted = SaCrypto::sm2Decrypt($encrypted);

// SM3 哈希
$hash = SaCrypto::sm3('hello');

// SM4 加解密
$encrypted = SaCrypto::sm4Encrypt('hello');
$decrypted = SaCrypto::sm4Decrypt($encrypted);
```

## SSO 单点登录

配置 `sso` 项后使用：

```php
use SaToken\Sso\SaSsoHandle;

// 构建登录 URL
$loginUrl = SaSsoHandle::buildLoginUrl();

// 处理 SSO 回调（ticket 换取账号 ID）
$loginId = SaSsoHandle::ssoCallback($ticket);
```

支持三种模式：
- `same-domain`：同域 Cookie
- `cross-domain`：跨域认证中心
- `front-separate`：前后端分离

## OAuth2.0

配置 `oauth2` 项后使用：

```php
use SaToken\OAuth2\SaOAuth2Handle;

// 生成授权码
$code = SaOAuth2Handle::generateCode($clientId, $loginId, $redirectUri);

// 授权码换 Access Token
$accessToken = SaOAuth2Handle::getTokenByCode($code, $clientId, $clientSecret);

// 刷新 Token
$newToken = SaOAuth2Handle::refreshToken($refreshToken, $clientId, $clientSecret);
```

支持四种授权模式：
- `authorization_code`：授权码模式
- `implicit`：隐藏式
- `password`：密码模式
- `client_credentials`：客户端凭证模式

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
    // 无权限
    echo $e->getPermission(); // 'user:add'
} catch (NotLoginException $e) {
    // 未登录
    echo $e->getType(); // 如 'NotLoginException.TOKEN_TIMEOUT'
}
```

## 配置参考

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `tokenName` | string | `satoken` | Token 名称（Cookie/Header/参数名） |
| `tokenPrefix` | string | `''` | Token 前缀，如 `Bearer` |
| `tokenStyle` | string | `uuid` | Token 风格：`uuid` / `simple-random` |
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
| `cookieSecure` | bool | `false` | Cookie 仅 HTTPS 传输 |
| `cookieHttpOnly` | bool | `false` | Cookie HttpOnly |
| `cookieSameSite` | string | `'Lax'` | Cookie SameSite：`Strict` / `Lax` / `None` |
| `cryptoType` | string | `'intl'` | 加密类型：`intl` / `sm` |
| `aesKey` | string | `''` | AES 密钥（16/24/32 字节） |
| `rsaPrivateKey` | string | `''` | RSA 私钥 |
| `rsaPublicKey` | string | `''` | RSA 公钥 |
| `hmacKey` | string | `''` | HMAC 密钥 |
| `sm2PrivateKey` | string | `''` | SM2 私钥 |
| `sm2PublicKey` | string | `''` | SM2 公钥 |
| `sm4Key` | string | `''` | SM4 密钥（16 字节） |
| `jwtSecretKey` | string | `''` | JWT 密钥 |
| `tokenSessionCheckLogin` | bool | `true` | TokenSession 是否校验登录 |
| `sso` | array | 见下方 | SSO 配置 |
| `oauth2` | array | 见下方 | OAuth2 配置 |

### SSO 配置

| 键名 | 默认值 | 说明 |
|------|--------|------|
| `loginUrl` | `''` | SSO 登录地址 |
| `authUrl` | `''` | 认证中心 URL |
| `backUrl` | `''` | 回调地址 |
| `checkTicketUrl` | `''` | Ticket 校验地址 |
| `sloUrl` | `''` | 单点注销地址 |
| `mode` | `'same-domain'` | SSO 模式 |
| `clientId` | `''` | Client ID |
| `clientSecret` | `''` | Client Secret |

### OAuth2 配置

| 键名 | 默认值 | 说明 |
|------|--------|------|
| `grantTypes` | `['authorization_code']` | 支持的授权模式 |
| `codeTimeout` | `60` | 授权码有效期（秒） |
| `accessTokenTimeout` | `7200` | Access Token 有效期（秒） |
| `refreshTokenTimeout` | `-1` | Refresh Token 有效期（秒），`-1` 不刷新 |
| `isNewRefreshToken` | `false` | 是否每次生成新 Refresh Token |

## 依赖

| 依赖 | 用途 |
|------|------|
| `firebase/php-jwt` | JWT Token 模式 |
| `predis/predis` | Redis 分布式会话存储（也可用 `ext-redis` 替代，性能更优） |
| `psr/simple-cache` | PSR-16 缓存适配 |
| `psr/http-message` | PSR-7 HTTP 消息接口 |
| `pohoc/crypto-sm` | 国密 SM2/SM3/SM4 算法 |

## 项目结构

```
src/
├── Action/                     # 业务行为接口
│   └── SaTokenActionInterface.php
├── Config/
│   └── SaTokenConfig.php       # 核心配置类
├── Dao/                        # 存储层
│   ├── SaTokenDaoInterface.php # DAO 接口
│   ├── SaTokenDaoMemory.php    # 内存存储
│   ├── SaTokenDaoRedis.php     # Redis 存储
│   └── SaTokenDaoPsr16.php     # PSR-16 适配
├── Exception/                  # 异常类
│   ├── SaTokenException.php
│   ├── NotLoginException.php
│   ├── NotPermissionException.php
│   ├── NotRoleException.php
│   ├── DisableServiceException.php
│   └── NotSafeException.php
├── Listener/                   # 事件监听
│   ├── SaTokenEvent.php
│   └── SaTokenListenerInterface.php
├── OAuth2/                     # OAuth2.0 模块
├── Sso/                        # SSO 单点登录模块
├── Util/                       # 工具类
├── SaLoginParameter.php        # 登录参数类
├── SaRouter.php                # 路由鉴权匹配器
├── SaSession.php               # 会话管理
├── SaTerminalInfo.php          # 终端信息
├── SaToken.php                 # 核心入口类
├── SaTokenInfo.php             # Token 信息
├── StpLogic.php                # 底层鉴权逻辑
├── StpUtil.php                 # 静态鉴权入口
└── TokenManager.php            # Token 管理器
```

## License

MIT
