<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Exception\NotLoginException;

/**
 * 核心鉴权入口（Facade 风格）
 *
 * 框架无关的静态调用入口，默认委托给 type='login' 的 StpLogic 实例
 * 提供一行代码完成登录鉴权的简洁 API
 *
 * 使用示例：
 *   StpUtil::login(10001);              // 登录
 *   StpUtil::checkLogin();              // 检查登录
 *   $id = StpUtil::getLoginId();        // 获取登录 ID
 *   StpUtil::checkPermission('user:add'); // 校验权限
 *   StpUtil::logout();                  // 注销
 */
class StpUtil
{
    /**
     * 默认登录类型
     */
    public const TYPE = 'login';

    /**
     * 获取当前 StpLogic 实例
     *
     * @return StpLogic
     */
    public static function getStpLogic(): StpLogic
    {
        return SaToken::getStpLogic(self::TYPE);
    }

    /**
     * 登录
     *
     * @param  mixed                 $loginId   登录 ID
     * @param  SaLoginParameter|null $parameter 登录参数
     * @return SaLoginResult         登录结果
     */
    public static function login(mixed $loginId, ?SaLoginParameter $parameter = null): SaLoginResult
    {
        return self::getStpLogic()->login($loginId, $parameter);
    }

    /**
     * 注销登录（当前 Token）
     *
     * @return void
     */
    public static function logout(): void
    {
        self::getStpLogic()->logout();
    }

    /**
     * 注销指定登录 ID 的所有会话
     *
     * @param  mixed $loginId 登录 ID
     * @return void
     */
    public static function logoutByLoginId(mixed $loginId): void
    {
        self::getStpLogic()->logoutByLoginId($loginId);
    }

    /**
     * 踢人下线（指定 Token）
     *
     * @param  string $tokenValue Token 值
     * @return void
     */
    public static function kickoutByTokenValue(string $tokenValue): void
    {
        self::getStpLogic()->kickoutByTokenValue($tokenValue);
    }

    /**
     * 踢人下线（指定登录 ID 的所有会话）
     *
     * @param  mixed $loginId 登录 ID
     * @return void
     */
    public static function kickout(mixed $loginId): void
    {
        self::getStpLogic()->kickout($loginId);
    }

    /**
     * 检查是否已登录
     *
     * @return void
     * @throws NotLoginException
     */
    public static function checkLogin(): void
    {
        self::getStpLogic()->checkLogin();
    }

    /**
     * 是否已登录
     *
     * @return bool
     */
    public static function isLogin(): bool
    {
        return self::getStpLogic()->isLogin();
    }

    /**
     * 获取当前登录 ID
     *
     * @return mixed 未登录返回 null
     */
    public static function getLoginId(): mixed
    {
        return self::getStpLogic()->getLoginId();
    }

    /**
     * 获取当前登录 ID（必须已登录）
     *
     * @return mixed
     * @throws NotLoginException
     */
    public static function getLoginIdAsNotNull(): mixed
    {
        return self::getStpLogic()->getLoginIdAsNotNull();
    }

    /**
     * 获取当前 Token 值
     *
     * @return string|null
     */
    public static function getTokenValue(): ?string
    {
        return self::getStpLogic()->getTokenValue();
    }

    /**
     * 获取 Token 信息
     *
     * @return SaTokenInfo
     */
    public static function getTokenInfo(): SaTokenInfo
    {
        return self::getStpLogic()->getTokenInfo();
    }

    /**
     * 校验权限
     *
     * @param  string $permission 权限码
     * @return void
     */
    public static function checkPermission(string $permission): void
    {
        self::getStpLogic()->checkPermission($permission);
    }

    /**
     * 校验权限（任一满足）
     *
     * @param  array<string> $permissions 权限码列表
     * @return void
     */
    public static function checkPermissionOr(array $permissions): void
    {
        self::getStpLogic()->checkPermissionOr($permissions);
    }

    /**
     * 校验权限（全部满足）
     *
     * @param  array<string> $permissions 权限码列表
     * @return void
     */
    public static function checkPermissionAnd(array $permissions): void
    {
        self::getStpLogic()->checkPermissionAnd($permissions);
    }

    /**
     * 是否有指定权限
     *
     * @param  string $permission 权限码
     * @return bool
     */
    public static function hasPermission(string $permission): bool
    {
        return self::getStpLogic()->hasPermission($permission);
    }

    /**
     * 校验角色
     *
     * @param  string $role 角色标识
     * @return void
     */
    public static function checkRole(string $role): void
    {
        self::getStpLogic()->checkRole($role);
    }

    /**
     * 校验角色（任一满足）
     *
     * @param  array<string> $roles 角色标识列表
     * @return void
     */
    public static function checkRoleOr(array $roles): void
    {
        self::getStpLogic()->checkRoleOr($roles);
    }

    /**
     * 校验角色（全部满足）
     *
     * @param  array<string> $roles 角色标识列表
     * @return void
     */
    public static function checkRoleAnd(array $roles): void
    {
        self::getStpLogic()->checkRoleAnd($roles);
    }

    /**
     * 是否有指定角色
     *
     * @param  string $role 角色标识
     * @return bool
     */
    public static function hasRole(string $role): bool
    {
        return self::getStpLogic()->hasRole($role);
    }

    /**
     * 获取权限列表
     *
     * @param  mixed         $loginId 登录 ID
     * @return array<string>
     */
    public static function getPermissionList(mixed $loginId): array
    {
        return self::getStpLogic()->getPermissionList($loginId);
    }

    /**
     * 获取角色列表
     *
     * @param  mixed         $loginId 登录 ID
     * @return array<string>
     */
    public static function getRoleList(mixed $loginId): array
    {
        return self::getStpLogic()->getRoleList($loginId);
    }

    /**
     * 获取当前会话
     *
     * @return SaSession
     */
    public static function getSession(): SaSession
    {
        return self::getStpLogic()->getSession();
    }

    /**
     * 获取指定登录 ID 的会话
     *
     * @param  mixed          $loginId  登录 ID
     * @param  bool           $isCreate 不存在时是否创建
     * @return SaSession|null
     */
    public static function getSessionByLoginId(mixed $loginId, bool $isCreate = true): ?SaSession
    {
        return self::getStpLogic()->getSessionByLoginId($loginId, $isCreate);
    }

    /**
     * 获取当前 TokenSession
     *
     * @param  bool           $isCreate 不存在时是否创建
     * @return SaSession|null
     */
    public static function getTokenSession(bool $isCreate = true): ?SaSession
    {
        return self::getStpLogic()->getTokenSession($isCreate);
    }

    /**
     * 封禁账号
     *
     * @param  mixed  $loginId 登录 ID
     * @param  string $service 封禁服务
     * @param  int    $level   封禁等级
     * @param  int    $time    封禁时长（秒）
     * @return void
     */
    public static function disable(mixed $loginId, string $service, int $level = 1, int $time = -1): void
    {
        self::getStpLogic()->disable($loginId, $service, $level, $time);
    }

    /**
     * 检查是否被封禁
     *
     * @param  mixed  $loginId 登录 ID
     * @param  string $service 封禁服务
     * @return bool
     */
    public static function isDisable(mixed $loginId, string $service): bool
    {
        return self::getStpLogic()->isDisable($loginId, $service);
    }

    /**
     * 检查是否被封禁（抛出异常）
     *
     * @param  mixed  $loginId 登录 ID
     * @param  string $service 封禁服务
     * @return void
     */
    public static function checkDisable(mixed $loginId, string $service): void
    {
        self::getStpLogic()->checkDisable($loginId, $service);
    }

    /**
     * 获取封禁等级
     *
     * @param  mixed  $loginId 登录 ID
     * @param  string $service 封禁服务
     * @return int
     */
    public static function getDisableLevel(mixed $loginId, string $service): int
    {
        return self::getStpLogic()->getDisableLevel($loginId, $service);
    }

    /**
     * 解除封禁
     *
     * @param  mixed  $loginId 登录 ID
     * @param  string $service 封禁服务
     * @return void
     */
    public static function untieDisable(mixed $loginId, string $service): void
    {
        self::getStpLogic()->untieDisable($loginId, $service);
    }

    /**
     * 开启二级认证
     *
     * @param  int    $safeTime 安全窗口时间（秒）
     * @param  string $service  服务标识
     * @return void
     */
    public static function openSafe(int $safeTime, string $service = 'default'): void
    {
        self::getStpLogic()->openSafe($safeTime, $service);
    }

    /**
     * 检查二级认证
     *
     * @param  string $service 服务标识
     * @return void
     */
    public static function checkSafe(string $service = 'default'): void
    {
        self::getStpLogic()->checkSafe($service);
    }

    /**
     * 是否在安全窗口内
     *
     * @param  string $service 服务标识
     * @return bool
     */
    public static function isSafe(string $service = 'default'): bool
    {
        return self::getStpLogic()->isSafe($service);
    }

    /**
     * 关闭二级认证
     *
     * @param  string $service 服务标识
     * @return void
     */
    public static function closeSafe(string $service = 'default'): void
    {
        self::getStpLogic()->closeSafe($service);
    }

    /**
     * 临时身份切换
     *
     * @param  mixed $loginId 切换目标 ID
     * @return void
     */
    public static function switchTo(mixed $loginId): void
    {
        self::getStpLogic()->switchTo($loginId);
    }

    /**
     * 结束身份切换
     *
     * @return void
     */
    public static function endSwitch(): void
    {
        self::getStpLogic()->endSwitch();
    }

    /**
     * 是否处于身份切换状态
     *
     * @return bool
     */
    public static function isSwitch(): bool
    {
        return self::getStpLogic()->isSwitch();
    }

    /**
     * 获取当前设备类型
     *
     * @return string
     */
    public static function getLoginDeviceType(): string
    {
        return self::getStpLogic()->getLoginDeviceType();
    }

    /**
     * 获取指定登录 ID 的所有终端信息
     *
     * @param  mixed                 $loginId 登录 ID
     * @return array<SaTerminalInfo>
     */
    public static function getTerminalListByLoginId(mixed $loginId): array
    {
        return self::getStpLogic()->getTerminalListByLoginId($loginId);
    }

    /**
     * 获取 Token 剩余超时时间
     *
     * @return int
     */
    public static function getTokenTimeout(): int
    {
        return self::getStpLogic()->getTokenTimeout();
    }

    /**
     * 续期当前 Token
     *
     * @param  int  $timeout 新的超时时间（秒）
     * @return void
     */
    public static function renewTimeout(int $timeout): void
    {
        self::getStpLogic()->renewTimeout($timeout);
    }

    /**
     * 创建临时 Token
     *
     * @param  mixed  $loginId 关联的登录 ID
     * @param  int    $timeout 超时时间（秒）
     * @return string
     */
    public static function createTempToken(mixed $loginId, int $timeout): string
    {
        return self::getStpLogic()->createTempToken($loginId, $timeout);
    }

    public static function createRefreshToken(string $accessToken, ?int $timeout = null): string
    {
        return self::getStpLogic()->createRefreshToken($accessToken, $timeout);
    }

    public static function refreshToken(string $refreshToken): SaLoginResult
    {
        return self::getStpLogic()->refreshToken($refreshToken);
    }

    public static function revokeRefreshToken(string $refreshToken): bool
    {
        return self::getStpLogic()->revokeRefreshToken($refreshToken);
    }

    public static function revokeRefreshTokenByAccessToken(string $accessToken): bool
    {
        return self::getStpLogic()->revokeRefreshTokenByAccessToken($accessToken);
    }

    public static function isRefreshTokenValid(string $refreshToken): bool
    {
        return self::getStpLogic()->isRefreshTokenValid($refreshToken);
    }

    public static function getRefreshTokenByAccessToken(string $accessToken): ?string
    {
        return self::getStpLogic()->getRefreshTokenByAccessToken($accessToken);
    }

    public static function revokeToken(string $tokenValue): bool
    {
        return self::getStpLogic()->revokeToken($tokenValue);
    }

    public static function isTokenRevoked(string $tokenValue): bool
    {
        return self::getStpLogic()->isTokenRevoked($tokenValue);
    }
}
