<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Config\SaTokenConfig;
use SaToken\Exception\DisableServiceException;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotPermissionException;
use SaToken\Exception\NotRoleException;
use SaToken\Exception\NotSafeException;
use SaToken\Exception\SaTokenException;
use SaToken\Listener\SaTokenEvent;
use SaToken\Plugin\SaTokenJwt;
use SaToken\Security\SaAntiBruteUtil;
use SaToken\Util\SaFoxUtil;
use SaToken\Util\SaTokenContext;

/**
 * 底层鉴权逻辑实现
 *
 * StpUtil 的逻辑委托对象，管理多登录体系（多 type 实例）
 * 不同 type 拥有独立的登录态/Token/Session
 *
 * 使用示例：
 *   $logic = new StpLogic('admin');
 *   $logic->login(10001);
 *   $logic->checkLogin();
 */
class StpLogic
{
    /**
     * 登录类型标识
     */
    protected string $loginType;

    /**
     * Token 管理器
     */
    protected TokenManager $tokenManager;

    public function __construct(string $loginType = 'login', ?TokenManager $tokenManager = null)
    {
        $this->loginType = $loginType;
        $this->tokenManager = $tokenManager ?? new TokenManager();
    }

    public function setTokenManager(TokenManager $tokenManager): void
    {
        $this->tokenManager = $tokenManager;
    }

    public function getTokenManager(): TokenManager
    {
        return $this->tokenManager;
    }

    /**
     * 获取登录类型
     *
     * @return string
     */
    public function getLoginType(): string
    {
        return $this->loginType;
    }

    /**
     * 获取配置
     *
     * @return SaTokenConfig
     */
    protected function getConfig(): SaTokenConfig
    {
        return SaToken::getConfig();
    }

    /**
     * 获取事件分发器
     *
     * @return SaTokenEvent
     */
    protected function getEvent(): SaTokenEvent
    {
        return SaToken::getEvent();
    }

    /**
     * 登录
     *
     * @param  mixed                 $loginId   登录 ID
     * @param  SaLoginParameter|null $parameter 登录参数
     * @return string                Token 值
     * @throws SaTokenException
     */
    public function login(mixed $loginId, ?SaLoginParameter $parameter = null): string
    {
        $parameter = $parameter ?? new SaLoginParameter();
        $config = $this->getConfig();

        // 检查账号是否被封禁
        $this->checkDisableForLogin($loginId);

        $deviceType = $parameter->getDeviceType();
        $timeout = $parameter->getTimeout() ?? $config->getTimeout();
        $isShare = $parameter->getIsShare() ?? $config->isShare();
        $maxLoginCount = $parameter->getMaxLoginCount() ?? $config->getMaxLoginCount();

        // 判断是否复用已有 Token（isShare + 同设备类型）
        $tokenValue = null;
        if ($isShare && $config->isConcurrent()) {
            $tokenValue = $this->getTokenValueByDeviceType($loginId, $deviceType);
        }

        if (!$config->isConcurrent() && $isShare) {
            $this->logoutAllExceptCurrent($loginId, $deviceType);
        }

        // 无可复用 Token，则创建新 Token
        if ($tokenValue === null) {
            $tokenValue = $this->tokenManager->createTokenValue($loginId, $this->loginType);
        }

        // 并发登录控制：超过最大登录数时踢出最早的
        $this->controlMaxLoginCount($loginId, $deviceType, $maxLoginCount, $tokenValue);

        // 保存 Token
        $this->tokenManager->saveToken($tokenValue, $loginId, $this->loginType, $deviceType, $timeout);

        // 写入 Token 到响应
        $this->writeTokenToResponse($tokenValue, $parameter);

        // 触发登录事件
        $this->getEvent()->onLogin($this->loginType, $loginId, $tokenValue, $parameter);

        $this->clearAntiBruteFailures($loginId);

        return $tokenValue;
    }

    public function loginStateless(mixed $loginId, ?SaLoginParameter $parameter = null): string
    {
        $parameter = $parameter ?? new SaLoginParameter();
        $config = $this->getConfig();

        $this->checkDisableForLogin($loginId);

        $timeout = $parameter->getTimeout() ?? $config->getTimeout();

        $jwt = $this->getJwt();
        $tokenValue = $jwt->createStatelessToken($loginId, $this->loginType, $timeout);

        $this->writeTokenToResponse($tokenValue, $parameter);

        $this->getEvent()->onLogin($this->loginType, $loginId, $tokenValue, $parameter);

        return $tokenValue;
    }

    /**
     * 注销登录（当前 Token）
     *
     * @return void
     */
    public function logout(): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return;
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            return;
        }

        $this->tokenManager->deleteToken($tokenValue, $loginId, $this->loginType);
        $this->clearTokenFromResponse();

        $this->getEvent()->onLogout($this->loginType, $loginId, $tokenValue);
    }

    /**
     * 注销指定登录 ID 的所有会话
     *
     * @param  mixed $loginId 登录 ID
     * @return void
     */
    public function logoutByLoginId(mixed $loginId): void
    {
        $tokens = $this->tokenManager->deleteAllTokenByLoginId($loginId, $this->loginType);
        foreach ($tokens as $tokenValue) {
            $this->getEvent()->onLogout($this->loginType, $loginId, $tokenValue);
        }
    }

    /**
     * 踢人下线（指定 Token）
     *
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function kickoutByTokenValue(string $tokenValue): void
    {
        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            return;
        }

        $this->tokenManager->kickout($tokenValue, $loginId, $this->loginType);
        $this->getEvent()->onKickout($this->loginType, $loginId, $tokenValue);
    }

    /**
     * 踢人下线（指定登录 ID 的所有会话）
     *
     * @param  mixed $loginId 登录 ID
     * @return void
     */
    public function kickout(mixed $loginId): void
    {
        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        foreach ($tokens as $item) {
            $tokenValue = $item['tokenValue'];
            $this->tokenManager->kickout($tokenValue, $loginId, $this->loginType);
            $this->getEvent()->onKickout($this->loginType, $loginId, $tokenValue);
        }
    }

    /**
     * 检查是否已登录
     *
     * @return void
     * @throws NotLoginException 未登录时抛出
     */
    public function checkLogin(): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            throw new NotLoginException('未登录，请先登录', NotLoginException::NOT_LOGIN);
        }

        $config = $this->getConfig();

        if ($config->isJwtStateless()) {
            $jwt = $this->getJwt();
            $payload = $jwt->validateStatelessToken($tokenValue);
            if ($payload !== null) {
                return;
            }
            throw new NotLoginException('Token 已失效，请重新登录', NotLoginException::TOKEN_TIMEOUT);
        }

        if ($config->getJwtMode() === 'mixed') {
            $jwt = $this->getJwt();
            $payload = $jwt->validateStatelessToken($tokenValue);
            if ($payload !== null) {
                $jwtLoginId = $payload['sub'] ?? null;
                $daoLoginId = $this->tokenManager->getLoginIdByToken($tokenValue);
                if ($daoLoginId !== null && $jwtLoginId === $daoLoginId) {
                    $this->checkActivityTimeout($tokenValue);
                    $this->tokenManager->updateLastActiveToNow($tokenValue);
                    return;
                }
            }
            throw new NotLoginException('Token 已失效，请重新登录', NotLoginException::TOKEN_TIMEOUT);
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            throw new NotLoginException('Token 已失效，请重新登录', NotLoginException::TOKEN_TIMEOUT);
        }

        // 检查活动超时
        $this->checkActivityTimeout($tokenValue);

        // 更新最后活跃时间
        $this->tokenManager->updateLastActiveToNow($tokenValue);
    }

    /**
     * 是否已登录
     *
     * @return bool
     */
    public function isLogin(): bool
    {
        try {
            $this->checkLogin();
            return true;
        } catch (NotLoginException) {
            return false;
        }
    }

    /**
     * 获取当前登录 ID
     *
     * @return mixed 登录 ID，未登录返回 null
     */
    public function getLoginId(): mixed
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return null;
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            return null;
        }

        // 检查身份切换
        $switchTo = $this->tokenManager->getSwitchTo($tokenValue, $this->loginType);
        if ($switchTo !== null) {
            return $switchTo;
        }

        // 更新活跃时间
        try {
            $this->checkActivityTimeout($tokenValue);
            $this->tokenManager->updateLastActiveToNow($tokenValue);
        } catch (NotLoginException) {
            return null;
        }

        return $loginId;
    }

    /**
     * 获取当前登录 ID（必须已登录，否则抛出异常）
     *
     * @return mixed
     * @throws NotLoginException
     */
    public function getLoginIdAsNotNull(): mixed
    {
        $loginId = $this->getLoginId();
        if ($loginId === null) {
            throw new NotLoginException('未登录，请先登录', NotLoginException::NOT_LOGIN);
        }
        return $loginId;
    }

    /**
     * 获取当前 Token 值
     *
     * @return string|null
     */
    public function getTokenValue(): ?string
    {
        $config = $this->getConfig();
        $tokenName = $config->getTokenName();

        // 1. 从 Header 读取
        if ($config->isReadHeader()) {
            $tokenValue = SaTokenContext::getHeader($tokenName);
            if (SaFoxUtil::isNotEmpty($tokenValue)) {
                return $this->formatTokenValue($tokenValue);
            }
        }

        // 2. 从 Cookie 读取
        if ($config->isReadCookie()) {
            $tokenValue = SaTokenContext::getCookie($tokenName);
            if (SaFoxUtil::isNotEmpty($tokenValue)) {
                return $this->formatTokenValue($tokenValue);
            }
        }

        // 3. 从请求参数读取
        if ($config->isReadBody()) {
            $tokenValue = SaTokenContext::getParam($tokenName);
            if (SaFoxUtil::isNotEmpty($tokenValue)) {
                return $this->formatTokenValue($tokenValue);
            }
        }

        return null;
    }

    /**
     * 格式化 Token 值（去除前缀）
     *
     * @param  string $tokenValue 原始 Token 值
     * @return string
     */
    protected function formatTokenValue(string $tokenValue): string
    {
        $prefix = $this->getConfig()->getTokenPrefix();
        if ($prefix !== '' && str_starts_with($tokenValue, $prefix . ' ')) {
            return substr($tokenValue, strlen($prefix) + 1);
        }
        return $tokenValue;
    }

    public function getLoginIdByToken(string $tokenValue): ?string
    {
        return $this->tokenManager->getLoginIdByToken($tokenValue);
    }

    public function getTokenInfo(): SaTokenInfo
    {
        $tokenValue = $this->getTokenValue();
        $config = $this->getConfig();

        $info = new SaTokenInfo();
        $info->setTokenName($config->getTokenName())
            ->setTokenValue($tokenValue ?? '')
            ->setLoginType($this->loginType)
            ->setTimeout($tokenValue !== null ? $this->tokenManager->getTokenTimeout($tokenValue) : -2)
            ->setActivityTimeout($config->getActivityTimeout());

        if ($tokenValue !== null) {
            $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
            $info->setLoginId($loginId);
        }

        return $info;
    }

    /**
     * 校验权限
     *
     * @param  string                 $permission 权限码
     * @return void
     * @throws NotPermissionException 无权限时抛出
     */
    public function checkPermission(string $permission): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $permissionList = $this->getPermissionList($loginId);

        if (!SaFoxUtil::inArray($permissionList, $permission)) {
            throw new NotPermissionException($permission);
        }
    }

    /**
     * 校验权限（任一满足）
     *
     * @param  array<string>          $permissions 权限码列表
     * @return void
     * @throws NotPermissionException 全部不满足时抛出
     */
    public function checkPermissionOr(array $permissions): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $permissionList = $this->getPermissionList($loginId);

        foreach ($permissions as $permission) {
            if (SaFoxUtil::inArray($permissionList, $permission)) {
                return;
            }
        }
        throw new NotPermissionException(implode(',', $permissions));
    }

    /**
     * 校验权限（全部满足）
     *
     * @param  array<string>          $permissions 权限码列表
     * @return void
     * @throws NotPermissionException 任一不满足时抛出
     */
    public function checkPermissionAnd(array $permissions): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $permissionList = $this->getPermissionList($loginId);

        foreach ($permissions as $permission) {
            if (!SaFoxUtil::inArray($permissionList, $permission)) {
                throw new NotPermissionException($permission);
            }
        }
    }

    /**
     * 是否有指定权限
     *
     * @param  string $permission 权限码
     * @return bool
     */
    public function hasPermission(string $permission): bool
    {
        try {
            $this->checkPermission($permission);
            return true;
        } catch (NotPermissionException $e) {
            return false;
        } catch (NotLoginException $e) { // @phpstan-ignore catch.neverThrown
            return false;
        }
    }

    /**
     * 校验角色
     *
     * @param  string           $role 角色标识
     * @return void
     * @throws NotRoleException 无角色时抛出
     */
    public function checkRole(string $role): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $roleList = $this->getRoleList($loginId);

        if (!SaFoxUtil::inArray($roleList, $role)) {
            throw new NotRoleException($role);
        }
    }

    /**
     * 校验角色（任一满足）
     *
     * @param  array<string>    $roles 角色标识列表
     * @return void
     * @throws NotRoleException 全部不满足时抛出
     */
    public function checkRoleOr(array $roles): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $roleList = $this->getRoleList($loginId);

        foreach ($roles as $role) {
            if (SaFoxUtil::inArray($roleList, $role)) {
                return;
            }
        }
        throw new NotRoleException(implode(',', $roles));
    }

    /**
     * 校验角色（全部满足）
     *
     * @param  array<string>    $roles 角色标识列表
     * @return void
     * @throws NotRoleException 任一不满足时抛出
     */
    public function checkRoleAnd(array $roles): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        $roleList = $this->getRoleList($loginId);

        foreach ($roles as $role) {
            if (!SaFoxUtil::inArray($roleList, $role)) {
                throw new NotRoleException($role);
            }
        }
    }

    /**
     * 是否有指定角色
     *
     * @param  string $role 角色标识
     * @return bool
     */
    public function hasRole(string $role): bool
    {
        try {
            $this->checkRole($role);
            return true;
        } catch (NotRoleException $e) {
            return false;
        } catch (NotLoginException $e) { // @phpstan-ignore catch.neverThrown
            return false;
        }
    }

    /**
     * 获取权限列表
     *
     * @param  mixed         $loginId 登录 ID
     * @return array<string>
     */
    public function getPermissionList(mixed $loginId): array
    {
        $action = SaToken::getAction();
        if ($action === null) {
            return [];
        }
        return $action->getPermissionList($loginId, $this->loginType);
    }

    /**
     * 获取角色列表
     *
     * @param  mixed         $loginId 登录 ID
     * @return array<string>
     */
    public function getRoleList(mixed $loginId): array
    {
        $action = SaToken::getAction();
        if ($action === null) {
            return [];
        }
        return $action->getRoleList($loginId, $this->loginType);
    }

    /**
     * 获取当前会话
     *
     * @return SaSession
     */
    public function getSession(): SaSession
    {
        $loginId = $this->getLoginIdAsNotNull();
        return $this->getSessionByLoginId($loginId);
    }

    /**
     * 获取指定登录 ID 的会话
     *
     * @param  mixed          $loginId  登录 ID
     * @param  bool           $isCreate 不存在时是否创建
     * @return SaSession|null
     */
    public function getSessionByLoginId(mixed $loginId, bool $isCreate = true): ?SaSession
    {
        $sessionId = TokenManager::SESSION_PREFIX . $this->loginType . ':' . $loginId;
        $session = SaSession::getBySessionId($sessionId);

        if ($session === null && $isCreate) {
            $timeout = $this->getConfig()->getTimeout();
            $sessionTimeout = ($timeout > 0) ? $timeout : null;
            $session = new SaSession($sessionId, false, $sessionTimeout);
        }

        return $session;
    }

    /**
     * 获取当前 TokenSession
     *
     * @param  bool           $isCreate 不存在时是否创建
     * @return SaSession|null
     */
    public function getTokenSession(bool $isCreate = true): ?SaSession
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return null;
        }

        $sessionId = TokenManager::TOKEN_SESSION_PREFIX . $tokenValue;
        $session = SaSession::getBySessionId($sessionId);

        if ($session === null && $isCreate) {
            $timeout = $this->tokenManager->getTokenTimeout($tokenValue);
            $sessionTimeout = ($timeout > 0) ? $timeout : null;
            $session = new SaSession($sessionId, false, $sessionTimeout);
        }

        return $session;
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
    public function disable(mixed $loginId, string $service, int $level = 1, int $time = -1): void
    {
        $this->tokenManager->disable($loginId, $service, $level, $time, $this->loginType);
        $this->getEvent()->onBlock($this->loginType, $loginId, $service, $level, $time);
    }

    /**
     * 检查是否被封禁
     *
     * @param  mixed  $loginId 登录 ID
     * @param  string $service 封禁服务
     * @return bool
     */
    public function isDisable(mixed $loginId, string $service): bool
    {
        return $this->tokenManager->isDisable($loginId, $service, $this->loginType);
    }

    /**
     * 检查是否被封禁（抛出异常）
     *
     * @param  mixed                   $loginId 登录 ID
     * @param  string                  $service 封禁服务
     * @return void
     * @throws DisableServiceException
     */
    public function checkDisable(mixed $loginId, string $service): void
    {
        if ($this->isDisable($loginId, $service)) {
            $level = $this->tokenManager->getDisableLevel($loginId, $service, $this->loginType);
            $remainingTime = $this->tokenManager->getDisableTime($loginId, $service, $this->loginType);
            throw new DisableServiceException($service, $level, $remainingTime);
        }
    }

    /**
     * 获取封禁等级
     *
     * @param  mixed  $loginId 登录 ID
     * @param  string $service 封禁服务
     * @return int    封禁等级，-1 表示未封禁
     */
    public function getDisableLevel(mixed $loginId, string $service): int
    {
        return $this->tokenManager->getDisableLevel($loginId, $service, $this->loginType);
    }

    /**
     * 解除封禁
     *
     * @param  mixed  $loginId 登录 ID
     * @param  string $service 封禁服务
     * @return void
     */
    public function untieDisable(mixed $loginId, string $service): void
    {
        $this->tokenManager->untieDisable($loginId, $service, $this->loginType);
    }

    /**
     * 开启二级认证
     *
     * @param  int    $safeTime 安全窗口时间（秒）
     * @param  string $service  服务标识，默认 'default'
     * @return void
     */
    public function openSafe(int $safeTime, string $service = 'default'): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            throw new NotLoginException('未登录，请先登录', NotLoginException::NOT_LOGIN);
        }
        $this->tokenManager->openSafe($tokenValue, $service, $safeTime, $this->loginType);
    }

    /**
     * 检查二级认证
     *
     * @param  string           $service 服务标识，默认 'default'
     * @return void
     * @throws NotSafeException
     */
    public function checkSafe(string $service = 'default'): void
    {
        if (!$this->isSafe($service)) {
            throw new NotSafeException();
        }
    }

    /**
     * 是否在安全窗口内
     *
     * @param  string $service 服务标识，默认 'default'
     * @return bool
     */
    public function isSafe(string $service = 'default'): bool
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return false;
        }
        return $this->tokenManager->isSafe($tokenValue, $service, $this->loginType);
    }

    /**
     * 关闭二级认证
     *
     * @param  string $service 服务标识，默认 'default'
     * @return void
     */
    public function closeSafe(string $service = 'default'): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return;
        }
        $this->tokenManager->closeSafe($tokenValue, $service, $this->loginType);
    }

    /**
     * 临时身份切换
     *
     * @param  mixed $loginId 切换目标 ID
     * @return void
     */
    public function switchTo(mixed $loginId): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            throw new NotLoginException('未登录，请先登录', NotLoginException::NOT_LOGIN);
        }
        $currentLoginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($currentLoginId === null) {
            throw new NotLoginException('Token 已失效', NotLoginException::TOKEN_TIMEOUT);
        }

        $this->tokenManager->setSwitchTo($tokenValue, $loginId, $this->loginType);
        $this->getEvent()->onSwitch($this->loginType, $currentLoginId, $loginId, $tokenValue);
    }

    /**
     * 结束身份切换
     *
     * @return void
     */
    public function endSwitch(): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return;
        }
        $this->tokenManager->clearSwitch($tokenValue, $this->loginType);
        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId !== null) {
            $this->getEvent()->onSwitchBack($this->loginType, $loginId, $tokenValue);
        }
    }

    /**
     * 是否处于身份切换状态
     *
     * @return bool
     */
    public function isSwitch(): bool
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return false;
        }
        return $this->tokenManager->getSwitchTo($tokenValue, $this->loginType) !== null;
    }

    /**
     * 获取当前设备类型
     *
     * @return string
     */
    public function getLoginDeviceType(): string
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return '';
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            return '';
        }

        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        foreach ($tokens as $item) {
            if ($item['tokenValue'] === $tokenValue) {
                return $item['deviceType'];
            }
        }

        return '';
    }

    /**
     * 获取指定登录 ID 的所有终端信息
     *
     * @param  mixed                 $loginId 登录 ID
     * @return array<SaTerminalInfo>
     */
    public function getTerminalListByLoginId(mixed $loginId): array
    {
        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        $result = [];
        foreach ($tokens as $item) {
            $result[] = new SaTerminalInfo([
                'deviceType' => $item['deviceType'] ?? '',
                'tokenValue' => $item['tokenValue'] ?? '',
                'createTime' => $item['createTime'] ?? 0,
            ]);
        }
        return $result;
    }

    /**
     * 获取 Token 剩余超时时间
     *
     * @return int 剩余秒数，-2 表示不存在，-1 表示永不过期
     */
    public function getTokenTimeout(): int
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return -2;
        }
        return $this->tokenManager->getTokenTimeout($tokenValue);
    }

    /**
     * 续期当前 Token
     *
     * @param  int  $timeout 新的超时时间（秒）
     * @return void
     */
    public function renewTimeout(int $timeout): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return;
        }
        $this->tokenManager->renewTimeout($tokenValue, $timeout);
    }

    /**
     * 创建临时 Token
     *
     * @param  mixed  $loginId 关联的登录 ID
     * @param  int    $timeout 超时时间（秒）
     * @return string Token 值
     */
    public function createTempToken(mixed $loginId, int $timeout): string
    {
        $tokenValue = $this->tokenManager->createTokenValue($loginId, $this->loginType);
        $this->tokenManager->saveToken($tokenValue, $loginId, $this->loginType, 'temp', $timeout);
        return $tokenValue;
    }

    // ---- 内部辅助方法 ----

    protected function getJwt(): SaTokenJwt
    {
        $config = $this->getConfig();
        return new SaTokenJwt([
            'jwtSecretKey' => $config->getJwtSecretKey(),
            'cryptoType'   => $config->getCryptoType(),
        ]);
    }

    /**
     * 检查登录前的封禁状态
     *
     * @param  mixed                   $loginId 登录 ID
     * @return void
     * @throws DisableServiceException
     */
    protected function checkDisableForLogin(mixed $loginId): void
    {
        if ($this->isDisable($loginId, 'login')) {
            $level = $this->tokenManager->getDisableLevel($loginId, 'login', $this->loginType);
            $remainingTime = $this->tokenManager->getDisableTime($loginId, 'login', $this->loginType);
            throw new DisableServiceException('login', $level, $remainingTime);
        }
    }

    /**
     * 检查活动超时
     *
     * @param  string            $tokenValue Token 值
     * @return void
     * @throws NotLoginException
     */
    protected function checkActivityTimeout(string $tokenValue): void
    {
        $config = $this->getConfig();
        if ($config->getActivityTimeout() <= 0) {
            return;
        }

        $lastActive = $this->tokenManager->getLastActiveTime($tokenValue);
        if ($lastActive === null) {
            // 没有活跃时间记录，说明还没有更新过，此时不应该判定超时
            return;
        }

        if (SaFoxUtil::getTime() - $lastActive > $config->getActivityTimeout()) {
            throw new NotLoginException('Token 活动超时，请重新登录', NotLoginException::TOKEN_TIMEOUT);
        }
    }

    /**
     * 获取指定设备类型的 Token 值
     *
     * @param  mixed       $loginId    登录 ID
     * @param  string      $deviceType 设备类型
     * @return string|null
     */
    protected function getTokenValueByDeviceType(mixed $loginId, string $deviceType): ?string
    {
        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        foreach ($tokens as $item) {
            if ($item['deviceType'] === $deviceType && $this->tokenManager->isTokenValid($item['tokenValue'])) {
                return $item['tokenValue'];
            }
        }
        return null;
    }

    protected function logoutAllExceptCurrent(mixed $loginId, string $deviceType): void
    {
        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        foreach ($tokens as $item) {
            if ($item['deviceType'] === $deviceType && $this->tokenManager->isTokenValid($item['tokenValue'])) {
                $this->tokenManager->kickout($item['tokenValue'], $loginId, $this->loginType);
                $this->getEvent()->onReplaced($this->loginType, $loginId, $item['tokenValue']);
            }
        }
    }

    /**
     * 并发登录控制
     *
     * @param  mixed  $loginId           登录 ID
     * @param  string $deviceType        设备类型
     * @param  int    $maxLoginCount     最大登录数
     * @param  string $currentTokenValue 当前 Token 值
     * @return void
     */
    protected function controlMaxLoginCount(mixed $loginId, string $deviceType, int $maxLoginCount, string $currentTokenValue): void
    {
        if ($maxLoginCount < 0) {
            return;
        }

        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        $validTokens = array_filter($tokens, fn ($item) => $this->tokenManager->isTokenValid($item['tokenValue']));

        // 不包含当前新 Token，需要检查数量限制
        $currentExists = false;
        foreach ($validTokens as $item) {
            if ($item['tokenValue'] === $currentTokenValue) {
                $currentExists = true;
                break;
            }
        }

        if (!$currentExists && count($validTokens) >= $maxLoginCount) {
            // 循环踢出最早的 Token，直到数量低于限制
            $validTokens = array_values($validTokens);
            while (count($validTokens) >= $maxLoginCount) {
                $toKick = array_shift($validTokens);
                if ($toKick !== null) {
                    $this->tokenManager->kickout($toKick['tokenValue'], $loginId, $this->loginType);
                    $this->getEvent()->onReplaced($this->loginType, $loginId, $toKick['tokenValue']);
                }
            }
        }
    }

    /**
     * 将 Token 写入响应
     *
     * @param  string           $tokenValue Token 值
     * @param  SaLoginParameter $parameter  登录参数
     * @return void
     */
    protected function writeTokenToResponse(string $tokenValue, SaLoginParameter $parameter): void
    {
        $config = $this->getConfig();
        $tokenName = $config->getTokenName();
        $tokenPrefix = $config->getTokenPrefix();
        $fullTokenValue = $tokenPrefix !== '' ? $tokenPrefix . ' ' . $tokenValue : $tokenValue;

        // 写入 Cookie
        if ($config->isWriteCookie()) {
            $timeout = $parameter->isLastingCookie() ? ($parameter->getTimeout() ?? $config->getTimeout()) : null;
            $cookieTimeout = $timeout !== null && $timeout > 0 ? $timeout : 0;

            SaTokenContext::setCookie(
                $tokenName,
                $fullTokenValue,
                $cookieTimeout,
                $config->getCookiePath(),
                $config->getCookieDomain(),
                $config->isCookieSecure(),
                $config->isCookieHttpOnly(),
                $config->getCookieSameSite()
            );
        }

        // 写入响应头
        if ($config->isWriteHeader()) {
            SaTokenContext::setHeader($tokenName, $fullTokenValue);
        }
    }

    /**
     * 清除响应中的 Token
     *
     * @return void
     */
    protected function clearTokenFromResponse(): void
    {
        $config = $this->getConfig();
        $tokenName = $config->getTokenName();

        if ($config->isWriteCookie()) {
            SaTokenContext::setCookie(
                $tokenName,
                '',
                -1,
                $config->getCookiePath(),
                $config->getCookieDomain(),
                $config->isCookieSecure(),
                $config->isCookieHttpOnly(),
                $config->getCookieSameSite()
            );
        }
    }

    public function checkAntiBrute(string $account): void
    {
        $config = $this->getConfig();
        $maxFailures = $config->getAntiBruteMaxFailures();

        if ($maxFailures <= 0) {
            return;
        }

        SaAntiBruteUtil::checkAndThrow($account, $this->loginType);
    }

    public function recordAntiBruteFailure(string $account): void
    {
        $config = $this->getConfig();
        $maxFailures = $config->getAntiBruteMaxFailures();

        if ($maxFailures <= 0) {
            return;
        }

        SaAntiBruteUtil::recordFailure($account, $this->loginType);

        if (SaAntiBruteUtil::getFailCount($account, $this->loginType) >= $maxFailures) {
            $lockDuration = $config->getAntiBruteLockDuration();
            SaAntiBruteUtil::lock($account, $this->loginType, $lockDuration);
        }
    }

    protected function clearAntiBruteFailures(mixed $loginId): void
    {
        $config = $this->getConfig();
        if ($config->getAntiBruteMaxFailures() <= 0) {
            return;
        }

        SaAntiBruteUtil::clearFailures((string) $loginId, $this->loginType);
    }

    public function isAccountLocked(string $account): bool
    {
        return SaAntiBruteUtil::isAccountLocked($account, $this->loginType);
    }

    public function getRemainingLockTime(string $account): int
    {
        return SaAntiBruteUtil::getRemainingLockTime($account, $this->loginType);
    }

    public function unlockAccount(string $account): void
    {
        SaAntiBruteUtil::unlock($account, $this->loginType);
    }

    public function getAntiBruteInfo(string $account): array
    {
        return SaAntiBruteUtil::getSecurityInfo($account, $this->loginType);
    }
}
