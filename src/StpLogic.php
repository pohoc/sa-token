<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Config\SaTokenConfig;
use SaToken\Exception\DisableServiceException;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\SaTokenException;
use SaToken\Listener\SaTokenEvent;
use SaToken\Plugin\SaTokenJwt;
use SaToken\Security\SaLoginDeviceManager;
use SaToken\Util\SaFoxUtil;
use SaToken\Util\SaTokenContext;

class StpLogic
{
    use StpLogicPermissionTrait;
    use StpLogicSessionTrait;
    use StpLogicSecurityTrait;
    use StpLogicRefreshTokenTrait;
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
     * @return SaLoginResult         登录结果
     * @throws SaTokenException
     */
    public function login(mixed $loginId, ?SaLoginParameter $parameter = null): SaLoginResult
    {
        // loginId 必须是非空标量：null/数组等会被静默归一为空串，
        // 使所有此类"用户"共享同一会话与 loginId 映射键
        if ($loginId === null || $loginId === '' || $loginId === [] || is_bool($loginId)) {
            throw new SaTokenException('loginId 不能为空且不能是布尔值');
        }
        if (!is_scalar($loginId)) {
            throw new SaTokenException('loginId 必须是标量类型');
        }

        $parameter = $parameter ?? new SaLoginParameter();
        $config = $this->getConfig();

        $this->checkDisableForLogin($loginId);

        $deviceType = $parameter->getDeviceType();
        $timeout = $parameter->getTimeout() ?? $config->getTimeout();
        $isShare = $parameter->getIsShare() ?? $config->isShare();
        $maxLoginCount = $parameter->getMaxLoginCount() ?? $config->getMaxLoginCount();

        // 并发登录互斥锁：获取失败说明同账号正在处理登录，直接拒绝以保证 maxLoginCount 等控制的一致性
        $loginIdStr = (string) $loginId;
        $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->tokenManager->acquireLock($lockKey, 5)) {
            throw new SaTokenException('同账号登录正在处理中，请勿重复提交');
        }

        try {
            $tokenValue = $this->resolveTokenValue($loginId, $deviceType, $isShare, $config);

            $this->controlMaxLoginCount($loginId, $deviceType, $maxLoginCount, $tokenValue);

            // mixed 模式下实际存储的是 JWT，后续指纹/响应/结果必须使用返回的真实值
            $tokenValue = $this->tokenManager->saveToken($tokenValue, $loginId, $this->loginType, $deviceType, $timeout);

            if ($config->isTokenFingerprint()) {
                $fingerprint = $this->tokenManager->computeFingerprint();
                $this->tokenManager->saveFingerprint($tokenValue, $fingerprint, $timeout);
            }

            $this->writeTokenToResponse($tokenValue, $parameter);

            $this->getEvent()->onLogin($this->loginType, $loginId, $tokenValue, $parameter);

            $this->clearAntiBruteFailures($loginId);

            if ($config->isDeviceManagement()) {
                $this->registerLoginDevice($loginId, $deviceType, $parameter, $tokenValue);
            }

            $result = $this->buildLoginResult($tokenValue, $timeout, $loginId, $config);
        } finally {
            $this->tokenManager->releaseLock($lockKey);
        }

        return $result;
    }

    protected function resolveTokenValue(mixed $loginId, string $deviceType, bool $isShare, SaTokenConfig $config): string
    {
        $tokenValue = null;
        if ($isShare && $config->isConcurrent()) {
            $existingToken = $this->getTokenValueByDeviceType($loginId, $deviceType);
            if ($existingToken !== null) {
                $this->removeTokenAndRefreshToken($existingToken, $loginId);
            }
        }

        if (!$config->isConcurrent() && $isShare) {
            $this->logoutAllExceptCurrent($loginId, $deviceType);
        }

        $tokenValue = $this->tokenManager->createTokenValue($loginId, $this->loginType);

        return $tokenValue;
    }

    protected function registerLoginDevice(mixed $loginId, string $deviceType, SaLoginParameter $parameter, string $tokenValue): void
    {
        $device = $parameter->getDevice();
        if ($device !== null) {
            $device->setDeviceType($deviceType !== '' ? $deviceType : $device->getDeviceType());
        }
        SaLoginDeviceManager::registerDevice($loginId, $this->loginType, $device, $tokenValue);
    }

    protected function buildLoginResult(string $tokenValue, int $timeout, mixed $loginId, SaTokenConfig $config): SaLoginResult
    {
        $result = (new SaLoginResult())
            ->setAccessToken($tokenValue)
            ->setAccessExpire($timeout > 0 ? $timeout : 0);

        if ($config->isRefreshToken()) {
            $refreshTokenValue = $this->tokenManager->createTokenValue($loginId, $this->loginType, 'srt_');
            $refreshTimeout = $config->getRefreshTokenTimeout();
            $this->tokenManager->saveRefreshToken($refreshTokenValue, $tokenValue, $loginId, $this->loginType, $refreshTimeout);
            SaTokenContext::setHeader('satoken-refresh', $refreshTokenValue);
            $result->setRefreshToken($refreshTokenValue)
                ->setRefreshExpire($refreshTimeout > 0 ? $refreshTimeout : 0);
        }

        return $result;
    }

    public function loginStateless(mixed $loginId, ?SaLoginParameter $parameter = null): string
    {
        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }

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

        if ($this->getConfig()->isJwtStateless()) {
            $loginId = $this->getStatelessLoginIdByToken($tokenValue);
            if ($loginId === null || !$this->revokeToken($tokenValue)) {
                return;
            }
            $this->clearTokenFromResponse();
            $this->getEvent()->onLogout($this->loginType, $loginId, $tokenValue);
            return;
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            return;
        }

        $this->tokenManager->deleteFingerprint($tokenValue);
        $this->removeTokenAndRefreshToken($tokenValue, $loginId);
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
        if ($this->getConfig()->isJwtStateless()) {
            $this->revokeStatelessTokensByLoginId($loginId);
            return;
        }

        $tokens = $this->tokenManager->deleteAllTokenByLoginId($loginId, $this->loginType);
        foreach ($tokens as $tokenValue) {
            $this->tokenManager->deleteRefreshTokenByAccessToken($loginId, $this->loginType, $tokenValue);
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
        if ($this->getConfig()->isJwtStateless()) {
            $loginId = $this->getStatelessLoginIdByToken($tokenValue);
            if ($loginId === null || !$this->revokeToken($tokenValue)) {
                return;
            }
            $this->getEvent()->onKickout($this->loginType, $loginId, $tokenValue);
            return;
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            return;
        }

        $this->removeTokenAndRefreshToken($tokenValue, $loginId);
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
        if ($this->getConfig()->isJwtStateless()) {
            $this->revokeStatelessTokensByLoginId($loginId);
            return;
        }

        // 账号级原子批量删除同时清理关联 RefreshToken，并与并发登录互斥。
        $tokens = $this->tokenManager->deleteAllTokenByLoginId($loginId, $this->loginType);
        foreach ($tokens as $tokenValue) {
            $this->getEvent()->onKickout($this->loginType, $loginId, $tokenValue);
        }
    }

    /** 删除会话时一并撤销其 RefreshToken，避免旧凭据重新建立会话。 */
    protected function removeTokenAndRefreshToken(string $tokenValue, mixed $loginId): void
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->tokenManager->acquireLock($lockKey, 5)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            $this->tokenManager->deleteRefreshTokenByAccessToken($loginId, $this->loginType, $tokenValue);
            // kickout 内部重复获取账号锁是安全的（TokenManager 锁支持可重入）。
            $this->tokenManager->kickout($tokenValue, $loginId, $this->loginType);
        } finally {
            $this->tokenManager->releaseLock($lockKey);
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

        // 被吊销（拉黑）的 Token 在任何模式下都立即失效
        if ($this->tokenManager->isBlacklisted($tokenValue)) {
            throw new NotLoginException('Token 已被撤销，请重新登录', NotLoginException::TOKEN_TIMEOUT);
        }

        if ($config->isJwtStateless()) {
            if ($this->getStatelessLoginIdByToken($tokenValue) !== null) {
                return;
            }
            throw new NotLoginException('Token 已失效，请重新登录', NotLoginException::TOKEN_TIMEOUT);
        }

        if ($config->getJwtMode() === 'mixed') {
            // mixed 模式先验 JWT 签名，再走与普通模式一致的 Dao 校验（Dao 为会话权威）
            $jwt = $this->getJwt();
            if ($jwt->validateStatelessToken($tokenValue) === null) {
                throw new NotLoginException('Token 已失效，请重新登录', NotLoginException::TOKEN_TIMEOUT);
            }
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null || !$this->isTokenOwnedByLoginType($tokenValue, $loginId)) {
            throw new NotLoginException('Token 已失效，请重新登录', NotLoginException::TOKEN_TIMEOUT);
        }

        $this->checkFingerprint($tokenValue);

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

        // 被吊销（拉黑）的 Token 不产生有效身份，保证 checkPermission/checkRole 等下游校验一致失效
        if ($this->tokenManager->isBlacklisted($tokenValue)) {
            return null;
        }

        if ($this->getConfig()->isJwtStateless()) {
            return $this->getStatelessLoginIdByToken($tokenValue);
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null || !$this->isTokenOwnedByLoginType($tokenValue, $loginId)) {
            return null;
        }

        // 所有以登录 ID 为入口的授权检查都必须执行完整的会话约束。
        // 先验证指纹与活动超时，再读取身份切换值，避免切换分支绕过约束。
        try {
            $this->checkFingerprint($tokenValue);
            $this->checkActivityTimeout($tokenValue);
            $this->tokenManager->updateLastActiveToNow($tokenValue);
        } catch (NotLoginException) {
            return null;
        }

        // 检查身份切换
        $switchTo = $this->tokenManager->getSwitchTo($tokenValue, $this->loginType);
        if ($switchTo !== null) {
            return $switchTo;
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
            if ($tokenValue !== null && SaFoxUtil::isNotEmpty($tokenValue)) {
                return $this->formatTokenValue($tokenValue);
            }
        }

        // 2. 从 Cookie 读取
        if ($config->isReadCookie()) {
            $tokenValue = SaTokenContext::getCookie($tokenName);
            if ($tokenValue !== null && SaFoxUtil::isNotEmpty($tokenValue)) {
                return $this->formatTokenValue($tokenValue);
            }
        }

        // 3. 从请求参数读取
        if ($config->isReadBody()) {
            $tokenValue = SaTokenContext::getParam($tokenName);
            if ($tokenValue !== null && SaFoxUtil::isNotEmpty($tokenValue)) {
                $contentType = SaTokenContext::getHeader('Content-Type');
                if ($contentType !== null
                    && !str_contains($contentType, 'application/json')) {
                    trigger_error('Sa-Token: 从 URL 参数读取 Token 存在安全风险，建议使用 Header 或 Cookie 传递', E_USER_NOTICE);
                }
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
        if ($this->tokenManager->isBlacklisted($tokenValue)) {
            return null;
        }

        if ($this->getConfig()->isJwtStateless()) {
            return $this->getStatelessLoginIdByToken($tokenValue);
        }

        if ($this->getConfig()->getJwtMode() === 'mixed'
            && $this->getJwt()->validateStatelessToken($tokenValue) === null) {
            return null;
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null || !$this->isTokenOwnedByLoginType($tokenValue, $loginId)) {
            return null;
        }

        try {
            $this->checkFingerprint($tokenValue);
            $this->checkActivityTimeout($tokenValue);
            $this->tokenManager->updateLastActiveToNow($tokenValue);
        } catch (NotLoginException) {
            return null;
        }

        return $loginId;
    }

    /**
     * 无状态 JWT 的身份来源是已验签的 sub，且必须属于当前 loginType。
     */
    protected function getStatelessLoginIdByToken(string $tokenValue): ?string
    {
        $payload = $this->getJwt()->validateStatelessToken($tokenValue);
        if ($payload === null) {
            return null;
        }

        $subject = $payload['sub'] ?? null;
        $type = $payload['type'] ?? null;
        if (!is_string($subject) || $subject === '' || !is_string($type) || $type !== $this->loginType) {
            return null;
        }

        if ($this->tokenManager->isStatelessTokenRevokedByLoginId(
            $subject,
            $this->loginType,
            $payload['iat'] ?? null
        )) {
            return null;
        }

        return $subject;
    }

    /**
     * 无状态 JWT 无法通过会话列表枚举，因此用账号级 iat 水位一次性吊销该账号的旧令牌。
     */
    protected function revokeStatelessTokensByLoginId(mixed $loginId): void
    {
        if ($loginId === null || is_bool($loginId) || !is_scalar($loginId) || $loginId === '') {
            return;
        }

        $this->tokenManager->revokeStatelessTokensByLoginId((string) $loginId, $this->loginType);
    }

    /**
     * 校验 Token 确实登记在当前 loginType 的会话列表中。
     *
     * Token 主键（satoken:login:token:{token}）不含 loginType——多账号体系
     * （member/user/admin 等）共享同一键空间，若不做归属校验，
     * 低权限类型的 Token 可在其他体系及 RPC 透传通道中冒用（横向越权）
     */
    protected function isTokenOwnedByLoginType(string $tokenValue, string $loginId): bool
    {
        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        foreach ($tokens as $item) {
            if (is_string($item['tokenValue'] ?? null) && $item['tokenValue'] === $tokenValue) {
                return true;
            }
        }
        return false;
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
            // TokenInfo is also an authentication-facing API: resolve identity through
            // the same blacklist, JWT, loginType, fingerprint, and activity checks as
            // getLoginIdByToken instead of trusting the shared DAO token key directly.
            $loginId = $this->getLoginIdByToken($tokenValue);
            $info->setLoginId($loginId);
        }

        return $info;
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
        // mixed 模式下实际存储的是 JWT，必须返回真实值
        return $this->tokenManager->saveToken($tokenValue, $loginId, $this->loginType, 'temp', $timeout);
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
            return;
        }

        if (SaFoxUtil::getTime() - $lastActive > $config->getActivityTimeout()) {
            throw new NotLoginException('Token 活动超时，请重新登录', NotLoginException::TOKEN_TIMEOUT);
        }
    }

    protected function checkFingerprint(string $tokenValue): void
    {
        $config = $this->getConfig();
        if (!$config->isTokenFingerprint()) {
            return;
        }

        $savedFingerprint = $this->tokenManager->getFingerprint($tokenValue);
        if ($savedFingerprint === null) {
            return;
        }

        $currentFingerprint = $this->tokenManager->computeFingerprint();
        if (!hash_equals($savedFingerprint, $currentFingerprint)) {
            throw new NotLoginException('Token 环境指纹不匹配，请重新登录', NotLoginException::TOKEN_TIMEOUT);
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
            $itemDeviceType = is_string($item['deviceType'] ?? null) ? $item['deviceType'] : '';
            $itemTokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            if ($itemDeviceType === $deviceType && $this->tokenManager->isTokenValid($itemTokenValue)) {
                return $itemTokenValue;
            }
        }
        return null;
    }

    protected function logoutAllExceptCurrent(mixed $loginId, string $deviceType): void
    {
        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        foreach ($tokens as $item) {
            $itemDeviceType = is_string($item['deviceType'] ?? null) ? $item['deviceType'] : '';
            $itemTokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            if ($itemDeviceType === $deviceType && $this->tokenManager->isTokenValid($itemTokenValue)) {
                $this->removeTokenAndRefreshToken($itemTokenValue, $loginId);
                $this->getEvent()->onReplaced($this->loginType, $loginId, $itemTokenValue);
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
        $validTokens = array_filter($tokens, fn ($item) => is_string($item['tokenValue'] ?? null) && $this->tokenManager->isTokenValid($item['tokenValue']));

        // 不包含当前新 Token，需要检查数量限制
        $currentExists = false;
        foreach ($validTokens as $item) {
            if ($item['tokenValue'] === $currentTokenValue) {
                $currentExists = true;
                break;
            }
        }

        if (!$currentExists && count($validTokens) >= $maxLoginCount) {
            $validTokens = array_values($validTokens);
            while (count($validTokens) >= $maxLoginCount) {
                $toKick = array_shift($validTokens);
                if ($toKick !== null) {
                    $kickTokenValue = is_string($toKick['tokenValue'] ?? null) ? $toKick['tokenValue'] : '';
                    if ($kickTokenValue !== '') {
                        $this->removeTokenAndRefreshToken($kickTokenValue, $loginId);
                        $this->getEvent()->onReplaced($this->loginType, $loginId, $kickTokenValue);
                    }
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

    public function revokeToken(string $tokenValue): bool
    {
        if ($this->tokenManager->isBlacklisted($tokenValue)) {
            return true;
        }

        $daoTimeout = $this->tokenManager->getTokenTimeout($tokenValue);
        $blacklistTimeout = null;

        // Stateless JWT 的签名与 loginType 是撤销资格的依据。未知或伪造值不能写入
        // 黑名单，否则攻击者可用任意输入持续占用存储。无 exp 的有效 JWT 永不过期。
        if ($this->getConfig()->isJwtStateless()) {
            if ($this->getStatelessLoginIdByToken($tokenValue) === null) {
                return false;
            }
            $payload = $this->getJwt()->validateStatelessToken($tokenValue);
            if ($payload !== null && isset($payload['exp']) && is_int($payload['exp'])) {
                $blacklistTimeout = max(1, $payload['exp'] - time());
            }
        } elseif ($daoTimeout === -1 || $daoTimeout > 0) {
            $blacklistTimeout = $daoTimeout === -1 ? null : $daoTimeout;
        } else {
            return false;
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId !== null) {
            $loginIdStr = $loginId;
            $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', $loginIdStr);
            if (!$this->tokenManager->acquireLock($lockKey, 5)) {
                throw new SaTokenException('同账号会话正在处理中，请稍后重试');
            }
            try {
                $this->tokenManager->addToBlacklist($tokenValue, $blacklistTimeout);
                // 锁内清理 RefreshToken 与会话记录，和并发刷新形成线性顺序。
                $this->removeTokenAndRefreshToken($tokenValue, $loginId);
            } finally {
                $this->tokenManager->releaseLock($lockKey);
            }
        } else {
            $this->tokenManager->addToBlacklist($tokenValue, $blacklistTimeout);
        }
        return true;
    }

    public function isTokenRevoked(string $tokenValue): bool
    {
        return $this->tokenManager->isBlacklisted($tokenValue);
    }

}
