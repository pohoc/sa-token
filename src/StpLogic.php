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
        $parameter = $parameter ?? new SaLoginParameter();
        $config = $this->getConfig();

        $this->checkDisableForLogin($loginId);

        $deviceType = $parameter->getDeviceType();
        $timeout = $parameter->getTimeout() ?? $config->getTimeout();
        $isShare = $parameter->getIsShare() ?? $config->isShare();
        $maxLoginCount = $parameter->getMaxLoginCount() ?? $config->getMaxLoginCount();

        $lockKey = 'satoken:lock:login:' . $this->loginType . ':' . (is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : ''));
        $lockAcquired = $this->tokenManager->acquireLock($lockKey, 5);

        try {
            $tokenValue = $this->resolveTokenValue($loginId, $deviceType, $isShare, $config);

            $this->controlMaxLoginCount($loginId, $deviceType, $maxLoginCount, $tokenValue);

            $this->tokenManager->saveToken($tokenValue, $loginId, $this->loginType, $deviceType, $timeout);

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
            if ($lockAcquired) {
                $this->tokenManager->releaseLock($lockKey);
            }
        }

        return $result;
    }

    protected function resolveTokenValue(mixed $loginId, string $deviceType, bool $isShare, SaTokenConfig $config): string
    {
        $tokenValue = null;
        if ($isShare && $config->isConcurrent()) {
            $existingToken = $this->getTokenValueByDeviceType($loginId, $deviceType);
            if ($existingToken !== null) {
                $this->tokenManager->deleteToken($existingToken, $loginId, $this->loginType);
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

        $this->tokenManager->deleteRefreshTokenByAccessToken($loginId, $this->loginType, $tokenValue);
        $this->tokenManager->deleteFingerprint($tokenValue);
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
            $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            if ($tokenValue === '') {
                continue;
            }
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

        if ($this->tokenManager->isBlacklisted($tokenValue)) {
            throw new NotLoginException('Token 已被撤销，请重新登录', NotLoginException::TOKEN_TIMEOUT);
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
                $this->tokenManager->kickout($itemTokenValue, $loginId, $this->loginType);
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
                        $this->tokenManager->kickout($kickTokenValue, $loginId, $this->loginType);
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
        $timeout = $this->tokenManager->getTokenTimeout($tokenValue);
        if ($timeout <= 0) {
            $timeout = $this->getConfig()->getTimeout();
        }
        $this->tokenManager->addToBlacklist($tokenValue, $timeout > 0 ? $timeout : 86400);
        return true;
    }

    public function isTokenRevoked(string $tokenValue): bool
    {
        return $this->tokenManager->isBlacklisted($tokenValue);
    }

}
