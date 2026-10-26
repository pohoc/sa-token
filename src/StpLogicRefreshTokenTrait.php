<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Exception\SaTokenException;
use SaToken\Util\SaTokenTimeout;

trait StpLogicRefreshTokenTrait
{
    public function createRefreshToken(string $accessToken, ?int $timeout = null): string
    {
        $config = $this->getConfig();
        $timeout = $timeout ?? $config->getRefreshTokenTimeout();
        SaTokenTimeout::validate($timeout, 'Refresh Token');

        $loginId = $this->getLoginIdByToken($accessToken);
        if ($loginId === null) {
            throw new SaTokenException('AccessToken 无效，无法创建 RefreshToken');
        }

        $this->checkDisableForLogin($loginId);

        // 与刷新、登出和踢出使用同一账号锁；一个 AccessToken 只保留一个有效 RefreshToken。
        $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', (string) $loginId);
        if (!$this->tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        $refreshToken = null;
        try {
            $this->checkDisableForLogin($loginId);
            $currentLoginId = $this->getLoginIdByToken($accessToken);
            if ($currentLoginId === null || $currentLoginId !== (string) $loginId
                || $this->tokenManager->isBlacklisted($accessToken)) {
                throw new SaTokenException('AccessToken 已失效，无法创建 RefreshToken');
            }

            $existingRefreshToken = $this->tokenManager->getRefreshTokenByAccessToken($loginId, $this->loginType, $accessToken);
            if ($existingRefreshToken !== null) {
                $this->tokenManager->deleteRefreshToken($existingRefreshToken);
            }

            $refreshToken = $this->tokenManager->createTokenValue($loginId, $this->loginType, 'srt_');
            $this->tokenManager->saveRefreshToken($refreshToken, $accessToken, $loginId, $this->loginType, $timeout);
            $this->checkDisableForLogin($loginId);
            if (!$this->tokenManager->renewLock($lockKey, 30)) {
                throw new SaTokenException('账号会话锁已失效，拒绝签发 RefreshToken');
            }
        } catch (\Throwable $exception) {
            if ($refreshToken !== null) {
                $this->tokenManager->deleteRefreshToken($refreshToken);
            }

            throw $exception;
        } finally {
            $this->tokenManager->releaseLock($lockKey);
        }

        return $refreshToken;
    }

    public function refreshToken(string $refreshToken): SaLoginResult
    {
        $config = $this->getConfig();

        $data = $this->tokenManager->getRefreshTokenData($refreshToken);
        if ($data === null) {
            if ($this->revokeAccountAfterRefreshTokenReuse($refreshToken)) {
                throw new SaTokenException('RefreshToken 重放已检测，账号会话已全部撤销，请重新登录');
            }
            throw new SaTokenException('RefreshToken 无效或已过期');
        }

        $loginId = is_string($data['loginId'] ?? null) ? $data['loginId'] : '';
        $loginType = is_string($data['loginType'] ?? null) ? $data['loginType'] : '';
        $oldAccessToken = is_string($data['accessToken'] ?? null) ? $data['accessToken'] : '';

        if ($loginId === '' || $loginType === '') {
            throw new SaTokenException('RefreshToken 数据异常');
        }

        if ($loginType !== $this->loginType) {
            throw new SaTokenException('RefreshToken 登录类型不匹配');
        }

        $this->checkDisableForLogin($loginId);

        // 与登录共用同一把账号级互斥锁，避免并发刷新/登录互相覆盖 Token 列表
        $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', $loginId);
        if (!$this->tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        $newAccessToken = null;
        $newRefreshToken = null;
        $timeout = $config->getTimeout();
        try {
            // 与 disable() 共用账号锁后重查，避免被封禁前的预检查结果
            // 在等待锁期间继续签发新的 AccessToken。
            $this->checkDisableForLogin($loginId);
            if ($config->isTokenFingerprint()) {
                $currentRefreshData = $this->tokenManager->getRefreshTokenData($refreshToken);
                if ($currentRefreshData !== null) {
                    $savedFingerprint = $currentRefreshData['fingerprint'] ?? null;
                    $currentFingerprint = $this->tokenManager->computeFingerprint();
                    if (!is_string($savedFingerprint) || !hash_equals($savedFingerprint, $currentFingerprint)) {
                        throw new SaTokenException('RefreshToken 客户端指纹不匹配');
                    }
                }
            }
            $remainingTimeout = $this->tokenManager->getRefreshTokenTimeout($refreshToken);

            $oldAccessToken = is_string($data['accessToken'] ?? null) ? $data['accessToken'] : '';
            // Validate rotation capability while both credentials are still
            // intact. A fixed custom generator must not consume a RefreshToken
            // and strand its still-live AccessToken on a failed refresh.
            if (!$config->isJwtStateless()
                && $this->tokenManager->createTokenValue($loginId, $this->loginType) === $oldAccessToken) {
                throw new SaTokenException('AccessToken 值冲突：刷新时拒绝复用旧凭据');
            }

            // 原子消费：同一 RefreshToken 并发重放时，仅第一个请求成功
            $consumed = $this->tokenManager->consumeRefreshToken($refreshToken);
            if ($consumed === null) {
                if ($this->revokeAccountAfterRefreshTokenReuse($refreshToken)) {
                    throw new SaTokenException('RefreshToken 重放已检测，账号会话已全部撤销，请重新登录');
                }
                throw new SaTokenException('RefreshToken 无效或已过期');
            }

            // The record read before acquiring the account lock may already be
            // stale when another non-rotating refresh completed while we waited.
            // Use the atomically consumed record as the authoritative binding so
            // each serialized refresh revokes the access token issued just before it.
            if (($consumed['loginId'] ?? null) !== $loginId
                || ($consumed['loginType'] ?? null) !== $loginType) {
                throw new SaTokenException('RefreshToken 数据异常');
            }
            $oldAccessToken = is_string($consumed['accessToken'] ?? null)
                ? $consumed['accessToken']
                : '';

            // Account-wide logout/kickout removes the account token index
            // before deleting every credential record. If storage cleanup
            // fails after that first step, an orphaned RefreshToken must not
            // use its still-present AccessToken record to create a new session.
            // Stateless JWTs use the account revocation watermark below instead
            // of an enumerable token list.
            if (!$config->isJwtStateless()) {
                $accountTokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
                if (!in_array($oldAccessToken, array_column($accountTokens, 'tokenValue'), true)) {
                    throw new SaTokenException('AccessToken 已从账号会话中撤销，无法刷新会话');
                }
            }

            $sessionId = null;
            if (!$config->isJwtStateless()) {
                $sessionId = $this->tokenManager->getTokenSessionId($oldAccessToken, $this->loginType);
                if ($sessionId === null) {
                    throw new SaTokenException('AccessToken 会话标识无效，无法刷新会话');
                }
            }

            if ($oldAccessToken !== '') {
                if ($this->tokenManager->isBlacklisted($oldAccessToken)) {
                    throw new SaTokenException('AccessToken 已撤销，无法刷新会话');
                }

                if ($config->isJwtStateless()) {
                    $oldAccessClaims = $this->getJwt()->parseToken($oldAccessToken, true);
                    if (($oldAccessClaims['sub'] ?? null) !== $loginId
                        || ($oldAccessClaims['type'] ?? null) !== $this->loginType) {
                        throw new SaTokenException('AccessToken 身份不匹配，无法刷新会话');
                    }
                    if ($this->tokenManager->isStatelessTokenRevokedByLoginId(
                        $loginId,
                        $this->loginType,
                        $oldAccessClaims['iat'] ?? null,
                        $oldAccessClaims['satoken_gen'] ?? null
                    )) {
                        throw new SaTokenException('AccessToken 已因账号撤销而失效，无法刷新会话');
                    }
                    if ($this->getLoginIdByToken($oldAccessToken) === $loginId) {
                        $this->revokeToken($oldAccessToken);
                    }
                } else {
                    $this->tokenManager->deleteToken($oldAccessToken, $loginId, $this->loginType);
                }
            }

            if ($config->isJwtStateless()) {
                $newAccessToken = $this->getJwt()->createStatelessToken($loginId, $this->loginType, $timeout);
                $newAccessClaims = $this->getJwt()->parseToken($newAccessToken);
                if (($newAccessClaims['sub'] ?? null) !== $loginId
                    || ($newAccessClaims['type'] ?? null) !== $this->loginType
                    || $this->tokenManager->isStatelessTokenRevokedByLoginId(
                        $loginId,
                        $this->loginType,
                        $newAccessClaims['iat'] ?? null,
                        $newAccessClaims['satoken_gen'] ?? null
                    )) {
                    throw new SaTokenException('账号会话已撤销，拒绝签发无效登录凭证');
                }
                if ($config->isTokenFingerprint()) {
                    $this->tokenManager->saveFingerprint($newAccessToken, $this->tokenManager->computeFingerprint(), $timeout);
                }
                $this->tokenManager->updateLastActiveToNow($newAccessToken);
            } else {
                $newAccessToken = $this->tokenManager->createTokenValue($loginId, $this->loginType);
                $newAccessToken = $this->tokenManager->saveToken(
                    $newAccessToken,
                    $loginId,
                    $this->loginType,
                    '',
                    $timeout,
                    $sessionId
                );
                if ($config->isTokenFingerprint()) {
                    $this->tokenManager->saveFingerprint($newAccessToken, $this->tokenManager->computeFingerprint(), $timeout);
                }
            }

            $result = (new SaLoginResult())
                ->setAccessToken($newAccessToken)
                ->setAccessExpire($timeout > 0 ? $timeout : 0);

            if ($config->isRefreshTokenRotation()) {
                $newRefreshToken = $this->tokenManager->createTokenValue($loginId, $this->loginType, 'srt_');
                $refreshTimeout = $config->getRefreshTokenTimeout();
                $this->tokenManager->saveRefreshToken($newRefreshToken, $newAccessToken, $loginId, $this->loginType, $refreshTimeout);
                $result->setRefreshToken($newRefreshToken)
                    ->setRefreshExpire($refreshTimeout > 0 ? $refreshTimeout : 0);
            } else {
                // 未开启轮换时保留原 RefreshToken 并重新绑定到新 AccessToken，
                // 避免一次刷新后客户端永久失去刷新能力
                $rtTimeout = ($remainingTimeout > 0) ? $remainingTimeout : $config->getRefreshTokenTimeout();
                $this->tokenManager->saveRefreshToken($refreshToken, $newAccessToken, $loginId, $this->loginType, $rtTimeout);
                $result->setRefreshToken($refreshToken)
                    ->setRefreshExpire($rtTimeout > 0 ? $rtTimeout : 0);
            }

            $this->checkDisableForLogin($loginId);
            if (!$this->tokenManager->renewLock($lockKey, 30)) {
                throw new SaTokenException('账号会话锁已失效，拒绝签发刷新凭证');
            }

            $this->writeTokenToResponse($newAccessToken, new SaLoginParameter());

            return $result;
        } catch (\Throwable $exception) {
            if ($newAccessToken !== null) {
                try {
                    if (!$this->revokeToken($newAccessToken)) {
                        throw new SaTokenException('刷新失败后的 AccessToken 撤销未完成');
                    }
                } catch (\Throwable $cleanupException) {
                    if ($config->isJwtStateless()) {
                        $blacklistTimeout = $timeout > 0 ? $timeout : null;
                        $this->tokenManager->addToBlacklist($newAccessToken, $blacklistTimeout);
                    } else {
                        $invalidated = $this->tokenManager->invalidateTokenIfOwnedByLoginType(
                            $newAccessToken,
                            $loginId,
                            $this->loginType
                        );
                        if (!$invalidated) {
                            throw $cleanupException;
                        }

                        try {
                            $this->removeTokenAndRefreshToken($newAccessToken, $loginId);
                        } catch (\Throwable) {
                            // The exact bearer has been blacklisted if its
                            // session index cannot be safely edited now.
                        }
                    }
                }
            }

            if ($newRefreshToken !== null) {
                $this->tokenManager->deleteRefreshToken($newRefreshToken);
            } elseif (!$config->isRefreshTokenRotation()) {
                $this->tokenManager->deleteRefreshToken($refreshToken);
            }

            throw $exception;
        } finally {
            $this->tokenManager->releaseLock($lockKey);
        }
    }

    protected function revokeAccountAfterRefreshTokenReuse(string $refreshToken): bool
    {
        if (!$this->getConfig()->isRefreshTokenRotation()) {
            return false;
        }

        $usedData = $this->tokenManager->getConsumedRefreshTokenData($refreshToken);
        $loginId = is_string($usedData['loginId'] ?? null) ? $usedData['loginId'] : '';
        $loginType = is_string($usedData['loginType'] ?? null) ? $usedData['loginType'] : '';
        if ($loginId === '' || $loginType !== $this->loginType) {
            return false;
        }

        $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', $loginId);
        if (!$this->tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            // Recheck under the same account lock as refresh/login so the used
            // token cannot be raced with a new active registration.
            $usedData = $this->tokenManager->getConsumedRefreshTokenData($refreshToken);
            if (($usedData['loginId'] ?? null) !== $loginId
                || ($usedData['loginType'] ?? null) !== $this->loginType
                || $this->tokenManager->getRefreshTokenData($refreshToken) !== null) {
                return false;
            }

            $this->tokenManager->deleteAllTokenByLoginId($loginId, $this->loginType);
            if ($this->getConfig()->isJwtStateless()) {
                $this->tokenManager->revokeStatelessTokensByLoginId($loginId, $this->loginType);
            }
            $this->tokenManager->deleteConsumedRefreshTokenData($refreshToken);
            return true;
        } finally {
            $this->tokenManager->releaseLock($lockKey);
        }
    }

    public function revokeRefreshToken(string $refreshToken): bool
    {
        $data = $this->tokenManager->getRefreshTokenData($refreshToken);
        $loginId = is_string($data['loginId'] ?? null) ? $data['loginId'] : '';
        $loginType = is_string($data['loginType'] ?? null) ? $data['loginType'] : '';
        if ($loginId === '' || $loginType !== $this->loginType) {
            return false;
        }

        $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', $loginId);
        if (!$this->tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            // 刷新与撤销共用账号锁；锁内重读，避免把刷新中已消费的 RT 报告为已撤销。
            $current = $this->tokenManager->getRefreshTokenData($refreshToken);
            if ($current === null
                || ($current['loginId'] ?? null) !== $loginId
                || ($current['loginType'] ?? null) !== $this->loginType) {
                return false;
            }

            $this->tokenManager->deleteRefreshToken($refreshToken);
            return true;
        } finally {
            $this->tokenManager->releaseLock($lockKey);
        }
    }

    public function revokeRefreshTokenByAccessToken(string $accessToken): bool
    {
        $loginId = $this->tokenManager->getLoginIdByToken($accessToken);
        if ($loginId === null) {
            return false;
        }

        $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', (string) $loginId);
        if (!$this->tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            if ($this->tokenManager->getLoginIdByToken($accessToken) !== (string) $loginId) {
                return false;
            }
            $refreshToken = $this->tokenManager->getRefreshTokenByAccessToken($loginId, $this->loginType, $accessToken);
            if ($refreshToken === null) {
                return false;
            }

            $this->tokenManager->deleteRefreshToken($refreshToken);
            return true;
        } finally {
            $this->tokenManager->releaseLock($lockKey);
        }
    }

    public function isRefreshTokenValid(string $refreshToken): bool
    {
        return $this->tokenManager->isRefreshTokenValid($refreshToken);
    }

    public function getRefreshTokenByAccessToken(string $accessToken): ?string
    {
        $loginId = $this->tokenManager->getLoginIdByToken($accessToken);
        if ($loginId === null) {
            return null;
        }
        return $this->tokenManager->getRefreshTokenByAccessToken($loginId, $this->loginType, $accessToken);
    }
}
