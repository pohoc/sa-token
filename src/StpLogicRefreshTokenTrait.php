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

        // 与刷新、登出和踢出使用同一账号锁；一个 AccessToken 只保留一个有效 RefreshToken。
        $lockKey = 'login:' . $this->loginType . ':' . hash('sha256', (string) $loginId);
        if (!$this->tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            $currentLoginId = $this->tokenManager->getLoginIdByToken($accessToken);
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

        try {
            $remainingTimeout = $this->tokenManager->getRefreshTokenTimeout($refreshToken);

            // 原子消费：同一 RefreshToken 并发重放时，仅第一个请求成功
            $consumed = $this->tokenManager->consumeRefreshToken($refreshToken);
            if ($consumed === null) {
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

            if ($oldAccessToken !== '') {
                $this->tokenManager->deleteToken($oldAccessToken, $loginId, $this->loginType);
            }

            $newAccessToken = $this->tokenManager->createTokenValue($loginId, $this->loginType);
            $timeout = $config->getTimeout();
            $newAccessToken = $this->tokenManager->saveToken($newAccessToken, $loginId, $this->loginType, '', $timeout);

            if ($config->isTokenFingerprint()) {
                $this->tokenManager->saveFingerprint($newAccessToken, $this->tokenManager->computeFingerprint(), $timeout);
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

            $this->writeTokenToResponse($newAccessToken, new SaLoginParameter());

            return $result;
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
