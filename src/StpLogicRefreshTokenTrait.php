<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Exception\SaTokenException;

trait StpLogicRefreshTokenTrait
{
    public function createRefreshToken(string $accessToken, ?int $timeout = null): string
    {
        $config = $this->getConfig();
        $timeout = $timeout ?? $config->getRefreshTokenTimeout();

        $loginId = $this->tokenManager->getLoginIdByToken($accessToken);
        if ($loginId === null) {
            throw new SaTokenException('AccessToken 无效，无法创建 RefreshToken');
        }

        $refreshToken = $this->tokenManager->createTokenValue($loginId, $this->loginType, 'srt_');
        $this->tokenManager->saveRefreshToken($refreshToken, $accessToken, $loginId, $this->loginType, $timeout);

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
        if (!$this->tokenManager->acquireLock($lockKey, 5)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            $remainingTimeout = $this->tokenManager->getRefreshTokenTimeout($refreshToken);

            // 原子消费：同一 RefreshToken 并发重放时，仅第一个请求成功
            $consumed = $this->tokenManager->consumeRefreshToken($refreshToken);
            if ($consumed === null) {
                throw new SaTokenException('RefreshToken 无效或已过期');
            }

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
        if (!$this->tokenManager->isRefreshTokenValid($refreshToken)) {
            return false;
        }
        $this->tokenManager->deleteRefreshToken($refreshToken);
        return true;
    }

    public function revokeRefreshTokenByAccessToken(string $accessToken): bool
    {
        $loginId = $this->tokenManager->getLoginIdByToken($accessToken);
        if ($loginId === null) {
            return false;
        }
        $refreshToken = $this->tokenManager->getRefreshTokenByAccessToken($loginId, $this->loginType, $accessToken);
        if ($refreshToken === null) {
            return false;
        }
        $this->tokenManager->deleteRefreshToken($refreshToken);
        return true;
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
