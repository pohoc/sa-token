<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Exception\SaTokenException;

trait StpLogicSessionTrait
{
    public function getSession(): SaSession
    {
        $loginId = $this->getLoginIdAsNotNull();
        $session = $this->getSessionByLoginId($loginId);
        if ($session === null) {
            throw new SaTokenException('会话不存在');
        }
        return $session;
    }

    public function getSessionByLoginId(mixed $loginId, bool $isCreate = true): ?SaSession
    {
        // loginId 来自调用方输入：空值会被归一为空串会话 ID（所有此类"用户"
        // 共享同一会话），任意垃圾输入则可无界创建会话键（存储 DoS）
        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new \SaToken\Exception\SaTokenException('loginId 不能为空且必须是非布尔标量');
        }
        $sessionId = TokenManager::buildSessionId($this->loginType, (string) $loginId);
        $session = SaSession::getLoginSessionById($sessionId);

        if ($session === null && $isCreate) {
            $timeout = $this->getConfig()->getTimeout();
            $sessionTimeout = ($timeout > 0) ? $timeout : null;
            $session = SaSession::forLoginSession($sessionId, $sessionTimeout);
        }

        return $session;
    }

    public function getTokenSession(bool $isCreate = true): ?SaSession
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return null;
        }

        // Token sessions are keyed only by bearer value, so validate the current
        // loginType and all session constraints before reading or creating one.
        if ($this->getLoginIdByToken($tokenValue) === null) {
            return null;
        }

        // Migrate any legacy refresh lineage metadata before touching the
        // TokenSession storage key; both used to share the same DAO namespace.
        if ($this->tokenManager->getTokenSessionId($tokenValue, $this->loginType) === null) {
            return null;
        }

        $sessionId = TokenManager::TOKEN_SESSION_PREFIX . $tokenValue;
        $session = SaSession::getTokenSessionById($sessionId);

        if ($session === null && $isCreate) {
            $timeout = $this->tokenManager->getTokenTimeout($tokenValue);
            $sessionTimeout = ($timeout > 0) ? $timeout : null;
            $session = SaSession::forTokenSession($sessionId, $sessionTimeout);
        }

        return $session;
    }
}
