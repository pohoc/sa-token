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
        if ($loginId === null || $loginId === '' || $loginId === [] || is_array($loginId) || (is_object($loginId) && !method_exists($loginId, '__toString'))) {
            throw new \SaToken\Exception\SaTokenException('loginId 不能为空且必须是标量类型');
        }
        $sessionId = TokenManager::SESSION_PREFIX . $this->loginType . ':' . (is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : ''));
        $session = SaSession::getBySessionId($sessionId);

        if ($session === null && $isCreate) {
            $timeout = $this->getConfig()->getTimeout();
            $sessionTimeout = ($timeout > 0) ? $timeout : null;
            $session = new SaSession($sessionId, false, $sessionTimeout);
        }

        return $session;
    }

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
}
