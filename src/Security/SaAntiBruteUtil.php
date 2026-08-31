<?php

declare(strict_types=1);

namespace SaToken\Security;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;

class SaAntiBruteUtil
{
    protected static string $keyPrefix = 'satoken:security:brute:';

    public static function setKeyPrefix(string $prefix): void
    {
        self::$keyPrefix = $prefix;
    }

    public static function getKeyPrefix(): string
    {
        return self::$keyPrefix;
    }

    public static function getKey(string $account, string $loginType = 'login'): string
    {
        return self::$keyPrefix . $loginType . ':' . md5($account);
    }

    protected static function getLockKey(string $account, string $loginType = 'login'): string
    {
        return self::getKey($account, $loginType) . ':lock';
    }

    protected static function getCountKey(string $account, string $loginType = 'login'): string
    {
        return self::getKey($account, $loginType) . ':cnt';
    }

    public static function isAccountLocked(string $account, string $loginType = 'login'): bool
    {
        $dao = SaToken::getDao();
        $lockUntil = $dao->get(self::getLockKey($account, $loginType));

        return $lockUntil !== null && (int) $lockUntil > time();
    }

    public static function getRemainingLockTime(string $account, string $loginType = 'login'): int
    {
        $dao = SaToken::getDao();
        $lockUntil = $dao->get(self::getLockKey($account, $loginType));

        if ($lockUntil === null) {
            return 0;
        }

        $remaining = (int) $lockUntil - time();
        return $remaining > 0 ? $remaining : 0;
    }

    public static function recordFailure(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $config = SaToken::getConfig();
        $maxFailures = $config->getAntiBruteMaxFailures();
        $lockDuration = $config->getAntiBruteLockDuration();

        // 原子递增失败计数：读-改-写在并发爆破下会互相覆盖，导致锁定阈值形同虚设
        $failCount = $dao->increment(self::getCountKey($account, $loginType), 1, 86400);

        if ($maxFailures > 0 && $lockDuration > 0 && $failCount >= $maxFailures) {
            self::lock($account, $loginType, $lockDuration);
        }
    }

    public static function checkAndThrow(string $account, string $loginType = 'login'): void
    {
        if (self::isAccountLocked($account, $loginType)) {
            $remaining = self::getRemainingLockTime($account, $loginType);
            throw new SaTokenException(
                '账号已被锁定，请 ' . $remaining . ' 秒后重试',
                -10
            );
        }
    }

    public static function lock(string $account, string $loginType = 'login', int $durationSeconds = 600): void
    {
        $dao = SaToken::getDao();
        $dao->set(
            self::getLockKey($account, $loginType),
            (string) (time() + $durationSeconds),
            $durationSeconds + 60
        );
    }

    public static function unlock(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $dao->delete(self::getLockKey($account, $loginType));
    }

    public static function clearFailures(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $dao->delete(self::getCountKey($account, $loginType));
        $dao->delete(self::getLockKey($account, $loginType));
    }

    public static function getFailCount(string $account, string $loginType = 'login'): int
    {
        $dao = SaToken::getDao();
        $count = $dao->get(self::getCountKey($account, $loginType));

        return $count !== null ? (int) $count : 0;
    }

    /**
     * @return array{failCount: int, isLocked: bool, remainingLockTime: int, firstFailureTime: int, lockedUntil: int}
     */
    public static function getSecurityInfo(string $account, string $loginType = 'login'): array
    {
        $lockUntil = SaToken::getDao()->get(self::getLockKey($account, $loginType));
        $lockedUntilInt = $lockUntil !== null ? (int) $lockUntil : 0;

        return [
            'failCount' => self::getFailCount($account, $loginType),
            'isLocked' => self::isAccountLocked($account, $loginType),
            'remainingLockTime' => self::getRemainingLockTime($account, $loginType),
            'firstFailureTime' => 0,
            'lockedUntil' => $lockedUntilInt,
        ];
    }

    public static function reset(): void
    {
        self::$keyPrefix = 'satoken:security:brute:';
    }
}
