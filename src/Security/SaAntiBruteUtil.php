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

    public static function isAccountLocked(string $account, string $loginType = 'login'): bool
    {
        $dao = SaToken::getDao();
        $key = self::getKey($account, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return false;
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return false;
        }

        $lockedUntil = $info['lockedUntil'] ?? 0;
        if ($lockedUntil > 0 && $lockedUntil > time()) {
            return true;
        }

        return false;
    }

    public static function getRemainingLockTime(string $account, string $loginType = 'login'): int
    {
        $dao = SaToken::getDao();
        $key = self::getKey($account, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return 0;
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return 0;
        }

        $lockedUntil = $info['lockedUntil'] ?? 0;
        if ($lockedUntil > time()) {
            return $lockedUntil - time();
        }

        return 0;
    }

    public static function recordFailure(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $key = self::getKey($account, $loginType);
        $data = $dao->get($key);

        $info = ['failCount' => 0, 'firstFailureTime' => 0, 'lockedUntil' => 0];
        if ($data !== null) {
            $decoded = @json_decode($data, true);
            if (is_array($decoded)) {
                $info = $decoded;
            }
        }

        $info['failCount'] = ($info['failCount'] ?? 0) + 1;
        if ($info['firstFailureTime'] === 0) {
            $info['firstFailureTime'] = time();
        }

        $dao->set($key, json_encode($info), 86400);
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
        $key = self::getKey($account, $loginType);
        $data = $dao->get($key);

        $info = ['failCount' => 0, 'firstFailureTime' => time(), 'lockedUntil' => time() + $durationSeconds];
        if ($data !== null) {
            $decoded = @json_decode($data, true);
            if (is_array($decoded)) {
                $info = $decoded;
                $info['lockedUntil'] = time() + $durationSeconds;
            }
        }

        $dao->set($key, json_encode($info), $durationSeconds + 60);
    }

    public static function unlock(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $key = self::getKey($account, $loginType);
        $dao->delete($key);
    }

    public static function clearFailures(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $key = self::getKey($account, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return;
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return;
        }

        unset($info['failCount'], $info['firstFailureTime']);
        $info['lockedUntil'] = 0;

        $remainingKeys = array_keys($info);
        if (count($remainingKeys) === 1 && $remainingKeys[0] === 'lockedUntil') {
            $dao->delete($key);
        } else {
            $dao->set($key, json_encode($info), 86400);
        }
    }

    public static function getFailCount(string $account, string $loginType = 'login'): int
    {
        $dao = SaToken::getDao();
        $key = self::getKey($account, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return 0;
        }

        $info = @json_decode($data, true);
        return $info['failCount'] ?? 0;
    }

    public static function getSecurityInfo(string $account, string $loginType = 'login'): array
    {
        $dao = SaToken::getDao();
        $key = self::getKey($account, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return ['failCount' => 0, 'isLocked' => false, 'remainingLockTime' => 0];
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return ['failCount' => 0, 'isLocked' => false, 'remainingLockTime' => 0];
        }

        return [
            'failCount' => $info['failCount'] ?? 0,
            'isLocked' => self::isAccountLocked($account, $loginType),
            'remainingLockTime' => self::getRemainingLockTime($account, $loginType),
            'firstFailureTime' => $info['firstFailureTime'] ?? 0,
            'lockedUntil' => $info['lockedUntil'] ?? 0,
        ];
    }

    public static function reset(): void
    {
        self::$keyPrefix = 'satoken:security:brute:';
    }
}
