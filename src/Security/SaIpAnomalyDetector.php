<?php

declare(strict_types=1);

namespace SaToken\Security;

use SaToken\SaToken;

class SaIpAnomalyDetector
{
    protected static string $keyPrefix = 'satoken:security:ip:';
    protected static string $historyPrefix = 'satoken:security:ip:history:';

    public static function setKeyPrefix(string $prefix): void
    {
        self::$keyPrefix = $prefix;
    }

    public static function getKeyPrefix(): string
    {
        return self::$keyPrefix;
    }

    public static function getKey(string $loginId, string $loginType = 'login'): string
    {
        return self::$keyPrefix . $loginType . ':' . md5((string) $loginId);
    }

    public static function getHistoryKey(string $loginId, string $loginType = 'login'): string
    {
        return self::$historyPrefix . $loginType . ':' . md5((string) $loginId);
    }

    public static function recordLoginIp(mixed $loginId, string $ip, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType);
        $historyKey = self::getHistoryKey($loginId, $loginType);

        $now = time();
        $data = $dao->get($key);
        $info = ['currentIp' => $ip, 'lastLoginIp' => null, 'lastLoginTime' => $now, 'anomalyCount' => 0];
        $history = [];

        if ($data !== null) {
            $decoded = @json_decode($data, true);
            if (is_array($decoded)) {
                $info = $decoded;
                $info['lastLoginIp'] = $info['currentIp'] ?? null;
                $info['lastLoginTime'] = $info['lastLoginTime'] ?? $now;
            }
        }

        $historyData = $dao->get($historyKey);
        if ($historyData !== null) {
            $history = @json_decode($historyData, true) ?? [];
        }

        $isAnomaly = self::detectAnomaly($info['currentIp'] ?? '', $ip, $history);
        if ($isAnomaly) {
            $info['anomalyCount'] = ($info['anomalyCount'] ?? 0) + 1;
        }

        $info['currentIp'] = $ip;
        $info['lastLoginTime'] = $now;
        $info['lastLoginIp'] = $info['lastLoginIp'] ?? null;

        $dao->set($key, json_encode($info), 2592000);

        $history[] = ['ip' => $ip, 'time' => $now];
        if (count($history) > 20) {
            $history = array_slice($history, -20);
        }
        $dao->set($historyKey, json_encode($history), 2592000);
    }

    protected static function detectAnomaly(string $lastIp, string $currentIp, array $history): bool
    {
        if ($lastIp === '' || $currentIp === '') {
            return false;
        }
        if ($lastIp === $currentIp) {
            return false;
        }

        $config = SaToken::getConfig();
        if ($config->getIpAnomalyDetection() === false) {
            return false;
        }

        $sensitivity = $config->getIpAnomalySensitivity();

        $matchingHistoryCount = 0;
        foreach ($history as $entry) {
            if (self::isSameRegion($entry['ip'] ?? '', $currentIp)) {
                $matchingHistoryCount++;
            }
        }

        if ($matchingHistoryCount >= $sensitivity) {
            return false;
        }

        return true;
    }

    public static function isSameRegion(string $ip1, string $ip2): bool
    {
        if ($ip1 === $ip2) {
            return true;
        }

        $isPrivate = function (string $ip): bool {
            $isLoopback = str_starts_with($ip, '127.');
            $is192168 = str_starts_with($ip, '192.168.');
            $is10 = str_starts_with($ip, '10.');
            $is172 = false;
            if (str_starts_with($ip, '172.')) {
                $parts = explode('.', $ip);
                if (count($parts) >= 2) {
                    $second = (int) $parts[1];
                    $is172 = $second >= 16 && $second <= 31;
                }
            }
            return $isLoopback || $is192168 || $is10 || $is172;
        };

        $isPrivate1 = $isPrivate($ip1);
        $isPrivate2 = $isPrivate($ip2);

        if ($isPrivate1 && $isPrivate2) {
            return true;
        }
        if ($isPrivate1 || $isPrivate2) {
            return false;
        }

        $p1 = strtok($ip1, '.');
        $p2 = strtok($ip2, '.');

        if ($p1 === false || $p2 === false) {
            return false;
        }

        return $p1 === $p2;
    }

    public static function getAnomalyCount(mixed $loginId, string $loginType = 'login'): int
    {
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return 0;
        }

        $info = @json_decode($data, true);
        return $info['anomalyCount'] ?? 0;
    }

    public static function getIpHistory(mixed $loginId, string $loginType = 'login'): array
    {
        $dao = SaToken::getDao();
        $key = self::getHistoryKey($loginId, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return [];
        }

        $history = @json_decode($data, true);
        return is_array($history) ? $history : [];
    }

    public static function getCurrentIp(mixed $loginId, string $loginType = 'login'): ?string
    {
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return null;
        }

        $info = @json_decode($data, true);
        return $info['currentIp'] ?? null;
    }

    public static function getLoginInfo(mixed $loginId, string $loginType = 'login'): array
    {
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return ['currentIp' => null, 'lastLoginIp' => null, 'lastLoginTime' => null, 'anomalyCount' => 0];
        }

        $info = @json_decode($data, true);
        return [
            'currentIp' => $info['currentIp'] ?? null,
            'lastLoginIp' => $info['lastLoginIp'] ?? null,
            'lastLoginTime' => $info['lastLoginTime'] ?? null,
            'anomalyCount' => $info['anomalyCount'] ?? 0,
        ];
    }

    public static function clearHistory(mixed $loginId, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $dao->delete(self::getKey($loginId, $loginType));
        $dao->delete(self::getHistoryKey($loginId, $loginType));
    }

    public static function reset(): void
    {
        self::$keyPrefix = 'satoken:security:ip:';
        self::$historyPrefix = 'satoken:security:ip:history:';
    }
}
