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
        return self::$keyPrefix . $loginType . ':' . md5($loginId);
    }

    public static function getHistoryKey(mixed $loginId, string $loginType = 'login'): string
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        return self::$historyPrefix . $loginType . ':' . md5($loginIdStr);
    }

    public static function recordLoginIp(mixed $loginId, string $ip, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::getKey($loginIdStr, $loginType);
        $historyKey = self::getHistoryKey($loginIdStr, $loginType);

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
            $decodedHistory = @json_decode($historyData, true);
            if (is_array($decodedHistory)) {
                /** @var array<array{ip: string, time: int}> $decodedHistory */
                $history = $decodedHistory;
            }
        }

        $lastIp = is_string($info['currentIp'] ?? null) ? $info['currentIp'] : '';
        $isAnomaly = self::detectAnomaly($lastIp, $ip, $history);
        if ($isAnomaly) {
            $anomalyCount = $info['anomalyCount'] ?? 0;
            $info['anomalyCount'] = (is_int($anomalyCount) ? $anomalyCount : 0) + 1;
        }

        $info['currentIp'] = $ip;
        $info['lastLoginTime'] = $now;
        $info['lastLoginIp'] = $info['lastLoginIp'] ?? null;

        $jsonStr = json_encode($info);
        $dao->set($key, $jsonStr !== false ? $jsonStr : '{}', 2592000);

        $history[] = ['ip' => $ip, 'time' => $now];
        if (count($history) > 20) {
            $history = array_slice($history, -20);
        }
        $historyJson = json_encode($history);
        $dao->set($historyKey, $historyJson !== false ? $historyJson : '[]', 2592000);
    }

    /**
     * @param array<array{ip: string, time: int}> $history
     */
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
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::getKey($loginIdStr, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return 0;
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return 0;
        }

        $anomalyCount = $info['anomalyCount'] ?? 0;
        return is_int($anomalyCount) ? $anomalyCount : 0;
    }

    /**
     * @return array<array{ip: string, time: int}>
     */
    public static function getIpHistory(mixed $loginId, string $loginType = 'login'): array
    {
        $dao = SaToken::getDao();
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::getHistoryKey($loginIdStr, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return [];
        }

        $history = @json_decode($data, true);
        if (!is_array($history)) {
            return [];
        }
        /** @var array<array{ip: string, time: int}> $history */
        return $history;
    }

    public static function getCurrentIp(mixed $loginId, string $loginType = 'login'): ?string
    {
        $dao = SaToken::getDao();
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::getKey($loginIdStr, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return null;
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return null;
        }

        $currentIp = $info['currentIp'] ?? null;
        return is_string($currentIp) ? $currentIp : null;
    }

    /**
     * @return array{currentIp: ?string, lastLoginIp: ?string, lastLoginTime: ?int, anomalyCount: int}
     */
    public static function getLoginInfo(mixed $loginId, string $loginType = 'login'): array
    {
        $dao = SaToken::getDao();
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::getKey($loginIdStr, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return ['currentIp' => null, 'lastLoginIp' => null, 'lastLoginTime' => null, 'anomalyCount' => 0];
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return ['currentIp' => null, 'lastLoginIp' => null, 'lastLoginTime' => null, 'anomalyCount' => 0];
        }

        $currentIp = $info['currentIp'] ?? null;
        $lastLoginIp = $info['lastLoginIp'] ?? null;
        $lastLoginTime = $info['lastLoginTime'] ?? null;
        $anomalyCount = $info['anomalyCount'] ?? 0;
        return [
            'currentIp' => is_string($currentIp) ? $currentIp : null,
            'lastLoginIp' => is_string($lastLoginIp) ? $lastLoginIp : null,
            'lastLoginTime' => is_int($lastLoginTime) ? $lastLoginTime : null,
            'anomalyCount' => is_int($anomalyCount) ? $anomalyCount : 0,
        ];
    }

    public static function clearHistory(mixed $loginId, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $dao->delete(self::getKey($loginIdStr, $loginType));
        $dao->delete(self::getHistoryKey($loginIdStr, $loginType));
    }

    public static function reset(): void
    {
        self::$keyPrefix = 'satoken:security:ip:';
        self::$historyPrefix = 'satoken:security:ip:history:';
    }
}
