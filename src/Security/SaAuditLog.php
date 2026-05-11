<?php

declare(strict_types=1);

namespace SaToken\Security;

use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

class SaAuditLog
{
    protected static string $keyPrefix = 'satoken:audit:';
    protected static bool $enabled = false;
    protected static int $maxEntries = 1000;
    protected static int $ttlDays = 30;

    public static function setEnabled(bool $enabled): void
    {
        self::$enabled = $enabled;
    }

    public static function isEnabled(): bool
    {
        return self::$enabled;
    }

    public static function setMaxEntries(int $max): void
    {
        self::$maxEntries = $max;
    }

    public static function setTtlDays(int $days): void
    {
        self::$ttlDays = $days;
    }

    public static function log(
        string $event,
        mixed $loginId = null,
        string $loginType = 'login',
        string $action = '',
        ?string $tokenValue = null,
        ?string $ip = null,
        ?string $userAgent = null,
        array $extra = []
    ): ?string {
        if (!self::$enabled) {
            return null;
        }

        $dao = SaToken::getDao();
        $id = bin2hex(random_bytes(16));
        $time = time();

        $entry = [
            'id' => $id,
            'event' => $event,
            'loginId' => $loginId !== null ? (string) $loginId : null,
            'loginType' => $loginType,
            'action' => $action,
            'tokenValue' => $tokenValue !== null ? substr($tokenValue, 0, 32) . '...' : null,
            'ip' => $ip ?? self::getClientIp(),
            'userAgent' => $userAgent ?? SaTokenContext::getHeader('User-Agent'),
            'extra' => $extra,
            'time' => $time,
            'timestamp' => date('Y-m-d H:i:s', $time),
        ];

        $key = self::$keyPrefix . $loginType . ':' . $id;
        $dao->set($key, json_encode($entry), self::$ttlDays * 86400);

        self::trimOldEntries($loginType);

        return $id;
    }

    public static function logLogin(mixed $loginId, string $loginType = 'login', ?string $tokenValue = null): ?string
    {
        return self::log('login', $loginId, $loginType, '用户登录', $tokenValue);
    }

    public static function logLogout(mixed $loginId, string $loginType = 'login', ?string $tokenValue = null): ?string
    {
        return self::log('logout', $loginId, $loginType, '用户登出', $tokenValue);
    }

    public static function logKickout(mixed $loginId, string $loginType = 'login', ?string $tokenValue = null): ?string
    {
        return self::log('kickout', $loginId, $loginType, '账号被踢出', $tokenValue);
    }

    public static function logDisable(mixed $loginId, string $loginType = 'login', ?string $reason = null): ?string
    {
        return self::log('disable', $loginId, $loginType, '账号被封禁', null, null, null, ['reason' => $reason ?? '']);
    }

    public static function logUndisable(mixed $loginId, string $loginType = 'login'): ?string
    {
        return self::log('undisable', $loginId, $loginType, '账号解封');
    }

    public static function logSwitchTo(mixed $loginId, mixed $targetLoginId, string $loginType = 'login'): ?string
    {
        return self::log('switch', $loginId, $loginType, '身份切换到 ' . $targetLoginId, null, null, null, ['targetLoginId' => (string) $targetLoginId]);
    }

    public static function logPermissionCheck(mixed $loginId, string $permission, bool $result, string $loginType = 'login'): ?string
    {
        return self::log('permission_check', $loginId, $loginType, '权限校验: ' . $permission, null, null, null, ['permission' => $permission, 'result' => $result]);
    }

    public static function getLog(string $id, string $loginType = 'login'): ?array
    {
        $dao = SaToken::getDao();
        $key = self::$keyPrefix . $loginType . ':' . $id;
        $data = $dao->get($key);

        if ($data === null) {
            return null;
        }

        return @json_decode($data, true);
    }

    public static function getRecentLogs(string $loginType = 'login', int $limit = 50): array
    {
        $dao = SaToken::getDao();
        $pattern = self::$keyPrefix . $loginType . ':';
        $results = $dao->search($pattern, '', 0, $limit);

        $logs = [];
        foreach ($results as $value) {
            if ($value === '') {
                continue;
            }
            $decoded = @json_decode($value, true);
            if (is_array($decoded)) {
                $logs[] = $decoded;
            }
        }

        usort($logs, fn ($a, $b) => ($b['time'] ?? 0) - ($a['time'] ?? 0));
        return $logs;
    }

    public static function getLogsByLoginId(mixed $loginId, string $loginType = 'login', int $limit = 50): array
    {
        $logs = self::getRecentLogs($loginType, $limit * 2);
        $result = [];

        foreach ($logs as $log) {
            if (($log['loginId'] ?? '') === (string) $loginId) {
                $result[] = $log;
                if (count($result) >= $limit) {
                    break;
                }
            }
        }

        return $result;
    }

    public static function getLogsByEvent(string $event, string $loginType = 'login', int $limit = 50): array
    {
        $logs = self::getRecentLogs($loginType, $limit * 2);
        $result = [];

        foreach ($logs as $log) {
            if (($log['event'] ?? '') === $event) {
                $result[] = $log;
                if (count($result) >= $limit) {
                    break;
                }
            }
        }

        return $result;
    }

    public static function getLogsByIp(string $ip, string $loginType = 'login', int $limit = 50): array
    {
        $dao = SaToken::getDao();
        $pattern = self::$keyPrefix . $loginType . ':';
        $results = $dao->search($pattern, '', 0, $limit * 2);

        $result = [];
        foreach ($results as $value) {
            if ($value === '') {
                continue;
            }
            $decoded = @json_decode($value, true);
            if (!is_array($decoded)) {
                continue;
            }
            if (($decoded['ip'] ?? '') === $ip) {
                $result[] = $decoded;
                if (count($result) >= $limit) {
                    break;
                }
            }
        }

        return $result;
    }

    public static function clearLogs(?string $loginType = null): void
    {
        $dao = SaToken::getDao();

        if ($loginType === null) {
            foreach (['login', 'admin'] as $type) {
                self::clearLogs($type);
            }
            return;
        }

        $pattern = self::$keyPrefix . $loginType . ':';
        $results = $dao->search($pattern, '', 0, self::$maxEntries * 10);

        foreach ($results as $value) {
            if ($value === '') {
                continue;
            }
            $decoded = @json_decode($value, true);
            if (!is_array($decoded)) {
                continue;
            }
            $id = $decoded['id'] ?? '';
            if ($id !== '') {
                $dao->delete(self::$keyPrefix . $loginType . ':' . $id);
            }
        }
    }

    protected static function trimOldEntries(string $loginType): void
    {
        $dao = SaToken::getDao();
        $pattern = self::$keyPrefix . $loginType . ':';
        $results = $dao->search($pattern, '', 0, self::$maxEntries + 100);

        if (count($results) <= self::$maxEntries) {
            return;
        }

        $entries = [];
        foreach ($results as $value) {
            if ($value === '') {
                continue;
            }
            $decoded = @json_decode($value, true);
            if (!is_array($decoded)) {
                continue;
            }
            $entries[] = $decoded;
        }

        usort($entries, fn ($a, $b) => ($b['time'] ?? 0) - ($a['time'] ?? 0));

        $toDelete = array_slice($entries, self::$maxEntries);
        foreach ($toDelete as $entry) {
            $id = $entry['id'] ?? '';
            if ($id !== '') {
                $dao->delete(self::$keyPrefix . $loginType . ':' . $id);
            }
        }
    }

    protected static function getClientIp(): ?string
    {
        $request = SaTokenContext::getRequest();
        if ($request === null) {
            return null;
        }

        if ($request instanceof \Psr\Http\Message\ServerRequestInterface) {
            $serverParams = $request->getServerParams();
            return $serverParams['REMOTE_ADDR'] ?? null;
        }

        if (method_exists($request, 'getHeaderLine')) {
            $ip = $request->getHeaderLine('X-Forwarded-For');
            if (!empty($ip)) {
                return explode(',', $ip)[0];
            }
            $ip = $request->getHeaderLine('X-Real-IP');
            if (!empty($ip)) {
                return $ip;
            }
        }

        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            if (isset($headers['X-Forwarded-For'])) {
                return explode(',', $headers['X-Forwarded-For'])[0];
            }
            if (isset($headers['X-Real-IP'])) {
                return $headers['X-Real-IP'];
            }
        }

        return null;
    }

    public static function reset(): void
    {
        self::$keyPrefix = 'satoken:audit:';
        self::$enabled = false;
        self::$maxEntries = 1000;
        self::$ttlDays = 30;
    }
}
