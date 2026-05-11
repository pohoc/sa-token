<?php

declare(strict_types=1);

namespace SaToken\Session;

use SaToken\Dao\SaTokenDaoInterface;
use SaToken\SaToken;

class SaSessionCleaner
{
    protected static bool $running = false;
    protected static bool $stopped = false;
    protected static int $intervalSeconds = 3600;
    protected static int $batchSize = 100;
    protected static int $totalCleaned = 0;

    public static function setInterval(int $seconds): void
    {
        self::$intervalSeconds = $seconds;
    }

    public static function setBatchSize(int $size): void
    {
        self::$batchSize = $size;
    }

    public static function isRunning(): bool
    {
        return self::$running;
    }

    public static function getTotalCleaned(): int
    {
        return self::$totalCleaned;
    }

    public static function cleanOnce(): int
    {
        $dao = SaToken::getDao();
        $cleaned = 0;

        $cleaned += self::cleanTokens($dao);
        $cleaned += self::cleanSessions($dao);
        $cleaned += self::cleanTokenSessions($dao);

        self::$totalCleaned += $cleaned;
        return $cleaned;
    }

    protected static function cleanTokens(SaTokenDaoInterface $dao): int
    {
        $pattern = 'satoken:login:token:';
        $results = $dao->search($pattern, '', 0, self::$batchSize);
        $cleaned = 0;

        foreach ($results as $value) {
            if ($value === '') {
                continue;
            }
            $data = @json_decode($value, true);
            if (!is_array($data)) {
                continue;
            }
            $expireAt = $data['expireAt'] ?? null;
            if ($expireAt !== null && $expireAt > 0 && $expireAt < time()) {
                $token = $data['tokenValue'] ?? '';
                if ($token !== '') {
                    $key = $pattern . $token;
                    $dao->delete($key);
                    $loginId = $data['loginId'] ?? null;
                    if ($loginId !== null) {
                        $dao->delete('satoken:login:token:list:' . $loginId . ':' . $token);
                    }
                    $cleaned++;
                }
            }
        }

        return $cleaned;
    }

    protected static function cleanSessions(SaTokenDaoInterface $dao): int
    {
        $pattern = 'satoken:session:';
        $results = $dao->search($pattern, '', 0, self::$batchSize);
        $cleaned = 0;

        foreach ($results as $value) {
            if ($value === '') {
                continue;
            }
            $data = @json_decode($value, true);
            if (!is_array($data)) {
                continue;
            }
            $expireAt = $data['expireAt'] ?? null;
            if ($expireAt !== null && $expireAt > 0 && $expireAt < time()) {
                $sessionId = $data['id'] ?? '';
                if ($sessionId !== '') {
                    $dao->delete($pattern . $sessionId);
                    $cleaned++;
                }
            }
        }

        return $cleaned;
    }

    protected static function cleanTokenSessions(SaTokenDaoInterface $dao): int
    {
        $pattern = 'satoken:tokenSession:';
        $results = $dao->search($pattern, '', 0, self::$batchSize);
        $cleaned = 0;

        foreach ($results as $value) {
            if ($value === '') {
                continue;
            }
            $data = @json_decode($value, true);
            if (!is_array($data)) {
                continue;
            }
            $expireAt = $data['expireAt'] ?? null;
            if ($expireAt !== null && $expireAt > 0 && $expireAt < time()) {
                $sessionId = $data['id'] ?? '';
                if ($sessionId !== '') {
                    $dao->delete($pattern . $sessionId);
                    $cleaned++;
                }
            }
        }

        return $cleaned;
    }

    public static function start(): void
    {
        if (self::$running) {
            return;
        }
        self::$running = true;
        self::$stopped = false;

        while (!self::$stopped) {
            self::cleanOnce();
            sleep(self::$intervalSeconds);
        }
        self::$running = false;
        return;
    }

    public static function stop(): void
    {
        self::$stopped = true;
    }

    public static function reset(): void
    {
        self::$running = false;
        self::$stopped = false;
        self::$totalCleaned = 0;
    }
}
