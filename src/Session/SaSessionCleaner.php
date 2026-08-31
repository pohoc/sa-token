<?php

declare(strict_types=1);

namespace SaToken\Session;

use SaToken\Dao\SaTokenDaoInterface;
use SaToken\SaToken;

/**
 * 会话记录清理器
 *
 * 职责：回收"存储后端未自动删除的已过期会话记录"。
 *
 * 内置存储后端（Redis EXPIRE / 内存惰性过期）会自动回收过期记录，
 * 但自定义 DAO（如数据库存储）可能只按 TTL 提供读取过滤而从不物理删除。
 *
 * 安全设计：判断过期只依据 DAO 自身的 TTL 元数据（getTimeout），
 * 绝不解析存储值内容（值可能是密文，且信任值内字段可被诱导删除任意键）
 */
class SaSessionCleaner
{
    protected static bool $running = false;
    protected static bool $stopped = false;
    protected static int $intervalSeconds = 3600;
    protected static int $batchSize = 100;
    protected static int $totalCleaned = 0;

    /** @var array<string> */
    protected static array $sweptPrefixes = [
        'satoken:login:token:',
        'satoken:login:lastActive:',
        'satoken:login:loginId:',
        'satoken:session:',
        'satoken:session:lock:',
        'satoken:tokenSession:',
        'satoken:refresh:',
        'satoken:refreshMap:',
        'satoken:fingerprint:',
        'satoken:blacklist:',
        'satoken:switch:',
        'satoken:safe:',
        'satoken:disable:',
        'satoken:sign:nonce:',
        'satoken:auth:digest:nonce:',
        'satoken:security:brute:',
        'satoken:security:device:',
        'satoken:sensitive:',
        'oauth2:code:',
        'oauth2:at:',
        'oauth2:rt:',
        'oauth2:rt:used:',
        'oauth2:client:fail:',
        'satoken:audit:',
    ];

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

        foreach (self::$sweptPrefixes as $prefix) {
            $cleaned += self::sweepExpired($dao, $prefix);
        }

        self::$totalCleaned += $cleaned;
        return $cleaned;
    }

    /**
     * 删除 TTL 已到期但存储后端未回收的记录。
     *
     * getTimeout 语义：>0 剩余秒数，-1 永不过期（保留），-2 不存在；
     * 等于 0（或负值）表示已到期仍未被后端回收，需要显式删除
     */
    protected static function sweepExpired(SaTokenDaoInterface $dao, string $prefix): int
    {
        $keys = $dao->searchKeys($prefix, '', 0, self::$batchSize);
        $cleaned = 0;

        foreach ($keys as $key) {
            if ($key === '') {
                continue;
            }
            $ttl = $dao->getTimeout($key);
            if ($ttl !== -1 && $ttl !== -2 && $ttl <= 0) {
                $dao->delete($key);
                $cleaned++;
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

        // stop() 由其他进程/协程调用，静态分析无法观察到静态属性的跨请求变更
        while (true) { // @phpstan-ignore-line
            if (self::$stopped) { // @phpstan-ignore-line
                self::$running = false;
                break;
            }
            self::cleanOnce();
            sleep(self::$intervalSeconds);
        }
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
