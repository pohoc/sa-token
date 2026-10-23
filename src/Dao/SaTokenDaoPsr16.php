<?php

declare(strict_types=1);

namespace SaToken\Dao;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;
use SaToken\Exception\SaTokenException;

/**
 * PSR-16 adapter with host-local file locks for atomic DAO operations.
 * A cache shared by multiple hosts still requires a distributed atomic DAO.
 */
class SaTokenDaoPsr16 implements SaTokenDaoInterface, SaTokenDaoCompareAndDeleteInterface
{
    protected CacheInterface $cache;

    protected SaTokenDaoFile $atomicLockDao;

    /** @var array<string, int> */
    protected array $ttlMap = [];

    protected int $createdAt;

    public function __construct(CacheInterface $cache, ?string $lockDirectory = null)
    {
        $this->cache = $cache;
        $this->createdAt = time();
        $uid = function_exists('posix_geteuid') ? (string) posix_geteuid() : (string) getmyuid();
        $defaultLockDirectory = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR . 'sa-token-psr16-' . hash('sha256', $uid);
        $this->atomicLockDao = new SaTokenDaoFile($lockDirectory ?? $defaultLockDirectory);
    }

    public function get(string $key): ?string
    {
        try {
            $value = $this->cache->get($this->normalizeKey($key));
            if ($value === null) {
                return null;
            }
            if (is_string($value)) {
                return $value;
            }
            if (is_scalar($value)) {
                return (string) $value;
            }
            return null;
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    public function set(string $key, string $value, ?int $timeout = null): void
    {
        $this->withAtomicLock($key, function () use ($key, $value, $timeout): void {
            if (!$this->writeCache($key, $value, $timeout)) {
                throw new SaTokenException('PSR-16 缓存写入失败');
            }
        });
    }

    protected function writeCache(string $key, string $value, ?int $timeout): bool
    {
        $effectiveTimeout = $timeout !== null && $timeout > 0 ? $timeout : null;
        try {
            if (!$this->cache->set($this->normalizeKey($key), $value, $effectiveTimeout)) {
                return false;
            }
            if ($effectiveTimeout !== null) {
                $this->ttlMap[$key] = time() + $effectiveTimeout;
            } else {
                unset($this->ttlMap[$key]);
            }
            return true;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public function update(string $key, string $value): void
    {
        $this->withAtomicLock($key, function () use ($key, $value): void {
            $ttl = $this->getTimeout($key);
            if ($ttl === -2) {
                return;
            }
            $timeout = ($ttl === -1) ? null : $ttl;
            if (!$this->writeCache($key, $value, $timeout)) {
                throw new SaTokenException('PSR-16 缓存更新失败');
            }
        });
    }

    public function delete(string $key): void
    {
        $this->withAtomicLock($key, fn () => $this->deleteCache($key));
    }

    protected function deleteCache(string $key): bool
    {
        try {
            $deleted = $this->cache->delete($this->normalizeKey($key));
            if ($deleted) {
                unset($this->ttlMap[$key]);
            }
            return $deleted;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public function getTimeout(string $key): int
    {
        if (isset($this->ttlMap[$key])) {
            $remaining = $this->ttlMap[$key] - time();
            if ($remaining <= 0) {
                unset($this->ttlMap[$key]);
                return -2;
            }
            return $remaining;
        }

        if (!$this->exists($key)) {
            return -2;
        }
        return -1;
    }

    public function expire(string $key, int $timeout): void
    {
        $this->withAtomicLock($key, function () use ($key, $timeout): void {
            $value = $this->get($key);
            if ($value !== null && !$this->writeCache($key, $value, $timeout > 0 ? $timeout : null)) {
                throw new SaTokenException('PSR-16 缓存过期时间更新失败');
            }
        });
    }

    public function getAndExpire(string $key, int $timeout): ?string
    {
        return $this->withAtomicLock($key, function () use ($key, $timeout): ?string {
            $value = $this->get($key);
            if ($value !== null && !$this->writeCache($key, $value, $timeout > 0 ? $timeout : null)) {
                throw new SaTokenException('PSR-16 缓存过期时间更新失败');
            }
            return $value;
        });
    }

    public function getAndDelete(string $key): ?string
    {
        return $this->withAtomicLock($key, function () use ($key): ?string {
            $value = $this->get($key);
            if ($value === null) {
                return null;
            }
            return $this->deleteCache($key) ? $value : null;
        });
    }

    public function exists(string $key): bool
    {
        try {
            return $this->cache->has($this->normalizeKey($key));
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public function deleteMultiple(array $keys): void
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
    }

    public function size(): int
    {
        return -1;
    }

    public function search(string $prefix, string $keyword, int $start, int $size): array
    {
        return [];
    }

    public function searchKeys(string $prefix, string $keyword, int $start, int $size): array
    {
        return [];
    }

    public function setIfNotExists(string $key, string $value, ?int $timeout = null): bool
    {
        return $this->withAtomicLock($key, function () use ($key, $value, $timeout): bool {
            if ($this->exists($key)) {
                return false;
            }
            return $this->writeCache($key, $value, $timeout);
        });
    }

    /** PSR-16 reserves punctuation used in Sa-Token's internal namespaces. */
    protected function normalizeKey(string $key): string
    {
        return 'sat_' . substr(hash('sha256', $key), 0, 60);
    }

    public function increment(string $key, int $amount = 1, ?int $timeout = null): int
    {
        return $this->withAtomicLock($key, function () use ($key, $amount, $timeout): int {
            $current = $this->get($key);
            $newValue = max(0, ($current === null ? 0 : (int) $current) + $amount);
            $effectiveTimeout = $current === null ? $timeout : $this->getTimeout($key);
            $writeTimeout = $effectiveTimeout !== null && $effectiveTimeout >= 0
                ? max(1, $effectiveTimeout)
                : null;
            if (!$this->writeCache($key, (string) $newValue, $writeTimeout)) {
                throw new SaTokenException('PSR-16 计数器更新失败');
            }
            return $newValue;
        });
    }

    public function compareAndDelete(string $key, string $expectedValue): bool
    {
        return $this->withAtomicLock($key, function () use ($key, $expectedValue): bool {
            if ($this->get($key) !== $expectedValue) {
                return false;
            }
            return $this->deleteCache($key);
        });
    }

    /**
     * PSR-16 has no atomic primitives; a fixed set of host-local file locks
     * makes DAO operations atomic across PHP processes on this host. Deployments
     * sharing the cache across hosts must use a shared atomic DAO such as Redis.
     * @template T
     * @param  callable(): T $operation
     * @return T
     */
    protected function withAtomicLock(string $key, callable $operation): mixed
    {
        $stripe = hexdec(substr(hash('sha256', $key), 0, 2)) % 64;
        $lockKey = 'psr16-atomic:' . str_pad((string) $stripe, 2, '0', STR_PAD_LEFT);
        $lockValue = bin2hex(random_bytes(16));
        $acquired = false;
        for ($attempt = 0; $attempt < 100; $attempt++) {
            if ($this->atomicLockDao->setIfNotExists($lockKey, $lockValue, 60)) {
                $acquired = true;
                break;
            }
            usleep(10000);
        }
        if (!$acquired) {
            throw new SaTokenException('PSR-16 缓存原子操作锁获取失败，请稍后重试');
        }

        try {
            return $operation();
        } finally {
            $this->atomicLockDao->compareAndDelete($lockKey, $lockValue);
        }
    }
}
