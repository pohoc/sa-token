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
class SaTokenDaoPsr16 implements SaTokenDaoInterface, SaTokenDaoCompareAndDeleteInterface, SaTokenDaoCompareAndExpireInterface, SaTokenDaoCompareAndSetInterface, SaTokenDaoCompareAndUpdateInterface, SaTokenDaoDeleteIfExpiredInterface
{
    protected const RECORD_PREFIX = "\0sa-token-psr16:v1\n";

    protected CacheInterface $cache;

    protected SaTokenDaoFile $atomicLockDao;

    public function __construct(CacheInterface $cache, ?string $lockDirectory = null)
    {
        $this->cache = $cache;
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

            if (is_string($value) && str_starts_with($value, self::RECORD_PREFIX)) {
                $record = $this->decodeCacheRecord($value);
                if ($record === null || ($record['expiresAt'] !== null && $record['expiresAt'] <= time())) {
                    return null;
                }
                return $record['value'];
            }

            $expiresAt = $this->getSharedExpiresAt($key);
            if ($expiresAt !== null && $expiresAt <= time()) {
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
        $expiresAt = $effectiveTimeout !== null ? time() + $effectiveTimeout : null;
        return $this->writeCacheRecord($key, $value, $expiresAt, $effectiveTimeout);
    }

    protected function writeCacheRecord(string $key, string $value, ?int $expiresAt, ?int $backendTimeout): bool
    {
        try {
            $json = json_encode([
                'value' => base64_encode($value),
                'expiresAt' => $expiresAt,
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if (!is_string($json)) {
                return false;
            }
            $encoded = self::RECORD_PREFIX . $json;
            if (!$this->cache->set($this->normalizeKey($key), $encoded, $backendTimeout)) {
                return false;
            }
            $ttlMetadata = $expiresAt !== null ? (string) $expiresAt : 'permanent';
            if (!$this->cache->set($this->normalizeTtlKey($key), $ttlMetadata, $backendTimeout)) {
                $this->cache->delete($this->normalizeKey($key));
                return false;
            }
            return true;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public function update(string $key, string $value): void
    {
        $this->withAtomicLock($key, function () use ($key, $value): void {
            if (!$this->updateCachePreservingTtl($key, $value)) {
                throw new SaTokenException('PSR-16 缓存更新失败');
            }
        });
    }

    protected function updateCachePreservingTtl(string $key, string $value): bool
    {
        try {
            $cacheKey = $this->normalizeKey($key);
            $storedValue = $this->cache->get($cacheKey);
            if ($storedValue === null) {
                return true;
            }

            if (is_string($storedValue) && str_starts_with($storedValue, self::RECORD_PREFIX)) {
                $record = $this->decodeCacheRecord($storedValue);
                if ($record === null) {
                    $this->deleteCache($key);
                    return true;
                }
                $expiresAt = $record['expiresAt'];
                if ($expiresAt === null) {
                    return $this->writeCache($key, $value, null);
                }
                $remaining = $expiresAt - time();
                if ($remaining <= 0) {
                    $this->deleteCache($key);
                    return true;
                }
                // Keep the absolute expiry embedded in the value. TTL metadata
                // is a compatibility index and may be evicted independently.
                return $this->writeCacheRecord($key, $value, $expiresAt, $remaining + 1);
            }

            $metadata = $this->cache->get($this->normalizeTtlKey($key));
            if ($metadata === null) {
                // A legacy value without its sidecar has unknown lifetime. Do
                // not turn an evicted TTL record into a permanent credential.
                $this->deleteCache($key);
                return true;
            }
            if ($metadata === 'permanent') {
                // Explicit permanent metadata retains legacy permanent semantics.
                return $this->writeCache($key, $value, null);
            }
            if (!is_string($metadata) || !ctype_digit($metadata)) {
                $this->deleteCache($key);
                return true;
            }

            $expiresAt = (int) $metadata;
            $remaining = $expiresAt - time();
            if ($remaining <= 0) {
                $this->deleteCache($key);
                return true;
            }

            // Round up the backend TTL so its physical expiry cannot precede
            // the exact shared expiry recorded in metadata.
            return $this->writeCacheRecord($key, $value, $expiresAt, $remaining + 1);
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public function delete(string $key): void
    {
        $this->withAtomicLock($key, fn () => $this->deleteCache($key));
    }

    protected function deleteCache(string $key): bool
    {
        try {
            $deleted = $this->cache->delete($this->normalizeKey($key));
            $this->cache->delete($this->normalizeTtlKey($key));
            return $deleted;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public function getTimeout(string $key): int
    {
        try {
            $storedValue = $this->cache->get($this->normalizeKey($key));
            if ($storedValue === null) {
                return -2;
            }
            if (is_string($storedValue) && str_starts_with($storedValue, self::RECORD_PREFIX)) {
                $record = $this->decodeCacheRecord($storedValue);
                if ($record === null) {
                    return -2;
                }
                if ($record['expiresAt'] === null) {
                    return -1;
                }
                $remaining = $record['expiresAt'] - time();
                return $remaining > 0 ? $remaining : -2;
            }

            $expiresAt = $this->getSharedExpiresAt($key);
            if ($expiresAt === null) {
                // Missing metadata is treated as legacy/permanent for compatibility.
                return -1;
            }
            $remaining = $expiresAt - time();
            return $remaining > 0 ? $remaining : -2;
        } catch (InvalidArgumentException) {
            return -1;
        }
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
            $storedValue = $this->cache->get($this->normalizeKey($key));
            if ($storedValue === null) {
                return false;
            }

            if (is_string($storedValue) && str_starts_with($storedValue, self::RECORD_PREFIX)) {
                $record = $this->decodeCacheRecord($storedValue);
                return $record !== null && ($record['expiresAt'] === null || $record['expiresAt'] > time());
            }

            $expiresAt = $this->getSharedExpiresAt($key);
            return $expiresAt === null || $expiresAt > time();
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    protected function getSharedExpiresAt(string $key): ?int
    {
        $value = $this->cache->get($this->normalizeTtlKey($key));
        if ($value === null) {
            // A missing sidecar cannot distinguish a legacy permanent value
            // from an expired legacy value whose metadata was evicted.
            return 0;
        }
        if ($value === 'permanent') {
            return null;
        }
        if (!is_string($value) || !ctype_digit($value)) {
            return 0;
        }
        return (int) $value;
    }

    /** @return array{value: string, expiresAt: int|null}|null */
    protected function decodeCacheRecord(string $value): ?array
    {
        if (!str_starts_with($value, self::RECORD_PREFIX)) {
            return null;
        }

        $record = json_decode(substr($value, strlen(self::RECORD_PREFIX)), true);
        if (!is_array($record)
            || !is_string($record['value'] ?? null)
            || (!array_key_exists('expiresAt', $record))
            || ($record['expiresAt'] !== null && !is_int($record['expiresAt']))) {
            return null;
        }

        $decodedValue = base64_decode($record['value'], true);
        if ($decodedValue === false) {
            return null;
        }

        return ['value' => $decodedValue, 'expiresAt' => $record['expiresAt']];
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

    /** TTL metadata uses a disjoint physical namespace from user values. */
    protected function normalizeTtlKey(string $key): string
    {
        return 'sat_ttl_' . substr(hash('sha256', $key), 0, 56);
    }

    public function increment(string $key, int $amount = 1, ?int $timeout = null): int
    {
        return $this->withAtomicLock($key, function () use ($key, $amount, $timeout): int {
            $current = $this->get($key);
            $effectiveTimeout = $current === null ? $timeout : $this->getTimeout($key);
            $newValue = max(0, ($current === null || $effectiveTimeout === -2 ? 0 : (int) $current) + $amount);
            if ($effectiveTimeout === -2) {
                $this->deleteCache($key);
                $effectiveTimeout = $timeout;
            }
            $writeTimeout = $effectiveTimeout !== null && $effectiveTimeout > 0
                ? $effectiveTimeout
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

    public function compareAndExpire(string $key, string $expectedValue, int $timeout): bool
    {
        if ($timeout !== -1 && $timeout <= 0) {
            return false;
        }

        return $this->withAtomicLock($key, function () use ($key, $expectedValue, $timeout): bool {
            if ($this->get($key) !== $expectedValue) {
                return false;
            }

            $currentTimeout = $this->getTimeout($key);
            if ($currentTimeout === -2) {
                // The cache value may have expired after the value comparison
                // but before this TTL read. Never turn that stale snapshot into
                // a fresh cache entry.
                return false;
            }
            if ($currentTimeout === -1) {
                return true;
            }
            if ($timeout === -1) {
                return $this->writeCache($key, $expectedValue, null);
            }
            if ($currentTimeout >= $timeout) {
                return true;
            }

            return $this->writeCache($key, $expectedValue, $timeout);
        });
    }

    public function compareAndSet(string $key, ?string $expectedValue, ?string $newValue, ?int $timeout = null): bool
    {
        return $this->withAtomicLock($key, function () use ($key, $expectedValue, $newValue, $timeout): bool {
            if ($this->get($key) !== $expectedValue) {
                return false;
            }
            if ($newValue === null) {
                return $this->deleteCache($key);
            }
            return $this->writeCache($key, $newValue, $timeout);
        });
    }

    public function compareAndUpdate(string $key, string $expectedValue, string $newValue): bool
    {
        return $this->withAtomicLock($key, function () use ($key, $expectedValue, $newValue): bool {
            if ($this->get($key) !== $expectedValue) {
                return false;
            }

            try {
                return $this->updateCachePreservingTtl($key, $newValue);
            } catch (InvalidArgumentException) {
                return false;
            }
        });
    }

    public function deleteIfExpired(string $key): bool
    {
        return $this->withAtomicLock($key, function () use ($key): bool {
            try {
                $storedValue = $this->cache->get($this->normalizeKey($key));
                if ($storedValue === null) {
                    return false;
                }
                if (is_string($storedValue) && str_starts_with($storedValue, self::RECORD_PREFIX)) {
                    $record = $this->decodeCacheRecord($storedValue);
                    if ($record === null) {
                        return $this->deleteCache($key);
                    }
                    return $record['expiresAt'] !== null
                        && $record['expiresAt'] <= time()
                        && $this->deleteCache($key);
                }
                $expiresAt = $this->getSharedExpiresAt($key);
                if ($expiresAt === null || $expiresAt > time()) {
                    return false;
                }
                return $this->deleteCache($key);
            } catch (InvalidArgumentException) {
                return false;
            }
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
        return $this->atomicLockDao->executeAtomically($lockKey, $operation);
    }
}
