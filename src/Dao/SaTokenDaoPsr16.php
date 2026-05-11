<?php

declare(strict_types=1);

namespace SaToken\Dao;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

class SaTokenDaoPsr16 implements SaTokenDaoInterface
{
    protected CacheInterface $cache;

    protected array $ttlMap = [];

    protected int $createdAt;

    public function __construct(CacheInterface $cache)
    {
        $this->cache = $cache;
        $this->createdAt = time();
    }

    public function get(string $key): ?string
    {
        try {
            $value = $this->cache->get($key);
            return $value === null ? null : (string) $value;
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    public function set(string $key, string $value, ?int $timeout = null): void
    {
        try {
            $this->cache->set($key, $value, $timeout);
            if ($timeout !== null && $timeout > 0) {
                $this->ttlMap[$key] = time() + $timeout;
            } else {
                unset($this->ttlMap[$key]);
            }
        } catch (InvalidArgumentException) {
        }
    }

    public function update(string $key, string $value): void
    {
        $ttl = $this->getTimeout($key);
        if ($ttl === -2) {
            return;
        }
        $timeout = ($ttl === -1) ? null : $ttl;
        $this->set($key, $value, $timeout);
    }

    public function delete(string $key): void
    {
        try {
            $this->cache->delete($key);
            unset($this->ttlMap[$key]);
        } catch (InvalidArgumentException) {
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
        $value = $this->get($key);
        if ($value !== null) {
            $this->set($key, $value, $timeout > 0 ? $timeout : null);
        }
    }

    public function getAndExpire(string $key, int $timeout): ?string
    {
        $value = $this->get($key);
        if ($value !== null) {
            $this->expire($key, $timeout);
        }
        return $value;
    }

    public function getAndDelete(string $key): ?string
    {
        $value = $this->get($key);
        if ($value !== null) {
            $this->delete($key);
        }
        return $value;
    }

    public function exists(string $key): bool
    {
        try {
            return $this->cache->has($key);
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    public function size(): int
    {
        return -1;
    }
}
