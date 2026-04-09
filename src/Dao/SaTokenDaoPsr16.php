<?php

declare(strict_types=1);

namespace SaToken\Dao;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

/**
 * PSR-16 Cache 适配器
 *
 * 将框架的 PSR-16 Cache 适配为 SaTokenDaoInterface，优先使用此适配器对接框架缓存
 *
 * 使用示例：
 *   $psr16Cache = new SomeFrameworkCache(); // 实现了 CacheInterface
 *   $dao = new SaTokenDaoPsr16($psr16Cache);
 *   $dao->set('key', 'value', 3600);
 */
class SaTokenDaoPsr16 implements SaTokenDaoInterface
{
    /**
     * @param CacheInterface $cache PSR-16 缓存实现
     */
    public function __construct(
        protected CacheInterface $cache
    ) {
    }

    /**
     * @inheritdoc
     */
    public function get(string $key): ?string
    {
        try {
            $value = $this->cache->get($key);
            return $value === null ? null : (string) $value;
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    /**
     * @inheritdoc
     */
    public function set(string $key, string $value, ?int $timeout = null): void
    {
        try {
            $this->cache->set($key, $value, $timeout);
        } catch (InvalidArgumentException) {
            // ignore
        }
    }

    /**
     * @inheritdoc
     */
    public function update(string $key, string $value): void
    {
        $ttl = $this->getTimeout($key);
        if ($ttl === -2) {
            return;
        }
        $timeout = ($ttl === -1) ? null : $ttl;
        $this->set($key, $value, $timeout);
    }

    /**
     * @inheritdoc
     */
    public function delete(string $key): void
    {
        try {
            $this->cache->delete($key);
        } catch (InvalidArgumentException) {
            // ignore
        }
    }

    /**
     * @inheritdoc
     *
     * 注意：PSR-16 不提供获取剩余 TTL 的标准方法，此实现返回近似值
     */
    public function getTimeout(string $key): int
    {
        if (!$this->exists($key)) {
            return -2;
        }
        // PSR-16 无法获取剩余 TTL，默认返回 -1（永不过期）
        // 子类可重写此方法以提供更精确的实现
        return -1;
    }

    /**
     * @inheritdoc
     */
    public function expire(string $key, int $timeout): void
    {
        $value = $this->get($key);
        if ($value !== null) {
            $this->set($key, $value, $timeout > 0 ? $timeout : null);
        }
    }

    /**
     * @inheritdoc
     */
    public function getAndExpire(string $key, int $timeout): ?string
    {
        $value = $this->get($key);
        if ($value !== null) {
            $this->expire($key, $timeout);
        }
        return $value;
    }

    /**
     * @inheritdoc
     */
    public function exists(string $key): bool
    {
        try {
            return $this->cache->has($key);
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    /**
     * @inheritdoc
     *
     * 注意：PSR-16 不提供统计总数的方法，此实现返回 -1 表示不支持
     */
    public function size(): int
    {
        return -1;
    }
}
