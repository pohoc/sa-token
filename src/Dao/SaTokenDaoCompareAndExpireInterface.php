<?php

declare(strict_types=1);

namespace SaToken\Dao;

/**
 * 可选 DAO 扩展：仅当键值仍匹配时原子延长过期时间，绝不缩短现有 TTL。
 * timeout 为 -1 时将键永久保留。
 *
 * 持有者在租约过期后不得续租新持有者的锁，因此比较和续租必须由 DAO 原子完成。
 */
interface SaTokenDaoCompareAndExpireInterface
{
    public function compareAndExpire(string $key, string $expectedValue, int $timeout): bool;
}
