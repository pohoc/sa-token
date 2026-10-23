<?php

declare(strict_types=1);

namespace SaToken\Dao;

/**
 * 可选能力：仅当键值仍匹配时原子删除，用于安全释放带租约的分布式锁。
 */
interface SaTokenDaoCompareAndDeleteInterface
{
    public function compareAndDelete(string $key, string $expectedValue): bool;
}
