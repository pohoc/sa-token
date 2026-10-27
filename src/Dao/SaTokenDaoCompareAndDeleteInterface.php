<?php

declare(strict_types=1);

namespace SaToken\Dao;

/**
 * 可选 DAO 扩展：仅当键值仍匹配时原子删除。
 *
 * 任何使用带租约互斥锁的操作都要求 DAO 实现此接口；不支持时应在获取锁前失败，
 * 禁止用“先读取再删除”模拟，因为租约过期后可能误删新持有者的锁。
 */
interface SaTokenDaoCompareAndDeleteInterface
{
    public function compareAndDelete(string $key, string $expectedValue): bool;
}
