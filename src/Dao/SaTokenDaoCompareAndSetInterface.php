<?php

declare(strict_types=1);

namespace SaToken\Dao;

/** 原子地仅当当前值仍等于快照时替换或删除记录；null 表示记录不存在。 */
interface SaTokenDaoCompareAndSetInterface
{
    public function compareAndSet(string $key, ?string $expectedValue, ?string $newValue, ?int $timeout = null): bool;
}
