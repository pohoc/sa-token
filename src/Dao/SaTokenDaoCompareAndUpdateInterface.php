<?php

declare(strict_types=1);

namespace SaToken\Dao;

/** Atomically replace a value only if it still matches, preserving its TTL. */
interface SaTokenDaoCompareAndUpdateInterface
{
    public function compareAndUpdate(string $key, string $expectedValue, string $newValue): bool;
}
