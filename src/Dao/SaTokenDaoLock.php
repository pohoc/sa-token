<?php

declare(strict_types=1);

namespace SaToken\Dao;

use SaToken\Exception\SaTokenException;

/**
 * 带租约的互斥锁操作。
 *
 * compareAndDelete 是安全释放租约锁的必要能力：仅靠先读后删无法避免
 * 持有者租约过期后误删后续持有者的锁。
 */
final class SaTokenDaoLock
{
    public static function acquire(SaTokenDaoInterface $dao, string $key, string $owner, ?int $ttl): bool
    {
        if (!$dao instanceof SaTokenDaoCompareAndDeleteInterface) {
            throw new SaTokenException('DAO 必须实现 SaTokenDaoCompareAndDeleteInterface 才能安全使用租约锁');
        }

        return $dao->setIfNotExists($key, $owner, $ttl);
    }

    public static function release(SaTokenDaoInterface $dao, string $key, string $owner): void
    {
        if ($dao instanceof SaTokenDaoCompareAndDeleteInterface) {
            $dao->compareAndDelete($key, $owner);
        }
    }

    public static function renew(SaTokenDaoInterface $dao, string $key, string $owner, int $ttl): bool
    {
        if ($ttl <= 0 || !$dao instanceof SaTokenDaoCompareAndExpireInterface) {
            return false;
        }

        return $dao->compareAndExpire($key, $owner, $ttl);
    }
}
