<?php

declare(strict_types=1);

namespace SaToken\Dao;

/**
 * Optional atomic capability used by sweepers to remove expired records safely.
 */
interface SaTokenDaoDeleteIfExpiredInterface
{
    /**
     * Delete a key only if its expiration has passed at the time of deletion.
     */
    public function deleteIfExpired(string $key): bool;
}
