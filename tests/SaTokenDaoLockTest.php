<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoInterface;
use SaToken\Dao\SaTokenDaoLock;
use SaToken\Exception\SaTokenException;

class SaTokenDaoLockTest extends TestCase
{
    public function testAcquireFailsBeforeWritingWhenDaoCannotReleaseLeasedLocksAtomically(): void
    {
        $dao = $this->createMock(SaTokenDaoInterface::class);
        $dao->expects(self::never())->method('setIfNotExists');

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('必须实现 SaTokenDaoCompareAndDeleteInterface');

        SaTokenDaoLock::acquire($dao, 'lock:key', 'owner', 5);
    }
}
