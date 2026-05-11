<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Security\SaAntiBruteUtil;

class SaAntiBruteUtilTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setDao(new SaTokenDaoMemory());
        SaAntiBruteUtil::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaAntiBruteUtil::reset();
    }

    public function testIsAccountLockedReturnsFalseInitially(): void
    {
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked('testuser'));
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked('admin'));
    }

    public function testRecordFailureIncrementsCount(): void
    {
        $account = 'testuser';

        SaAntiBruteUtil::recordFailure($account);
        $this->assertEquals(1, SaAntiBruteUtil::getFailCount($account));

        SaAntiBruteUtil::recordFailure($account);
        $this->assertEquals(2, SaAntiBruteUtil::getFailCount($account));

        SaAntiBruteUtil::recordFailure($account);
        $this->assertEquals(3, SaAntiBruteUtil::getFailCount($account));
    }

    public function testIsAccountLockedReturnsTrueAfterLock(): void
    {
        $account = 'testuser';

        SaAntiBruteUtil::lock($account, 'login', 600);
        $this->assertTrue(SaAntiBruteUtil::isAccountLocked($account));
    }

    public function testGetRemainingLockTime(): void
    {
        $account = 'testuser';

        SaAntiBruteUtil::lock($account, 'login', 600);
        $remaining = SaAntiBruteUtil::getRemainingLockTime($account);

        $this->assertGreaterThan(590, $remaining);
        $this->assertLessThanOrEqual(600, $remaining);
    }

    public function testUnlockClearsLock(): void
    {
        $account = 'testuser';

        SaAntiBruteUtil::lock($account, 'login', 600);
        $this->assertTrue(SaAntiBruteUtil::isAccountLocked($account));

        SaAntiBruteUtil::unlock($account, 'login');
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked($account));
    }

    public function testClearFailuresResetsCount(): void
    {
        $account = 'testuser';

        SaAntiBruteUtil::recordFailure($account);
        SaAntiBruteUtil::recordFailure($account);
        SaAntiBruteUtil::recordFailure($account);
        $this->assertEquals(3, SaAntiBruteUtil::getFailCount($account));

        SaAntiBruteUtil::clearFailures($account);
        $this->assertEquals(0, SaAntiBruteUtil::getFailCount($account));
    }

    public function testGetSecurityInfo(): void
    {
        $account = 'testuser';

        $info = SaAntiBruteUtil::getSecurityInfo($account);
        $this->assertArrayHasKey('failCount', $info);
        $this->assertArrayHasKey('isLocked', $info);
        $this->assertArrayHasKey('remainingLockTime', $info);
        $this->assertEquals(0, $info['failCount']);
        $this->assertFalse($info['isLocked']);

        SaAntiBruteUtil::recordFailure($account);
        SaAntiBruteUtil::recordFailure($account);
        $info = SaAntiBruteUtil::getSecurityInfo($account);
        $this->assertEquals(2, $info['failCount']);
    }

    public function testMultipleAccountsAreIndependent(): void
    {
        $accountA = 'user_a';
        $accountB = 'user_b';

        SaAntiBruteUtil::lock($accountA, 'login', 600);
        $this->assertTrue(SaAntiBruteUtil::isAccountLocked($accountA));
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked($accountB));

        SaAntiBruteUtil::unlock($accountA);
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked($accountA));
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked($accountB));
    }

    public function testCheckAndThrowThrowsWhenLocked(): void
    {
        $account = 'testuser';
        SaAntiBruteUtil::lock($account, 'login', 600);

        $this->expectException(SaTokenException::class);
        SaAntiBruteUtil::checkAndThrow($account, 'login');
    }

    public function testCheckAndThrowDoesNotThrowWhenNotLocked(): void
    {
        $account = 'testuser';

        SaAntiBruteUtil::checkAndThrow($account, 'login');
        $this->assertTrue(true);
    }

    public function testDifferentLoginTypesAreIndependent(): void
    {
        $account = 'testuser';

        SaAntiBruteUtil::lock($account, 'login', 600);
        $this->assertTrue(SaAntiBruteUtil::isAccountLocked($account, 'login'));
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked($account, 'admin'));
    }

    public function testGetKeyFormat(): void
    {
        $key = SaAntiBruteUtil::getKey('testuser', 'login');
        $this->assertStringStartsWith('satoken:security:brute:', $key);
        $this->assertStringContainsString('login:', $key);
    }

    public function testCustomKeyPrefix(): void
    {
        SaAntiBruteUtil::setKeyPrefix('custom:prefix:');
        $key = SaAntiBruteUtil::getKey('testuser', 'login');
        $this->assertStringStartsWith('custom:prefix:', $key);
    }
}
