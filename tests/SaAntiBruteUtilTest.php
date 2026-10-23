<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Security\SaAntiBruteUtil;
use SaToken\Util\SaTokenContext;

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

    public function testAutomaticLockoutFromOneIpDoesNotBlockAnotherIp(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 2,
            'antiBruteLockDuration' => 600,
        ]));
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.10'));

        SaAntiBruteUtil::recordFailure('known-account');
        SaAntiBruteUtil::recordFailure('known-account');
        $this->assertTrue(SaAntiBruteUtil::isAccountLocked('known-account'));

        try {
            SaAntiBruteUtil::checkAndThrow('known-account');
            $this->fail('达到阈值的来源 IP 必须受到锁定');
        } catch (SaTokenException $e) {
            $this->assertSame(-10, $e->getCode());
        }

        SaTokenContext::setRequest($this->requestFromIp('192.0.2.20'));
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked('known-account'));
        SaAntiBruteUtil::checkAndThrow('known-account');

        SaTokenContext::setRequest($this->requestFromIp('192.0.2.10'));
        SaAntiBruteUtil::unlock('known-account');
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked('known-account'));
        $this->assertSame(0, SaAntiBruteUtil::getFailCount('known-account'));
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.20'));
        $this->assertSame(0, SaAntiBruteUtil::getFailCount('known-account'));
    }

    public function testManualLockAppliesAcrossSourceIps(): void
    {
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.10'));
        SaAntiBruteUtil::lock('known-account');

        SaTokenContext::setRequest($this->requestFromIp('192.0.2.20'));
        $this->assertTrue(SaAntiBruteUtil::isAccountLocked('known-account'));
        $this->expectException(SaTokenException::class);
        SaAntiBruteUtil::checkAndThrow('known-account');
    }

    protected function requestFromIp(string $ip): object
    {
        return new class ($ip) {
            public function __construct(private string $ip)
            {
            }

            public function getClientIp(): string
            {
                return $this->ip;
            }
        };
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
