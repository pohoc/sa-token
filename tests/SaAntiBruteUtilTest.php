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
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.1'));
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

    public function testSourceFailureLimitBoundsCountersAcrossRandomAccounts(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 0,
            'antiBruteIpMaxFailures' => 2,
            'antiBruteLockDuration' => 600,
        ]));
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.50'));

        SaAntiBruteUtil::recordFailure('random-user-1');
        SaAntiBruteUtil::recordFailure('random-user-2');

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('当前来源失败次数过多');
        SaAntiBruteUtil::checkAndThrow('random-user-3');
    }

    public function testSourceFailureLimitIsIsolatedByIpAndLoginType(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteIpMaxFailures' => 1,
            'antiBruteLockDuration' => 600,
        ]));
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.50'));
        SaAntiBruteUtil::recordFailure('random-user', 'login');

        SaTokenContext::setRequest($this->requestFromIp('192.0.2.51'));
        SaAntiBruteUtil::checkAndThrow('random-user', 'login');
        $this->assertSame(0, SaAntiBruteUtil::getFailCount('random-user', 'login'));

        SaTokenContext::setRequest($this->requestFromIp('192.0.2.50'));
        SaAntiBruteUtil::checkAndThrow('random-user', 'admin');
        $this->assertSame(0, SaAntiBruteUtil::getFailCount('random-user', 'admin'));
    }

    public function testUnknownIpDoesNotCreateSharedSourceLockout(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteIpMaxFailures' => 1,
            'antiBruteLockDuration' => 600,
        ]));
        SaTokenContext::setRequest(null);

        try {
            SaAntiBruteUtil::checkAndThrow('victim-account');
            $this->fail('启用防暴力限制时无法识别来源 IP 必须拒绝认证');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无法识别客户端 IP', $e->getMessage());
        }

        try {
            SaAntiBruteUtil::recordFailure('victim-account');
            $this->fail('无法识别来源 IP 时不得把失败写入共享 unknown 账号桶');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无法识别客户端 IP', $e->getMessage());
        }

        $this->assertFalse(SaAntiBruteUtil::isAccountLocked('victim-account'));
        $this->assertSame(0, SaAntiBruteUtil::getFailCount('victim-account'));
    }

    public function testUnknownIpIsAllowedWhenBruteProtectionIsDisabled(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 0,
            'antiBruteIpMaxFailures' => 0,
        ]));
        SaTokenContext::setRequest(null);

        SaAntiBruteUtil::checkAndThrow('account');
        SaAntiBruteUtil::recordFailure('account');

        $this->assertSame(1, SaAntiBruteUtil::getFailCount('account'));
        $this->assertFalse(SaAntiBruteUtil::isAccountLocked('account'));
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
