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
        SaTokenContext::setContextId('default');
        SaTokenContext::clear();
        SaToken::setDao(new SaTokenDaoMemory());
        SaAntiBruteUtil::reset();
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.1'));
    }

    protected function tearDown(): void
    {
        SaTokenContext::setContextId('default');
        SaTokenContext::clear();
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

    public function testStaleFailureCannotRelockAccountAfterConcurrentUnlock(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 1,
            'antiBruteIpMaxFailures' => 0,
            'antiBruteLockDuration' => 600,
        ]));

        $dao = new class () extends SaTokenDaoMemory {
            public bool $unlockAfterFailureIncrement = false;

            public function increment(string $key, int $amount = 1, ?int $timeout = null): int
            {
                $value = parent::increment($key, $amount, $timeout);
                if ($this->unlockAfterFailureIncrement && str_contains($key, ':ip-count:')) {
                    $this->unlockAfterFailureIncrement = false;
                    SaAntiBruteUtil::unlock('unlock-race-account');
                }
                return $value;
            }
        };
        SaToken::setDao($dao);
        $dao->unlockAfterFailureIncrement = true;

        SaAntiBruteUtil::recordFailure('unlock-race-account');

        self::assertFalse(SaAntiBruteUtil::isAccountLocked('unlock-race-account'));
    }

    public function testStaleFailureCannotRelockAccountAfterSuccessfulSourceCleanup(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 1,
            'antiBruteIpMaxFailures' => 0,
            'antiBruteLockDuration' => 600,
        ]));

        $dao = new class () extends SaTokenDaoMemory {
            public bool $pauseAfterFailureIncrement = false;

            public function increment(string $key, int $amount = 1, ?int $timeout = null): int
            {
                $value = parent::increment($key, $amount, $timeout);
                if ($this->pauseAfterFailureIncrement && str_contains($key, ':ip-count:')) {
                    $this->pauseAfterFailureIncrement = false;
                    \Fiber::suspend();
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $makeRequest = fn (): object => $this->requestFromIp('192.0.2.77');
        $fiber = new \Fiber(function () use ($makeRequest): void {
            SaTokenContext::setRequest($makeRequest());
            SaAntiBruteUtil::recordFailure('source-cleanup-race');
        });
        $dao->pauseAfterFailureIncrement = true;

        $fiber->start();
        self::assertTrue($fiber->isSuspended());

        // Successful authentication clears the current account+source state
        // while an earlier failed request is paused before writing its lock.
        SaTokenContext::setRequest($makeRequest());
        SaAntiBruteUtil::clearCurrentSourceFailures('source-cleanup-race');
        $fiber->resume();

        self::assertTrue($fiber->isTerminated());
        self::assertFalse(SaAntiBruteUtil::isAccountLocked('source-cleanup-race'));
        self::assertSame(0, SaAntiBruteUtil::getFailCount('source-cleanup-race'));
    }

    public function testSuccessfulAuthenticationClearsCurrentSourceFailureLock(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 0,
            'antiBruteIpMaxFailures' => 2,
            'antiBruteLockDuration' => 600,
        ]));
        $request = $this->requestFromIp('192.0.2.49');
        SaTokenContext::setRequest($request);

        SaAntiBruteUtil::recordFailure('random-user-1');
        SaAntiBruteUtil::recordFailure('random-user-2');
        try {
            SaAntiBruteUtil::checkAndThrow('valid-user');
            self::fail('来源失败上限应阻止达到阈值后的认证');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('来源失败次数过多', $exception->getMessage());
        }

        // An external credential verifier has authenticated this user. The
        // documented successful-login cleanup must clear this source's state.
        SaAntiBruteUtil::clearCurrentSourceFailures('valid-user');
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.49'));
        SaAntiBruteUtil::checkAndThrow('another-user');
        SaAntiBruteUtil::clearCurrentSourceFailures('another-user');
    }

    public function testStaleSourceFailureCannotRelockAfterSuccessfulCleanup(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 0,
            'antiBruteIpMaxFailures' => 1,
            'antiBruteLockDuration' => 600,
        ]));
        $dao = new class () extends SaTokenDaoMemory {
            public bool $pauseAfterSourceFailureIncrement = false;

            public function increment(string $key, int $amount = 1, ?int $timeout = null): int
            {
                $value = parent::increment($key, $amount, $timeout);
                if ($this->pauseAfterSourceFailureIncrement && str_contains($key, ':source-fail:')) {
                    $this->pauseAfterSourceFailureIncrement = false;
                    \Fiber::suspend();
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $makeRequest = fn (): object => $this->requestFromIp('192.0.2.48');
        $fiber = new \Fiber(function () use ($makeRequest): void {
            SaTokenContext::setRequest($makeRequest());
            SaAntiBruteUtil::recordFailure('stale-source-failure');
        });
        $dao->pauseAfterSourceFailureIncrement = true;
        $fiber->start();
        self::assertTrue($fiber->isSuspended());

        SaTokenContext::setRequest($makeRequest());
        SaAntiBruteUtil::clearCurrentSourceFailures('successful-account');
        $fiber->resume();

        self::assertTrue($fiber->isTerminated());
        SaTokenContext::setRequest($makeRequest());
        SaAntiBruteUtil::checkAndThrow('next-account');
        SaAntiBruteUtil::clearCurrentSourceFailures('next-account');
    }

    public function testSourceGenerationExpiresWithFailureWindow(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 0,
            'antiBruteIpMaxFailures' => 2,
            'antiBruteLockDuration' => 60,
        ]));
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.47'));

        SaAntiBruteUtil::checkAndThrow('valid-user');
        SaAntiBruteUtil::clearCurrentSourceFailures('valid-user');

        $identity = hash('sha256', "login\0" . '192.0.2.47');
        $epochKey = 'satoken:security:brute:source-epoch:' . $identity;
        self::assertGreaterThan(0, $this->daoTimeout($epochKey));
        self::assertLessThanOrEqual(60, $this->daoTimeout($epochKey));
    }

    protected function daoTimeout(string $key): int
    {
        return SaToken::getDao()->getTimeout($key);
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

    public function testConcurrentFailuresDoNotAllocateAccountCountersAfterSourceLimit(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 5,
            'antiBruteIpMaxFailures' => 1,
            'antiBruteLockDuration' => 600,
        ]));

        $makeRequest = fn (): object => $this->requestFromIp('192.0.2.60');
        $first = new \Fiber(function () use ($makeRequest): void {
            SaTokenContext::setRequest($makeRequest());
            SaAntiBruteUtil::checkAndThrow('random-user-1');
            \Fiber::suspend();
            SaAntiBruteUtil::recordFailure('random-user-1');
        });
        $secondDenied = false;
        $second = new \Fiber(function () use ($makeRequest): void {
            SaTokenContext::setRequest($makeRequest());
            try {
                SaAntiBruteUtil::checkAndThrow('random-user-2');
                \Fiber::suspend();
                SaAntiBruteUtil::recordFailure('random-user-2');
            } catch (SaTokenException) {
                // The source cap must reject before another credential check.
            }
        });

        // The configured source cap rejects concurrent requests before they
        // enter credential validation.
        $first->start();
        $second->start();
        $secondDenied = $second->isTerminated();
        $first->resume();
        if ($second->isSuspended()) {
            $second->resume();
        }

        $this->assertTrue($secondDenied);
        SaTokenContext::setRequest($makeRequest());
        $this->assertSame(0, SaAntiBruteUtil::getFailCount('random-user-1'));
        $this->assertSame(0, SaAntiBruteUtil::getFailCount('random-user-2'));
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('当前来源失败次数过多');
        SaAntiBruteUtil::checkAndThrow('random-user-3');
    }

    public function testConcurrentAccountAttemptsAreReservedBeforeCredentialValidation(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 1,
            'antiBruteIpMaxFailures' => 0,
            'antiBruteLockDuration' => 600,
        ]));

        $makeRequest = fn (): object => $this->requestFromIp('192.0.2.61');
        $admitted = 0;
        $fibers = [];
        for ($i = 0; $i < 12; $i++) {
            $fibers[] = new \Fiber(function () use (&$admitted, $makeRequest): void {
                SaTokenContext::setRequest($makeRequest());
                try {
                    SaAntiBruteUtil::checkAndThrow('concurrent-victim');
                    $admitted++;
                    \Fiber::suspend();
                    SaAntiBruteUtil::recordFailure('concurrent-victim');
                } catch (SaTokenException) {
                    // The limit must deny requests before they enter the
                    // credential verifier.
                }
            });
        }

        foreach ($fibers as $fiber) {
            $fiber->start();
        }

        self::assertSame(1, $admitted);
        foreach ($fibers as $fiber) {
            if ($fiber->isSuspended()) {
                $fiber->resume();
            }
        }

        SaTokenContext::setRequest($makeRequest());
        self::assertTrue(SaAntiBruteUtil::isAccountLocked('concurrent-victim'));
        self::assertSame(1, SaAntiBruteUtil::getFailCount('concurrent-victim'));
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

    public function testExpiredSourceReservationCannotReleaseAnotherRequestSlot(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 0,
            'antiBruteIpMaxFailures' => 2,
            'antiBruteLockDuration' => 1,
        ]));
        $ip = '192.0.2.77';

        SaTokenContext::setContextId('slow-auth-request');
        SaTokenContext::setRequest($this->requestFromIp($ip));
        SaAntiBruteUtil::checkAndThrow('slow-account');

        // Let the first request's concurrency lease expire, then admit a new
        // request into the refreshed shared counter.
        sleep(2);
        SaTokenContext::setContextId('new-auth-request');
        SaTokenContext::setRequest($this->requestFromIp($ip));
        SaAntiBruteUtil::checkAndThrow('new-account');

        // The old request now completes. It must not decrement the new
        // request's live reservation merely because the shared key exists.
        SaTokenContext::setContextId('slow-auth-request');
        SaTokenContext::setRequest($this->requestFromIp($ip));
        SaAntiBruteUtil::recordFailure('slow-account');

        SaTokenContext::setContextId('third-auth-request');
        SaTokenContext::setRequest($this->requestFromIp($ip));
        SaAntiBruteUtil::checkAndThrow('third-account');

        SaTokenContext::setContextId('fourth-auth-request');
        SaTokenContext::setRequest($this->requestFromIp($ip));
        $this->expectException(SaTokenException::class);
        SaAntiBruteUtil::checkAndThrow('fourth-account');
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
        $this->assertSame(
            'satoken:security:brute:v2:login:' . hash('sha256', 'testuser'),
            $key
        );
    }

    public function testAccountLockKeysUseDistinctHashAndEscapedLoginType(): void
    {
        $this->assertNotSame(
            SaAntiBruteUtil::getKey('testuser', 'admin:read'),
            SaAntiBruteUtil::getKey('testuser', 'admin')
        );
        $this->assertNotSame(
            SaAntiBruteUtil::getKey('account-a'),
            SaAntiBruteUtil::getKey('account-b')
        );
    }

    public function testCustomKeyPrefix(): void
    {
        SaAntiBruteUtil::setKeyPrefix('custom:prefix:');
        $key = SaAntiBruteUtil::getKey('testuser', 'login');
        $this->assertStringStartsWith('custom:prefix:', $key);
    }
}
