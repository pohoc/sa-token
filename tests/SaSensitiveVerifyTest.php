<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\NotSafeException;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Security\SaSensitiveVerify;

class SensitiveVerifyInterleavingDao extends SaTokenDaoMemory
{
    /** @var callable(string, ?string): void|null */
    private $afterNextGet = null;

    private ?string $replaceRateKeyOnStateLock = null;

    public function afterNextGet(callable $callback): void
    {
        $this->afterNextGet = $callback;
    }

    public function replaceRateKeyOnNextStateLock(string $rateKey): void
    {
        $this->replaceRateKeyOnStateLock = $rateKey;
    }

    public function setIfNotExists(string $key, string $value, ?int $timeout = null): bool
    {
        if ($this->replaceRateKeyOnStateLock !== null && str_ends_with($key, ':state-lock')) {
            $rateKey = $this->replaceRateKeyOnStateLock;
            $this->replaceRateKeyOnStateLock = null;
            $this->delete($rateKey);
            $this->set($rateKey, 'another-request-owner', 60);
        }

        return parent::setIfNotExists($key, $value, $timeout);
    }

    public function get(string $key): ?string
    {
        $value = parent::get($key);
        if ($this->afterNextGet !== null) {
            $callback = $this->afterNextGet;
            $this->afterNextGet = null;
            $callback($key, $value);
        }
        return $value;
    }
}

class SaSensitiveVerifyTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setDao(new SaTokenDaoMemory());
        SaSensitiveVerify::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaSensitiveVerify::reset();
    }

    public function testGenerateCodeReturnsNumericString(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $code = SaSensitiveVerify::generateCode($scene, $loginId);

        $this->assertEquals(6, strlen($code));
        $this->assertMatchesRegularExpression('/^\d{6}$/', $code);
    }

    public function testVerifyValidCodeReturnsTrue(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $code = SaSensitiveVerify::generateCode($scene, $loginId);
        $result = SaSensitiveVerify::verifyCode($scene, $code, $loginId);

        $this->assertTrue($result);
    }

    public function testCodeRegenerationCannotInterleaveWithVerification(): void
    {
        $dao = new SensitiveVerifyInterleavingDao();
        SaToken::setDao($dao);
        $scene = 'interleaved-scene';
        $loginId = 10001;
        $oldCode = SaSensitiveVerify::generateCode($scene, $loginId);
        $regenerationWasBlocked = false;
        $key = SaSensitiveVerify::getKey($scene, $loginId);

        $dao->afterNextGet(static function (string $readKey, ?string $ignoredValue) use ($key, $scene, $loginId, &$regenerationWasBlocked): void {
            if ($readKey !== $key) {
                return;
            }
            try {
                SaSensitiveVerify::generateCode($scene, $loginId);
            } catch (SaTokenException $e) {
                $regenerationWasBlocked = str_contains($e->getMessage(), '状态正在更新');
            }
        });

        $this->assertTrue(SaSensitiveVerify::verifyCode($scene, $oldCode, $loginId));
        $this->assertTrue($regenerationWasBlocked);

        $newCode = SaSensitiveVerify::generateCode($scene, $loginId);
        $this->assertFalse(SaSensitiveVerify::isVerified($scene, $loginId));
        $this->assertFalse(SaSensitiveVerify::verifyCode($scene, $oldCode, $loginId));
        $this->assertTrue(SaSensitiveVerify::verifyCode($scene, $newCode, $loginId));
    }

    public function testSendIntervalZeroDisablesRateLimitWithoutCreatingPermanentKey(): void
    {
        SaSensitiveVerify::setSendInterval(0);

        SaSensitiveVerify::sendCode('unlimited-scene', 10001);
        SaSensitiveVerify::sendCode('unlimited-scene', 10001);

        $rateKey = SaSensitiveVerify::getKey('unlimited-scene', 10001) . ':sent';
        $this->assertNull(SaToken::getDao()->get($rateKey));
    }

    public function testFailedSendDoesNotDeleteAnotherRequestsRateLimitReservation(): void
    {
        $dao = new SensitiveVerifyInterleavingDao();
        SaToken::setDao($dao);
        $scene = 'rate-owner-scene';
        $loginId = 10001;
        $key = SaSensitiveVerify::getKey($scene, $loginId);
        $rateKey = $key . ':sent';
        $dao->set($key . ':state-lock', 'existing-owner', 30);
        $dao->replaceRateKeyOnNextStateLock($rateKey);

        try {
            SaSensitiveVerify::sendCode($scene, $loginId);
            $this->fail('已有验证码状态锁时应拒绝发送');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('状态正在更新', $e->getMessage());
        }

        $this->assertSame('another-request-owner', $dao->get($rateKey));
    }

    public function testConcurrentSuccessfulCodeVerificationIsRejectedByAtomicClaim(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;
        $code = SaSensitiveVerify::generateCode($scene, $loginId);

        // Represents another worker having atomically claimed this verification.
        SaToken::getDao()->setIfNotExists(SaSensitiveVerify::getKey($scene, $loginId) . ':verified', '1', 360);

        $this->assertFalse(SaSensitiveVerify::verifyCode($scene, $code, $loginId));
    }

    public function testVerifyWrongCodeReturnsFalse(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        SaSensitiveVerify::generateCode($scene, $loginId);
        $result = SaSensitiveVerify::verifyCode($scene, '000000', $loginId);

        $this->assertFalse($result);
    }

    public function testMaxAttemptsLimitThrowsException(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;
        SaSensitiveVerify::setMaxAttempts(3);

        $code = SaSensitiveVerify::generateCode($scene, $loginId);
        $correctCode = $code;
        $wrongCode = str_pad((string)((int)$correctCode + 1), 6, '0', STR_PAD_LEFT);

        SaSensitiveVerify::verifyCode($scene, $wrongCode, $loginId);
        SaSensitiveVerify::verifyCode($scene, $wrongCode, $loginId);
        SaSensitiveVerify::verifyCode($scene, $wrongCode, $loginId);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('验证码尝试次数过多');
        SaSensitiveVerify::verifyCode($scene, $wrongCode, $loginId);
    }

    public function testIsVerifiedReturnsTrueAfterSuccessfulVerification(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $this->assertFalse(SaSensitiveVerify::isVerified($scene, $loginId));

        $code = SaSensitiveVerify::generateCode($scene, $loginId);
        $this->assertFalse(SaSensitiveVerify::isVerified($scene, $loginId));

        SaSensitiveVerify::verifyCode($scene, $code, $loginId);
        $this->assertTrue(SaSensitiveVerify::isVerified($scene, $loginId));
    }

    public function testClearVerifiedRemovesVerificationStatus(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $code = SaSensitiveVerify::generateCode($scene, $loginId);
        SaSensitiveVerify::verifyCode($scene, $code, $loginId);
        $this->assertTrue(SaSensitiveVerify::isVerified($scene, $loginId));

        SaSensitiveVerify::clearVerified($scene, $loginId);
        $this->assertFalse(SaSensitiveVerify::isVerified($scene, $loginId));
    }

    public function testCreateAndVerifySafeToken(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;
        $loginType = 'login';

        $token = SaSensitiveVerify::createSafeToken($scene, $loginId, $loginType);
        $this->assertEquals(64, strlen($token));

        $result = SaSensitiveVerify::verifySafeToken($scene, $token, $loginId, $loginType);
        $this->assertTrue($result);
    }

    public function testVerifySafeTokenFailsWithWrongToken(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        SaSensitiveVerify::createSafeToken($scene, $loginId);
        $result = SaSensitiveVerify::verifySafeToken($scene, 'wrong-token', $loginId);

        $this->assertFalse($result);
    }

    public function testVerifySafeTokenCanOnlyBeUsedOnce(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $token = SaSensitiveVerify::createSafeToken($scene, $loginId);

        $firstResult = SaSensitiveVerify::verifySafeToken($scene, $token, $loginId);
        $this->assertTrue($firstResult);

        $secondResult = SaSensitiveVerify::verifySafeToken($scene, $token, $loginId);
        $this->assertFalse($secondResult);
    }

    public function testSafeTokenWithoutFullTokenHashIsRejected(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;
        $token = SaSensitiveVerify::createSafeToken($scene, $loginId);
        $key = 'satoken:sensitive:login:safe-token:' . $scene . ':' . md5((string) $loginId) . ':' . substr($token, 0, 16);

        SaToken::getDao()->set($key, json_encode([
            'scene' => $scene,
            'loginId' => (string) $loginId,
            'loginType' => 'login',
            'expiresAt' => time() + 600,
        ]) ?: '{}', 660);

        $this->assertFalse(SaSensitiveVerify::verifySafeToken($scene, $token, $loginId));
    }

    public function testGetRemainingAttemptsDecreasesOnWrongCode(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;
        SaSensitiveVerify::setMaxAttempts(3);

        $this->assertEquals(3, SaSensitiveVerify::getRemainingAttempts($scene, $loginId));

        SaSensitiveVerify::generateCode($scene, $loginId);
        SaSensitiveVerify::verifyCode($scene, '000001', $loginId);
        $this->assertEquals(2, SaSensitiveVerify::getRemainingAttempts($scene, $loginId));

        SaSensitiveVerify::verifyCode($scene, '000002', $loginId);
        $this->assertEquals(1, SaSensitiveVerify::getRemainingAttempts($scene, $loginId));
    }

    public function testVerifyCodeAndThrowThrowsNotSafeException(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $code = SaSensitiveVerify::generateCode($scene, $loginId);

        $this->expectException(NotSafeException::class);
        SaSensitiveVerify::verifyCodeAndThrow($scene, 'wrong', $loginId);
    }

    public function testVerifySafeTokenAndThrowThrowsNotSafeException(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        SaSensitiveVerify::createSafeToken($scene, $loginId);

        $this->expectException(NotSafeException::class);
        SaSensitiveVerify::verifySafeTokenAndThrow($scene, 'wrong-token', $loginId);
    }

    public function testDifferentLoginTypesAreIndependent(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $code1 = SaSensitiveVerify::generateCode($scene, $loginId, 'login');
        $result1 = SaSensitiveVerify::verifyCode($scene, $code1, $loginId, 'login');
        $this->assertTrue($result1);

        $code2 = SaSensitiveVerify::generateCode($scene, $loginId, 'admin');
        $result2 = SaSensitiveVerify::verifyCode($scene, $code2, $loginId, 'admin');
        $this->assertTrue($result2);

        $this->assertTrue(SaSensitiveVerify::isVerified($scene, $loginId, 'login'));
        $this->assertTrue(SaSensitiveVerify::isVerified($scene, $loginId, 'admin'));
    }

    public function testSendCodeReturnsCode(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $code = SaSensitiveVerify::sendCode($scene, $loginId);

        $this->assertEquals(6, strlen($code));
    }

    public function testCodeCannotBeReusedAfterVerification(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;

        $code = SaSensitiveVerify::generateCode($scene, $loginId);

        $firstVerify = SaSensitiveVerify::verifyCode($scene, $code, $loginId);
        $this->assertTrue($firstVerify);

        $secondVerify = SaSensitiveVerify::verifyCode($scene, $code, $loginId);
        $this->assertFalse($secondVerify);
    }
}
