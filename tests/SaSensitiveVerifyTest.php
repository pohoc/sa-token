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

    /** @var callable(string): void|null */
    private $beforeNextGetAndDelete = null;

    private ?string $replaceRateKeyOnStateLock = null;

    public function afterNextGet(callable $callback): void
    {
        $this->afterNextGet = $callback;
    }

    public function beforeNextGetAndDelete(callable $callback): void
    {
        $this->beforeNextGetAndDelete = $callback;
    }

    public function getAndDelete(string $key): ?string
    {
        if ($this->beforeNextGetAndDelete !== null) {
            $callback = $this->beforeNextGetAndDelete;
            $this->beforeNextGetAndDelete = null;
            $callback($key);
        }

        return parent::getAndDelete($key);
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
        SaToken::getConfig()->setSignKey('sensitive-verify-test-sign-key-32-bytes');
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

    public function testSensitiveVerificationRejectsInvalidLoginIdsInsteadOfAliasingThem(): void
    {
        foreach ([null, '', false, true, [], new \stdClass()] as $loginId) {
            try {
                SaSensitiveVerify::generateCode('invalid-login-id', $loginId);
                self::fail('Invalid loginId values must not share a sensitive verification state');
            } catch (SaTokenException $exception) {
                self::assertStringContainsString('loginId', $exception->getMessage());
            }
        }

        try {
            SaSensitiveVerify::createSafeToken('invalid-login-id', false);
            self::fail('Safe tokens must not bind to a normalized invalid identity');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('loginId', $exception->getMessage());
        }
    }

    public function testGeneratedCodeIsStoredAsOneWayHash(): void
    {
        $scene = 'hashed-code-scene';
        $loginId = 10001;

        $code = SaSensitiveVerify::generateCode($scene, $loginId);
        $stored = SaToken::getDao()->get(SaSensitiveVerify::getKey($scene, $loginId));
        self::assertNotNull($stored);
        $envelope = json_decode($stored, true);
        $this->assertIsArray($envelope);
        $encodedPayload = is_string($envelope['payload'] ?? null) ? $envelope['payload'] : '';
        $payload = base64_decode($encodedPayload, true);
        $data = is_string($payload) ? json_decode($payload, true) : null;

        $this->assertIsArray($data);
        $this->assertArrayNotHasKey('code', $data);
        $this->assertIsString($data['codeHash'] ?? null);
        $this->assertNotSame($code, $data['codeHash']);
        $this->assertTrue(password_verify($code, $data['codeHash']));
        $this->assertTrue(SaSensitiveVerify::verifyCode($scene, $code, $loginId));
    }

    public function testCodeLengthRejectsInsecureAndUnboundedValues(): void
    {
        foreach ([0, 1, 5, 13, PHP_INT_MAX] as $length) {
            try {
                SaSensitiveVerify::setCodeLength($length);
                $this->fail('验证码长度超出安全范围应被拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('6-12', $e->getMessage());
            }
        }

        SaSensitiveVerify::setCodeLength(8);
        $this->assertMatchesRegularExpression('/^\d{8}$/', SaSensitiveVerify::generateCode('long-code', 10001));
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
        SaToken::getConfig()->setSensitiveVerifyCallback(static fn () => null);
        SaSensitiveVerify::setSendInterval(0);

        SaSensitiveVerify::sendCode('unlimited-scene', 10001);
        SaSensitiveVerify::sendCode('unlimited-scene', 10001);

        $rateKey = SaSensitiveVerify::getKey('unlimited-scene', 10001) . ':sent';
        $this->assertNull(SaToken::getDao()->get($rateKey));
    }

    public function testFailedSendDoesNotDeleteAnotherRequestsRateLimitReservation(): void
    {
        SaToken::getConfig()->setSensitiveVerifyCallback(static fn () => null);
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

    public function testExpiredStateLockCannotLoseFailedOtpAttempts(): void
    {
        $dao = new SensitiveVerifyInterleavingDao();
        SaToken::setDao($dao);
        $scene = 'expired-state-lock-attempt-count';
        $loginId = 'alice';
        SaSensitiveVerify::generateCode($scene, $loginId);
        $stateKey = SaSensitiveVerify::getKey($scene, $loginId);

        $dao->afterNextGet(function (string $key) use ($dao, $stateKey, $scene, $loginId): void {
            if ($key !== $stateKey) {
                return;
            }

            // Simulate the first worker's lease expiring after its snapshot
            // read. The nested worker records a failed attempt first.
            $dao->delete($stateKey . ':state-lock');
            self::assertFalse(SaSensitiveVerify::verifyCode($scene, 'wrong-code', $loginId));
        });

        self::assertFalse(SaSensitiveVerify::verifyCode($scene, 'wrong-code', $loginId));
        self::assertSame(1, SaSensitiveVerify::getRemainingAttempts($scene, $loginId));
        self::assertFalse(SaSensitiveVerify::verifyCode($scene, 'wrong-code', $loginId));
        self::assertSame(0, SaSensitiveVerify::getRemainingAttempts($scene, $loginId));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('验证码尝试次数过多');
        SaSensitiveVerify::verifyCode($scene, 'wrong-code', $loginId);
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

    public function testSafeTokenStateCannotBeCopiedToAnotherLoginId(): void
    {
        $scene = 'copied-safe-token-state';
        $token = SaSensitiveVerify::createSafeToken($scene, 'alice');
        $sourceKey = 'satoken:sensitive:login:safe-token:' . $scene . ':' . hash('sha256', 'alice') . ':' . substr($token, 0, 16);
        $targetKey = 'satoken:sensitive:login:safe-token:' . $scene . ':' . hash('sha256', 'bob') . ':' . substr($token, 0, 16);
        $sourceState = SaToken::getDao()->get($sourceKey);
        self::assertNotNull($sourceState);
        SaToken::getDao()->set($targetKey, $sourceState, 660);

        self::assertFalse(SaSensitiveVerify::verifySafeToken($scene, $token, 'bob'));
    }

    public function testSafeTokenExpiryIsRecheckedWhenAtomicallyConsumed(): void
    {
        $dao = new SensitiveVerifyInterleavingDao();
        SaToken::setDao($dao);
        $scene = 'safe-token-expiry-race';
        $loginId = 'alice';
        $token = SaSensitiveVerify::createSafeToken($scene, $loginId);
        $key = 'satoken:sensitive:login:safe-token:' . $scene . ':' . hash('sha256', $loginId) . ':' . substr($token, 0, 16);
        $encodeState = new \ReflectionMethod(SaSensitiveVerify::class, 'encodeSensitiveState');
        $encodeState->setAccessible(true);

        $dao->afterNextGet(static function (string $readKey, ?string $ignoredValue) use ($dao, $key, $scene, $loginId, $token, $encodeState): void {
            if ($readKey !== $key) {
                return;
            }
            $expiredState = $encodeState->invoke(null, [
                'scene' => $scene,
                'loginId' => $loginId,
                'loginType' => 'login',
                'createdAt' => time() - 601,
                'expiresAt' => time() - 1,
                'tokenHash' => hash('sha256', $token),
            ], $key);
            self::assertIsString($expiredState);
            $dao->set($key, $expiredState, 60);
        });

        self::assertFalse(SaSensitiveVerify::verifySafeToken($scene, $token, $loginId));
    }

    public function testSafeTokenWithoutFullTokenHashIsRejected(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;
        $token = SaSensitiveVerify::createSafeToken($scene, $loginId);
        $key = 'satoken:sensitive:login:safe-token:' . $scene . ':' . hash('sha256', (string) $loginId) . ':' . substr($token, 0, 16);

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

    public function testOtpCannotCrossLoginTypesThroughSceneDelimiterCollision(): void
    {
        $loginId = 10001;
        $code = SaSensitiveVerify::generateCode('admin:otp', $loginId, 'user');

        $this->assertFalse(SaSensitiveVerify::verifyCode('otp', $code, $loginId, 'user:admin'));
        $this->assertTrue(SaSensitiveVerify::verifyCode('admin:otp', $code, $loginId, 'user'));
    }

    public function testSafeTokenCannotCrossLoginTypesThroughSceneDelimiterCollision(): void
    {
        $loginId = 10002;
        $token = SaSensitiveVerify::createSafeToken('admin:safe-token:otp', $loginId, 'user');

        $this->assertFalse(SaSensitiveVerify::verifySafeToken('otp', $token, $loginId, 'user:safe-token:admin'));
        $this->assertTrue(SaSensitiveVerify::verifySafeToken('admin:safe-token:otp', $token, $loginId, 'user'));
    }

    public function testSendCodeDeliversCodeWithoutReturningIt(): void
    {
        $scene = 'test-scene';
        $loginId = 10001;
        $deliveredCode = null;
        SaToken::getConfig()->setSensitiveVerifyCallback(
            static function (string $sentScene, string $code, mixed $sentLoginId) use (&$deliveredCode, $scene, $loginId): void {
                self::assertSame($scene, $sentScene);
                self::assertSame($loginId, $sentLoginId);
                $deliveredCode = $code;
            }
        );

        SaSensitiveVerify::sendCode($scene, $loginId);

        $this->assertSame('void', (string) (new \ReflectionMethod(SaSensitiveVerify::class, 'sendCode'))->getReturnType());
        $this->assertIsString($deliveredCode);
        $this->assertMatchesRegularExpression('/^\d{6}$/', $deliveredCode);
    }

    public function testSendCodeRequiresDeliveryCallback(): void
    {
        try {
            SaSensitiveVerify::sendCode('missing-sender', 10003);
            $this->fail('未配置发送回调时不得生成不可投递的验证码');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('回调未配置', $e->getMessage());
        }

        $key = SaSensitiveVerify::getKey('missing-sender', 10003);
        $this->assertNull(SaToken::getDao()->get($key));
        $this->assertNull(SaToken::getDao()->get($key . ':sent'));
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

    public function testNonPositiveCodeLifetimeIsRejected(): void
    {
        $this->expectException(SaTokenException::class);
        SaSensitiveVerify::setValidSeconds(0);
    }

    public function testTamperedCodeExpiryFailsClosed(): void
    {
        $scene = 'invalid-expiry-code';
        $loginId = 10031;
        $code = SaSensitiveVerify::generateCode($scene, $loginId);
        $key = SaSensitiveVerify::getKey($scene, $loginId);
        $envelope = json_decode((string) SaToken::getDao()->get($key), true);
        if (!is_array($envelope)) {
            self::fail('Generated code state envelope must be a JSON object');
        }
        $payload = base64_decode(is_string($envelope['payload'] ?? null) ? $envelope['payload'] : '', true);
        $data = is_string($payload) ? json_decode($payload, true) : null;
        self::assertIsArray($data);
        $data['expiresAt'] = 0;
        $envelope['payload'] = base64_encode(json_encode($data) ?: '{}');
        SaToken::getDao()->set($key, json_encode($envelope) ?: '{}', 300);

        $this->assertFalse(SaSensitiveVerify::verifyCode($scene, $code, $loginId));
    }

    public function testTamperedVerificationStateCannotForgeSuccessfulOtp(): void
    {
        $scene = 'tampered-verification-state';
        $loginId = 10034;
        SaSensitiveVerify::generateCode($scene, $loginId);
        $key = SaSensitiveVerify::getKey($scene, $loginId);
        $envelope = json_decode((string) SaToken::getDao()->get($key), true);
        self::assertIsArray($envelope);
        $payload = base64_decode(is_string($envelope['payload'] ?? null) ? $envelope['payload'] : '', true);
        $data = is_string($payload) ? json_decode($payload, true) : null;
        self::assertIsArray($data);
        $data['verified'] = true;
        $envelope['payload'] = base64_encode(json_encode($data) ?: '{}');
        SaToken::getDao()->set($key, json_encode($envelope) ?: '{}', 300);

        self::assertFalse(SaSensitiveVerify::isVerified($scene, $loginId));
        self::assertFalse(SaSensitiveVerify::verifyCode($scene, '000000', $loginId));
    }

    public function testVerifiedOtpStateCannotBeCopiedToAnotherLoginId(): void
    {
        $scene = 'copied-verification-state';
        $sourceLoginId = 'alice';
        $targetLoginId = 'bob';
        $code = SaSensitiveVerify::generateCode($scene, $sourceLoginId);
        self::assertTrue(SaSensitiveVerify::verifyCode($scene, $code, $sourceLoginId));

        $sourceKey = SaSensitiveVerify::getKey($scene, $sourceLoginId);
        $targetKey = SaSensitiveVerify::getKey($scene, $targetLoginId);
        $sourceState = SaToken::getDao()->get($sourceKey);
        self::assertNotNull($sourceState);
        SaToken::getDao()->set($targetKey, $sourceState, 60);

        self::assertFalse(SaSensitiveVerify::isVerified($scene, $targetLoginId));
    }

    public function testExpiredStateLockCannotMintTwoSafeTokensFromOneOtpVerification(): void
    {
        $dao = new SensitiveVerifyInterleavingDao();
        SaToken::setDao($dao);
        $scene = 'expired-state-lock-single-use';
        $loginId = 'alice';
        $code = SaSensitiveVerify::generateCode($scene, $loginId);
        self::assertTrue(SaSensitiveVerify::verifyCode($scene, $code, $loginId));

        $stateKey = SaSensitiveVerify::getKey($scene, $loginId);
        $nestedToken = null;
        $dao->beforeNextGetAndDelete(function (string $key) use ($dao, $stateKey, $scene, $loginId, &$nestedToken): void {
            if ($key !== $stateKey) {
                return;
            }

            // Model another worker acquiring the state lock after its lease
            // expires while this request is between reading and deleting.
            $dao->delete($stateKey . ':state-lock');
            $nestedToken = SaSensitiveVerify::createSafeTokenAfterVerified($scene, $loginId);
        });

        try {
            SaSensitiveVerify::createSafeTokenAfterVerified($scene, $loginId);
            self::fail('One OTP verification must not issue two safe tokens after lock lease expiry');
        } catch (NotSafeException) {
            self::assertIsString($nestedToken);
            self::assertTrue(SaSensitiveVerify::verifySafeToken($scene, $nestedToken, $loginId));
        }
    }

    public function testCodeGenerationRequiresStateSigningKey(): void
    {
        SaToken::getConfig()->setSignKey('');

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('至少 32 字节的 signKey');
        SaSensitiveVerify::generateCode('missing-state-signing-key', 10035);
    }

    public function testSafeTokenRejectsNonPositiveLifetime(): void
    {
        $this->expectException(SaTokenException::class);
        SaSensitiveVerify::createSafeToken('invalid-expiry-safe-token', 10032, 'login', 0);
    }

    public function testTamperedSafeTokenStateFailsClosed(): void
    {
        $scene = 'invalid-expiry-safe-token';
        $loginId = 10033;
        $token = SaSensitiveVerify::createSafeToken($scene, $loginId);
        $key = 'satoken:sensitive:login:safe-token:' . $scene . ':' . hash('sha256', (string) $loginId) . ':' . substr($token, 0, 16);
        SaToken::getDao()->set($key, json_encode([
            'scene' => $scene,
            'loginId' => (string) $loginId,
            'loginType' => 'login',
            'expiresAt' => 0,
            'tokenHash' => hash('sha256', $token),
        ]) ?: '{}', 300);

        $this->assertFalse(SaSensitiveVerify::verifySafeToken($scene, $token, $loginId));
    }
}
