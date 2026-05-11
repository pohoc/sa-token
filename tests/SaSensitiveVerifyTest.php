<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\NotSafeException;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Security\SaSensitiveVerify;

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
