<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;
use SaToken\Util\SaTokenContext;

class TestableStpLogic extends StpLogic
{
    public function checkFingerprint(string $tokenValue): void
    {
        parent::checkFingerprint($tokenValue);
    }
}

class StpLogicSecurityTest extends TestCase
{
    protected TestableStpLogic $stp;
    protected TokenManager $manager;
    protected SaTokenDaoMemory $dao;

    protected function setUp(): void
    {
        SaToken::reset();
        $config = new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'tokenStyle'      => 'uuid',
            'tokenFingerprint' => true,
            'aesKey'          => 'test-encryption-key-for-sa-token-tests-only-32bytes',
        ]);
        SaToken::setConfig($config);
        $this->dao = new SaTokenDaoMemory();
        SaToken::setDao($this->dao);

        $this->stp = new TestableStpLogic('login');
        $this->manager = new TokenManager();

        SaTokenContext::setContextId('test');
    }

    protected function tearDown(): void
    {
        SaTokenContext::setContextId('test');
        SaTokenContext::clear();
        SaToken::reset();
    }

    // ===== Token 指纹相关测试 =====

    public function testComputeFingerprint(): void
    {
        $fingerprint = $this->manager->computeFingerprint();
        $this->assertNotEmpty($fingerprint);
        $this->assertEquals(64, strlen($fingerprint)); // sha256 hash is 64 hex chars
    }

    public function testFingerprintConsistentWithSameInput(): void
    {
        $fp1 = $this->manager->computeFingerprint();
        $fp2 = $this->manager->computeFingerprint();
        $this->assertEquals($fp1, $fp2);
    }

    public function testFingerprintSavedWhenEnabled(): void
    {
        $token = 'sat_test-token-123';
        $fingerprint = $this->manager->computeFingerprint();

        $this->manager->saveFingerprint($token, $fingerprint, 3600);

        $savedFp = $this->manager->getFingerprint($token);
        $this->assertEquals($fingerprint, $savedFp);
    }

    public function testFingerprintDeleted(): void
    {
        $token = 'sat_test-token-456';
        $fingerprint = $this->manager->computeFingerprint();
        $this->manager->saveFingerprint($token, $fingerprint, 3600);

        $this->manager->deleteFingerprint($token);

        $this->assertNull($this->manager->getFingerprint($token));
    }

    public function testLoginSavesFingerprintWhenEnabled(): void
    {
        SaToken::getConfig()->setTokenFingerprint(true);
        SaTokenContext::setHeader('User-Agent', 'Test-Agent/1.0');

        $result = $this->stp->login(10001);
        $token = $result->getAccessToken();

        $savedFp = $this->manager->getFingerprint($token);
        $this->assertNotEmpty($savedFp);
    }

    public function testCheckFingerprintMatches(): void
    {
        $token = 'sat_token-fingerprint-check';
        $fingerprint = $this->manager->computeFingerprint();

        $this->manager->saveFingerprint($token, $fingerprint, 3600);
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(true));

        $this->stp = new TestableStpLogic('login');

        try {
            $this->stp->checkFingerprint($token);
            $this->assertTrue(true);
        } catch (\Throwable $e) {
            $this->fail('Fingerprint check should pass when matches');
        }
    }

    public function testCheckFingerprintFailsWhenDifferent(): void
    {
        $token = 'sat_token-fingerprint-fail';
        $wrongFp = hash('sha256', 'different-ip-and-ua');

        $this->manager->saveFingerprint($token, $wrongFp, 3600);
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(true));

        $this->stp = new TestableStpLogic('login');

        $this->expectException(\SaToken\Exception\NotLoginException::class);
        $this->stp->checkFingerprint($token);
    }

    public function testCheckFingerprintDisabled(): void
    {
        $token = 'sat_token-fingerprint-disabled';
        $wrongFp = hash('sha256', 'different-ip-and-ua');

        $this->manager->saveFingerprint($token, $wrongFp, 3600);
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(false));
        $this->stp = new TestableStpLogic('login');

        try {
            $this->stp->checkFingerprint($token);
            $this->assertTrue(true);
        } catch (\Throwable $e) {
            $this->fail('Fingerprint check should not fail when disabled');
        }
    }

    public function testCheckFingerprintWhenNoneSaved(): void
    {
        $token = 'sat_token-no-fingerprint';
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(true));
        $this->stp = new TestableStpLogic('login');

        try {
            $this->stp->checkFingerprint($token);
            $this->assertTrue(true);
        } catch (\Throwable $e) {
            $this->fail('Fingerprint check should pass when no fingerprint saved');
        }
    }

    public function testLogoutClearsFingerprint(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(true));

        $result = $this->stp->login(10001);
        $token = $result->getAccessToken();

        $this->assertNotEmpty($this->manager->getFingerprint($token));

        $this->manager->deleteRefreshTokenByAccessToken(10001, 'login', $token);
        $this->manager->deleteFingerprint($token);
        $this->manager->deleteToken($token, 10001, 'login');

        $this->assertNull($this->manager->getFingerprint($token));
    }

    // ===== Token 黑名单相关测试 =====

    public function testAddToBlacklist(): void
    {
        $token = 'sat_token-to-blacklist';
        $this->manager->addToBlacklist($token, 3600);

        $this->assertTrue($this->manager->isBlacklisted($token));
    }

    public function testRemoveFromBlacklist(): void
    {
        $token = 'sat_token-from-blacklist';
        $this->manager->addToBlacklist($token, 3600);

        $this->assertTrue($this->manager->isBlacklisted($token));

        $this->manager->removeFromBlacklist($token);

        $this->assertFalse($this->manager->isBlacklisted($token));
    }

    public function testRevokeToken(): void
    {
        $result = $this->stp->login(10001);
        $token = $result->getAccessToken();

        $this->assertTrue($this->stp->revokeToken($token));
        $this->assertTrue($this->stp->isTokenRevoked($token));
    }

    public function testRevokeTokenUsesTokenTimeout(): void
    {
        $token = 'sat_token-with-timeout';
        $this->manager->saveToken($token, 10001, 'login', 'PC', 7200);

        $this->stp->revokeToken($token);

        $this->assertTrue($this->manager->isBlacklisted($token));
    }

    public function testCheckLoginFailsWhenTokenRevoked(): void
    {
        $result = $this->stp->login(10001);
        $token = $result->getAccessToken();

        $this->stp->revokeToken($token);

        SaTokenContext::setHeader('satoken', $token);

        $this->expectException(\SaToken\Exception\NotLoginException::class);
        $this->stp->checkLogin();
    }

    public function testIsTokenRevokedTrueWhenRevoked(): void
    {
        $token = 'sat_token-revoked-check';
        $this->manager->addToBlacklist($token, 3600);

        $this->assertTrue($this->stp->isTokenRevoked($token));
    }

    public function testIsTokenRevokedFalseWhenNotRevoked(): void
    {
        $token = 'sat_token-not-revoked';

        $this->assertFalse($this->stp->isTokenRevoked($token));
    }

    public function testDeleteAllTokenByLoginIdClearsBlacklist(): void
    {
        $token1 = $this->manager->createTokenValue(10001, 'login');
        $token2 = $this->manager->createTokenValue(10001, 'login');

        $this->manager->saveToken($token1, 10001, 'login', 'PC');
        $this->manager->saveToken($token2, 10001, 'login', 'APP');

        $this->manager->addToBlacklist($token1, 3600);
        $this->manager->addToBlacklist($token2, 3600);

        $this->assertTrue($this->manager->isBlacklisted($token1));
        $this->assertTrue($this->manager->isBlacklisted($token2));

        $this->manager->deleteAllTokenByLoginId(10001, 'login');

        $this->assertFalse($this->manager->isBlacklisted($token1));
        $this->assertFalse($this->manager->isBlacklisted($token2));
    }

    // ===== StpUtil 静态方法测试 =====

    public function testStpUtilRevokeToken(): void
    {
        $result = $this->stp->login(10001);
        $token = $result->getAccessToken();

        $this->assertTrue(\SaToken\StpUtil::revokeToken($token));
        $this->assertTrue(\SaToken\StpUtil::isTokenRevoked($token));
    }

    public function testStpUtilIsTokenRevoked(): void
    {
        $token = 'sat_stp-util-token';
        $this->manager->addToBlacklist($token, 3600);

        $this->assertTrue(\SaToken\StpUtil::isTokenRevoked($token));
    }

    // ===== 组合功能测试 =====

    public function testFullLoginWithFingerprintAndRevokeFlow(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(true));
        SaTokenContext::setHeader('User-Agent', 'Test-Combination/1.0');

        $result = $this->stp->login(10001);
        $token = $result->getAccessToken();

        $this->assertNotEmpty($this->manager->getFingerprint($token));

        SaTokenContext::setHeader('satoken', $token);

        $this->stp->revokeToken($token);

        $this->expectException(\SaToken\Exception\NotLoginException::class);
        $this->stp->checkLogin();
    }
}
