<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\NotSafeException;
use SaToken\SaToken;
use SaToken\Security\SaSensitiveVerify;
use SaToken\StpLogic;
use SaToken\StpUtil;
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
            'signKey'         => 'sensitive-verify-test-sign-key-32-bytes',
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

    public function testOpenSensitiveVerifyCannotMintProofBeforeOtpVerification(): void
    {
        $loginId = 'sensitive-user';
        $token = $this->stp->login($loginId)->getAccessToken();
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => strcasecmp($name, 'satoken') === 0 ? [$token] : []);
        SaTokenContext::setRequest($request);

        $this->expectException(NotSafeException::class);
        $this->expectExceptionMessage('请先完成该场景的一次性验证码验证');
        $this->stp->openSensitiveVerify('payment');
    }

    public function testOpenSensitiveVerifyConsumesSuccessfulOtpBeforeIssuingProof(): void
    {
        $loginId = 'sensitive-user';
        $token = $this->stp->login($loginId)->getAccessToken();
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => strcasecmp($name, 'satoken') === 0 ? [$token] : []);
        SaTokenContext::setRequest($request);

        $code = SaSensitiveVerify::generateCode('payment', $loginId);
        $this->stp->verifyOtpCode('payment', $code);

        $proof = $this->stp->openSensitiveVerify('payment');
        $this->stp->checkSensitiveVerify('payment', $proof);
        self::assertFalse(SaSensitiveVerify::isVerified('payment', $loginId));

        $this->expectException(NotSafeException::class);
        $this->stp->openSensitiveVerify('payment');
    }

    public function testOtpVerificationCannotMintSensitiveProofForAnotherSession(): void
    {
        SaToken::getConfig()->setTokenFingerprint(false);
        $loginId = 'cross-session-sensitive-user';
        $tokenA = $this->manager->createTokenValue($loginId, 'login');
        $this->manager->saveToken($tokenA, $loginId, 'login', 'PC', 3600);
        $tokenB = $this->manager->createTokenValue($loginId, 'login');
        $this->manager->saveToken($tokenB, $loginId, 'login', 'APP', 3600);

        $requestA = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $requestA->method('getHeader')->willReturnCallback(static fn (string $name): array => strcasecmp($name, 'satoken') === 0 ? [$tokenA] : []);
        SaTokenContext::setRequest($requestA);

        $code = SaSensitiveVerify::generateCode('payment', $loginId);
        $this->stp->verifyOtpCode('payment', $code);

        $requestB = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $requestB->method('getHeader')->willReturnCallback(static fn (string $name): array => strcasecmp($name, 'satoken') === 0 ? [$tokenB] : []);
        SaTokenContext::setRequest($requestB);

        try {
            $this->stp->openSensitiveVerify('payment');
            self::fail('A second session must not mint a proof from another session OTP');
        } catch (NotSafeException $exception) {
            self::assertSame('请先完成该场景的一次性验证码验证', $exception->getMessage());
        }

        SaTokenContext::setRequest($requestA);
        $proof = $this->stp->openSensitiveVerify('payment');
        SaTokenContext::setRequest($requestB);
        try {
            $this->stp->checkSensitiveVerify('payment', $proof);
            self::fail('A sensitive proof must not be usable from another session');
        } catch (NotSafeException $exception) {
            self::assertSame('安全验证令牌无效或已过期', $exception->getMessage());
        }

        SaTokenContext::setRequest($requestA);
        $this->stp->checkSensitiveVerify('payment', $proof);
    }

    public function testExpiredTokenReuseCannotCrossLoginTypeThroughStaleAccountIndex(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public ?\Closure $afterTokenWrite = null;

            public function setIfNotExists(string $key, string $value, ?int $timeout = null): bool
            {
                $created = parent::setIfNotExists($key, $value, $timeout);
                if ($created && str_starts_with($key, TokenManager::TOKEN_PREFIX) && $this->afterTokenWrite !== null) {
                    $callback = $this->afterTokenWrite;
                    $this->afterTokenWrite = null;
                    $callback();
                }

                return $created;
            }
        };
        $this->dao = $dao;
        SaToken::setDao($dao);
        SaToken::getConfig()->setConcurrent(true);
        $legacyType = new StpLogic('legacy');
        $otherType = new StpLogic('current');
        $tokenValues = [
            'legacy'  => ['reused-cross-type-token-value', 'legacy-keep-token-value'],
            'current' => ['reused-cross-type-token-value'],
        ];
        SaToken::setAction(new class ($tokenValues) implements \SaToken\Action\SaTokenActionInterface {
            /** @param array<string, array<string>> $tokenValues */
            public function __construct(private array $tokenValues)
            {
            }

            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return array_shift($this->tokenValues[$loginType]);
            }
        });

        $loginId = 'same-login-id';
        $expiredToken = $legacyType->login(
            $loginId,
            (new \SaToken\SaLoginParameter())->setTimeout(1)
        )->getAccessToken();
        $legacyType->login(
            $loginId,
            (new \SaToken\SaLoginParameter())->setTimeout(3600)->setDeviceType('mobile')
        );
        self::assertContains(
            $expiredToken,
            array_column($this->manager->getTokenListByLoginId($loginId, 'legacy'), 'tokenValue')
        );

        // Simulate expiry of one short-lived token while another token keeps
        // the account index alive. A newly issued token in another login type
        // may then legitimately reuse the expired bearer string.
        $this->dao->delete(TokenManager::TOKEN_PREFIX . $expiredToken);
        $this->dao->delete(TokenManager::TOKEN_SESSION_LINEAGE_PREFIX . $expiredToken);
        $loginIdObservedDuringBearerPublish = 'not observed';
        $dao->afterTokenWrite = function () use ($legacyType, $expiredToken, &$loginIdObservedDuringBearerPublish): void {
            $loginIdObservedDuringBearerPublish = $legacyType->getLoginIdByToken($expiredToken);
        };
        $currentToken = $otherType->login($loginId)->getAccessToken();
        self::assertSame($expiredToken, $currentToken);
        self::assertNull($loginIdObservedDuringBearerPublish);

        self::assertNull(
            $legacyType->getLoginIdByToken($currentToken),
            'A stale account index must not authenticate a token now owned by another login type'
        );
        $legacyType->kickoutByTokenValue($currentToken);
        self::assertSame($loginId, $otherType->getLoginIdByToken($currentToken));
    }

    public function testSourceAntiBruteLimitRemainsEnabledWhenAccountLimitIsDisabled(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 0,
            'antiBruteIpMaxFailures' => 2,
            'antiBruteLockDuration' => 600,
        ]));
        SaTokenContext::setRequest(new class () {
            public function getClientIp(): string
            {
                return '192.0.2.77';
            }
        });

        $this->stp->checkAntiBrute('random-user-1');
        $this->stp->recordAntiBruteFailure('random-user-1');
        $this->stp->checkAntiBrute('random-user-2');
        $this->stp->recordAntiBruteFailure('random-user-2');

        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $this->expectExceptionMessage('当前来源失败次数过多');
        $this->stp->checkAntiBrute('random-user-3');
    }

    public function testSuccessfulStandaloneAntiBruteCheckReleasesItsSourceSlot(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures' => 0,
            'antiBruteIpMaxFailures' => 1,
            'antiBruteLockDuration' => 600,
        ]));
        SaTokenContext::setRequest(new class () {
            public function getClientIp(): string
            {
                return '192.0.2.78';
            }
        });

        StpUtil::checkAntiBrute('external-user');
        StpUtil::clearAntiBruteFailures('external-user');
        StpUtil::checkAntiBrute('external-user');
        StpUtil::recordAntiBruteFailure('external-user');

        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $this->expectExceptionMessage('当前来源失败次数过多');
        StpUtil::checkAntiBrute('another-user');
    }

    public function testGetTokenValueRejectsRepeatedFrameworkCredentialHeaders(): void
    {
        $headerBag = new class () {
            /** @return array<int, string> */
            public function all(?string $name = null): array
            {
                return $name === 'satoken' ? ['valid-token', 'attacker-token'] : [];
            }
        };
        SaTokenContext::setRequest(new class ($headerBag) {
            public function __construct(public object $headers)
            {
            }

            public function header(string $name): string
            {
                return 'valid-token';
            }
        });

        self::assertNull($this->stp->getTokenValue());
    }

    public function testGetTokenValueRejectsDuplicateCookiesWithTheSameName(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getCookieParams')->willReturn(['satoken' => 'victim-token']);
        $request->method('getHeader')->willReturnCallback(static function (string $name): array {
            return strcasecmp($name, 'Cookie') === 0
                ? ['satoken=attacker-token; satoken=victim-token']
                : [];
        });
        SaTokenContext::setRequest($request);

        self::assertNull($this->stp->getTokenValue());
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

        $this->manager->saveToken($token, 10001, 'login', 'PC');
        $this->manager->saveFingerprint($token, $fingerprint, 3600);

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

        $this->manager->saveToken($token, 10001, 'login', 'PC');
        $this->manager->saveFingerprint($token, $wrongFp, 3600);

        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(true));

        $this->stp = new TestableStpLogic('login');

        $this->expectException(\SaToken\Exception\NotLoginException::class);
        $this->stp->checkFingerprint($token);
    }

    public function testCheckFingerprintDisabled(): void
    {
        $token = 'sat_token-fingerprint-disabled';
        $wrongFp = hash('sha256', 'different-ip-and-ua');

        $this->manager->saveToken($token, 10001, 'login', 'PC');
        $this->manager->saveFingerprint($token, $wrongFp, 3600);

        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(false));
        $this->stp = new TestableStpLogic('login');

        try {
            $this->stp->checkFingerprint($token);
            $this->assertTrue(true);
        } catch (\Throwable $e) {
            $this->fail('Fingerprint check should not fail when disabled');
        }
    }

    public function testCheckFingerprintFailsClosedWhenNoneSaved(): void
    {
        $token = 'sat_token-no-fingerprint';
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(true));
        $this->stp = new TestableStpLogic('login');

        $this->expectException(\SaToken\Exception\NotLoginException::class);
        $this->stp->checkFingerprint($token);
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

    public function testRevokedStatefulAccessTokenCannotBeReactivatedByRefreshTokenAfterCleanupFailure(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public bool $failNextRefreshDelete = false;

            public function delete(string $key): void
            {
                if ($this->failNextRefreshDelete && str_starts_with($key, TokenManager::REFRESH_TOKEN_PREFIX)) {
                    $this->failNextRefreshDelete = false;
                    throw new \SaToken\Exception\SaTokenException('simulated refresh cleanup failure');
                }

                parent::delete($key);
            }
        };
        $this->dao = $dao;
        SaToken::setDao($dao);
        SaToken::getConfig()
            ->setRefreshToken(true)
            ->setRefreshTokenTimeout(3600)
            ->setRefreshTokenRotation(false);

        $accessToken = $this->stp->login('revoked-with-orphan-refresh')->getAccessToken();
        $refreshToken = $this->stp->createRefreshToken($accessToken, 3600);
        $dao->failNextRefreshDelete = true;

        try {
            $this->stp->revokeToken($accessToken);
            self::fail('Token cleanup failure should be surfaced');
        } catch (\SaToken\Exception\SaTokenException) {
            self::assertTrue($this->manager->isBlacklisted($accessToken));
            self::assertNotNull($this->manager->getLoginIdByToken($accessToken));
            self::assertTrue($this->manager->isRefreshTokenValid($refreshToken));
        }

        try {
            $this->stp->refreshToken($refreshToken);
            self::fail('A revoked AccessToken must not be reactivated by its orphaned RefreshToken');
        } catch (\SaToken\Exception\SaTokenException $exception) {
            self::assertNotNull($this->manager->getLoginIdByToken($accessToken), $exception->getMessage());
        }

        // Retrying revoke is idempotent, and must finish cleanup instead of
        // treating the blacklist marker as proof that the session is gone.
        self::assertTrue($this->stp->revokeToken($accessToken));
        self::assertNull($this->manager->getLoginIdByToken($accessToken));
        self::assertFalse($this->manager->isRefreshTokenValid($refreshToken));
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

    public function testDeleteAllTokenByLoginIdPreservesBlacklist(): void
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

        $this->assertTrue($this->manager->isBlacklisted($token1));
        $this->assertTrue($this->manager->isBlacklisted($token2));
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
