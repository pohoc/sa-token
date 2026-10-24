<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\StpUtil;
use SaToken\TokenManager;
use SaToken\Util\SaTokenContext;

class RefreshTokenTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::init([
            'timeout'              => 7200,
            'refreshToken'         => true,
            'refreshTokenTimeout'  => 2592000,
            'refreshTokenRotation' => true,
        ]);
    }

    protected function tearDown(): void
    {
        StpUtil::logout();
        SaTokenContext::clear();
        SaToken::reset();
    }

    public function testCreateRefreshToken(): void
    {
        $loginResult = StpUtil::login(10001);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $this->assertNotEmpty($refreshToken);
        $this->assertNotEquals($accessToken, $refreshToken);
        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testCreateRefreshTokenWithInvalidAccessToken(): void
    {
        $this->expectException(SaTokenException::class);
        StpUtil::createRefreshToken('invalid-access-token');
    }

    public function testCreateRefreshTokenWithCustomTimeout(): void
    {
        $loginResult = StpUtil::login(10002);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken, 3600);

        $this->assertNotEmpty($refreshToken);
        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testInvalidCustomTimeoutDoesNotRevokeExistingRefreshToken(): void
    {
        $loginResult = StpUtil::login(10003);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        foreach ([0, -2, PHP_INT_MAX] as $timeout) {
            try {
                StpUtil::createRefreshToken($accessToken, $timeout);
                $this->fail("无效 Refresh Token 有效期 {$timeout} 应被拒绝");
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('有效期', $e->getMessage());
            }
            $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));
        }
    }

    public function testKickoutByTokenRevokesItsRefreshToken(): void
    {
        $loginResult = StpUtil::login(10020);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        StpUtil::kickoutByTokenValue($accessToken);

        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
        try {
            StpUtil::refreshToken($refreshToken);
            $this->fail('被踢出的会话对应 RefreshToken 不得重新签发会话');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无效', $e->getMessage());
        }
    }

    public function testKickoutByLoginIdRevokesAllRefreshTokens(): void
    {
        $loginResult = StpUtil::login(10021);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        StpUtil::kickout(10021);

        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testRevokeAccessTokenRevokesItsRefreshToken(): void
    {
        $loginResult = StpUtil::login(10022);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $this->assertTrue(StpUtil::revokeToken($accessToken));
        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testMaxLoginCountEvictionRevokesOldRefreshToken(): void
    {
        SaToken::getConfig()->setMaxLoginCount(1);
        $firstLogin = StpUtil::login(10023);
        $oldRefreshToken = StpUtil::createRefreshToken($firstLogin->getAccessToken());

        $secondLogin = StpUtil::login(10023);

        $this->assertNotSame($firstLogin->getAccessToken(), $secondLogin->getAccessToken());
        $this->assertFalse(StpUtil::isRefreshTokenValid($oldRefreshToken));
    }

    public function testCreatingRefreshTokenAgainInvalidatesPreviousOne(): void
    {
        $accessToken = StpUtil::login(10024)->getAccessToken();
        $firstRefreshToken = StpUtil::createRefreshToken($accessToken);
        $secondRefreshToken = StpUtil::createRefreshToken($accessToken);

        $this->assertNotSame($firstRefreshToken, $secondRefreshToken);
        $this->assertFalse(StpUtil::isRefreshTokenValid($firstRefreshToken));
        $this->assertTrue(StpUtil::isRefreshTokenValid($secondRefreshToken));
    }

    public function testRefreshTokenCannotBeCreatedForAnotherLoginType(): void
    {
        $memberLogic = SaToken::getStpLogic('member');
        $accessToken = $memberLogic->login(10025)->getAccessToken();

        $this->expectException(SaTokenException::class);
        SaToken::getStpLogic('admin')->createRefreshToken($accessToken);
    }

    public function testRefreshTokenCollisionDoesNotOverwriteExistingOwner(): void
    {
        $manager = StpUtil::getStpLogic()->getTokenManager();
        $accessTokenA = $manager->createTokenValue(10026, 'login');
        $accessTokenB = $manager->createTokenValue(10027, 'login');
        $manager->saveToken($accessTokenA, 10026, 'login');
        $manager->saveToken($accessTokenB, 10027, 'login');
        $manager->saveRefreshToken('same-refresh-token', $accessTokenA, 10026, 'login', 3600);

        try {
            $manager->saveRefreshToken('same-refresh-token', $accessTokenB, 10027, 'login', 3600);
            $this->fail('RefreshToken 碰撞不能覆盖已有凭据');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('冲突', $e->getMessage());
        }

        $data = $manager->getRefreshTokenData('same-refresh-token');
        $this->assertSame('10026', $data['loginId'] ?? null);
        $this->assertSame('same-refresh-token', $manager->getRefreshTokenByAccessToken(10026, 'login', $accessTokenA));
        $this->assertNull($manager->getRefreshTokenByAccessToken(10027, 'login', $accessTokenB));
    }

    public function testSaveRefreshTokenRequiresAccountLock(): void
    {
        $manager = StpUtil::getStpLogic()->getTokenManager();
        $otherManager = new TokenManager();
        $loginId = 'refresh-save-lock-user';
        $lockKey = 'login:login:' . hash('sha256', $loginId);
        self::assertTrue($otherManager->acquireLock($lockKey));

        try {
            $manager->saveRefreshToken('refresh-save-lock-token', 'access-save-lock-token', $loginId, 'login', 3600);
            self::fail('账号锁被其他请求持有时不能写入 RefreshToken');
        } catch (SaTokenException $e) {
            self::assertStringContainsString('同账号', $e->getMessage());
        }

        self::assertNull($manager->getRefreshTokenData('refresh-save-lock-token'));
        self::assertNull($manager->getRefreshTokenByAccessToken($loginId, 'login', 'access-save-lock-token'));
        $otherManager->releaseLock($lockKey);
    }

    public function testRefreshTokenRotation(): void
    {
        $loginResult = StpUtil::login(10003);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $result = StpUtil::refreshToken($refreshToken);

        $this->assertNotEmpty($result->getAccessToken());
        $this->assertTrue($result->hasRefreshToken());
        $this->assertNotEmpty($result->getRefreshToken());
        $this->assertNotEquals($accessToken, $result->getAccessToken());
        $this->assertNotEquals($refreshToken, $result->getRefreshToken());

        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
        $this->assertTrue(StpUtil::isRefreshTokenValid($result->getRefreshToken()));

        $this->assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($result->getAccessToken()));
        $this->assertFalse(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($accessToken));
    }

    public function testRefreshingStatelessJwtReturnsUsableStatelessJwt(): void
    {
        SaToken::reset();
        SaToken::init([
            'timeout'              => 7200,
            'activityTimeout'      => -1,
            'jwtStateless'         => true,
            'jwtSecretKey'         => 'test-refresh-stateless-jwt-secret-32-bytes',
            'refreshToken'         => true,
            'refreshTokenTimeout'  => 2592000,
            'refreshTokenRotation' => true,
        ]);
        $logic = new StpLogic('login');

        $accessToken = $logic->loginStateless('stateless-refresh-user');
        $refreshToken = $logic->createRefreshToken($accessToken);
        $result = $logic->refreshToken($refreshToken);

        self::assertSame('stateless-refresh-user', $logic->getLoginIdByToken($result->getAccessToken()));
        self::assertNotSame($accessToken, $result->getAccessToken());
        self::assertNull($logic->getLoginIdByToken($accessToken));
        self::assertTrue($logic->isRefreshTokenValid($result->getRefreshToken()));
    }

    public function testStatelessAccountKickoutRevokesItsRefreshTokens(): void
    {
        SaToken::reset();
        SaToken::init([
            'timeout'              => 7200,
            'activityTimeout'      => -1,
            'jwtStateless'         => true,
            'jwtSecretKey'         => 'test-refresh-stateless-jwt-secret-32-bytes',
            'refreshToken'         => true,
            'refreshTokenTimeout'  => 2592000,
            'refreshTokenRotation' => true,
        ]);
        $logic = new StpLogic('login');

        $accessToken = $logic->loginStateless('stateless-kickout-user');
        $refreshToken = $logic->createRefreshToken($accessToken);
        $logic->kickout('stateless-kickout-user');

        self::assertNull($logic->getLoginIdByToken($accessToken));
        self::assertFalse($logic->isRefreshTokenValid($refreshToken));
        try {
            $logic->refreshToken($refreshToken);
            self::fail('被踢出的无状态账号不能通过 RefreshToken 重新建立会话');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('无效', $exception->getMessage());
        }
    }

    public function testStatelessRefreshRejectsOldTokenAfterAccountRevocationEvenIfIndexIsMissing(): void
    {
        SaToken::reset();
        SaToken::init([
            'timeout'              => 7200,
            'activityTimeout'      => -1,
            'jwtStateless'         => true,
            'jwtSecretKey'         => 'test-refresh-stateless-jwt-secret-32-bytes',
            'refreshToken'         => true,
            'refreshTokenTimeout'  => 2592000,
            'refreshTokenRotation' => true,
        ]);
        $logic = new StpLogic('login');
        $loginId = 'stateless-orphan-refresh-user';

        $accessToken = $logic->loginStateless($loginId);
        $refreshToken = $logic->createRefreshToken($accessToken);
        // Simulate an incomplete/corrupt refresh index: the bearer record is
        // still present, but account-wide cleanup cannot enumerate it.
        SaToken::getDao()->delete('satoken:refreshAccount:login:' . $loginId);
        $logic->getTokenManager()->revokeStatelessTokensByLoginId($loginId, 'login');

        try {
            $logic->refreshToken($refreshToken);
            self::fail('账号撤销水位之后的旧 JWT 不得通过残留 RefreshToken 重新签发');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('撤销', $exception->getMessage());
        }

        self::assertNull($logic->getLoginIdByToken($accessToken));
    }

    public function testStatelessRefreshCanRenewExpiredAccessJwt(): void
    {
        SaToken::reset();
        SaToken::init([
            'timeout'              => 1,
            'activityTimeout'      => -1,
            'jwtStateless'         => true,
            'jwtSecretKey'         => 'test-refresh-stateless-jwt-secret-32-bytes',
            'refreshToken'         => true,
            'refreshTokenTimeout'  => 60,
            'refreshTokenRotation' => true,
        ]);
        $logic = new StpLogic('login');

        $accessToken = $logic->loginStateless('stateless-expired-refresh-user');
        $refreshToken = $logic->createRefreshToken($accessToken, 60);
        sleep(2);

        self::assertNull($logic->getLoginIdByToken($accessToken));
        $result = $logic->refreshToken($refreshToken);
        self::assertSame('stateless-expired-refresh-user', $logic->getLoginIdByToken($result->getAccessToken()));
    }

    public function testRefreshTokenWithoutRotation(): void
    {
        SaToken::reset();
        SaToken::init([
            'timeout'              => 7200,
            'refreshToken'         => true,
            'refreshTokenTimeout'  => 2592000,
            'refreshTokenRotation' => false,
        ]);

        $loginResult = StpUtil::login(10004);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $result = StpUtil::refreshToken($refreshToken);

        $this->assertNotEmpty($result->getAccessToken());
        // 未开启轮换时应保留原 RefreshToken 并重新绑定到新 AccessToken，
        // 否则客户端刷新一次后即永久失去刷新能力
        $this->assertTrue($result->hasRefreshToken());
        $this->assertSame($refreshToken, $result->getRefreshToken());

        $this->assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($result->getAccessToken()));
        $this->assertFalse(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($accessToken));
        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));

        // 原 RefreshToken 应可继续用于下一次刷新
        $result2 = StpUtil::refreshToken($refreshToken);
        $this->assertNotEmpty($result2->getAccessToken());
        $this->assertNotEquals($result->getAccessToken(), $result2->getAccessToken());
    }

    public function testConcurrentRefreshWithoutRotationRevokesPreviousRotatedAccessToken(): void
    {
        SaToken::reset();
        SaToken::init([
            'timeout'              => 7200,
            'refreshToken'         => true,
            'refreshTokenTimeout'  => 2592000,
            'refreshTokenRotation' => false,
        ]);

        $dao = new class () extends \SaToken\Dao\SaTokenDaoMemory {
            public ?string $triggerKey = null;
            public ?\Closure $afterRead = null;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($key === $this->triggerKey && $this->afterRead !== null) {
                    $callback = $this->afterRead;
                    $this->afterRead = null;
                    $callback();
                }
                return $value;
            }
        };
        SaToken::setDao($dao);

        $accessToken = StpUtil::login(10005)->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);
        $firstRefresh = null;
        $dao->triggerKey = TokenManager::REFRESH_TOKEN_PREFIX . $refreshToken;
        $dao->afterRead = function () use ($refreshToken, &$firstRefresh): void {
            $firstRefresh = StpUtil::refreshToken($refreshToken);
        };

        $secondRefresh = StpUtil::refreshToken($refreshToken);

        self::assertNotNull($firstRefresh);
        self::assertFalse(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($firstRefresh->getAccessToken()));
        self::assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($secondRefresh->getAccessToken()));
        self::assertSame($refreshToken, $secondRefresh->getRefreshToken());
    }

    public function testRefreshTokenInvalid(): void
    {
        $this->expectException(SaTokenException::class);
        StpUtil::refreshToken('invalid-refresh-token');
    }

    public function testRefreshTokenReuseDetection(): void
    {
        $loginResult = StpUtil::login(10005);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $result1 = StpUtil::refreshToken($refreshToken);

        try {
            StpUtil::refreshToken($refreshToken);
            $this->fail('RefreshToken 重放必须撤销轮换后派生的账号会话');
        } catch (SaTokenException $exception) {
            $this->assertStringContainsString('重放', $exception->getMessage());
        }

        $this->assertFalse(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($result1->getAccessToken()));
        $this->assertFalse(StpUtil::isRefreshTokenValid((string) $result1->getRefreshToken()));

        $newLogin = StpUtil::login(10005);
        try {
            StpUtil::refreshToken($refreshToken);
            $this->fail('已处理的旧 RefreshToken 后续重放不得再次触发撤销');
        } catch (SaTokenException $exception) {
            $this->assertStringContainsString('无效', $exception->getMessage());
        }
        $this->assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($newLogin->getAccessToken()));
    }

    public function testConcurrentRotatedRefreshReplayRevokesWinningDescendants(): void
    {
        $dao = new class () extends \SaToken\Dao\SaTokenDaoMemory {
            public ?string $triggerKey = null;
            public ?\Closure $afterRead = null;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($key === $this->triggerKey && $this->afterRead !== null) {
                    $callback = $this->afterRead;
                    $this->afterRead = null;
                    $callback();
                }
                return $value;
            }
        };
        SaToken::setDao($dao);

        $accessToken = StpUtil::login(10051)->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);
        $winningResult = null;
        $dao->triggerKey = TokenManager::REFRESH_TOKEN_PREFIX . $refreshToken;
        $dao->afterRead = function () use ($refreshToken, &$winningResult): void {
            $winningResult = StpUtil::refreshToken($refreshToken);
        };

        try {
            StpUtil::refreshToken($refreshToken);
            $this->fail('并发旧 RefreshToken 重放必须撤销获胜请求签发的会话');
        } catch (SaTokenException $exception) {
            $this->assertStringContainsString('重放', $exception->getMessage());
        }

        $this->assertNotNull($winningResult);
        $this->assertFalse(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($winningResult->getAccessToken()));
        $this->assertFalse(StpUtil::isRefreshTokenValid((string) $winningResult->getRefreshToken()));
    }

    public function testRevokeRefreshToken(): void
    {
        $loginResult = StpUtil::login(10006);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));

        $result = StpUtil::revokeRefreshToken($refreshToken);
        $this->assertTrue($result);
        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testRevokeRefreshTokenDoesNotRaceAnInFlightRefresh(): void
    {
        $loginId = 10030;
        $accessToken = StpUtil::login($loginId)->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);
        $lockKey = \SaToken\TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', (string) $loginId);
        $this->assertTrue(SaToken::getDao()->setIfNotExists($lockKey, 'refresh-in-progress', 5));

        try {
            StpUtil::revokeRefreshToken($refreshToken);
            $this->fail('刷新正在处理时撤销不得报告成功');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('正在处理中', $e->getMessage());
        } finally {
            SaToken::getDao()->delete($lockKey);
        }

        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testRevokeInvalidRefreshToken(): void
    {
        $result = StpUtil::revokeRefreshToken('nonexistent-token');
        $this->assertFalse($result);
    }

    public function testRevokeRefreshTokenByAccessToken(): void
    {
        $loginResult = StpUtil::login(10007);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));

        $result = StpUtil::revokeRefreshTokenByAccessToken($accessToken);
        $this->assertTrue($result);
        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testGetRefreshTokenByAccessToken(): void
    {
        $loginResult = StpUtil::login(10008);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $found = StpUtil::getRefreshTokenByAccessToken($accessToken);
        $this->assertEquals($refreshToken, $found);
    }

    public function testGetRefreshTokenByInvalidAccessToken(): void
    {
        $found = StpUtil::getRefreshTokenByAccessToken('nonexistent-token');
        $this->assertNull($found);
    }

    public function testLogoutClearsRefreshToken(): void
    {
        $loginResult = StpUtil::login(10009);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::getRefreshTokenByAccessToken($accessToken);
        $this->assertNotNull($refreshToken);
        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));

        StpUtil::logoutByLoginId(10009);

        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testLogoutByLoginIdClearsRefreshTokens(): void
    {
        $loginResult = StpUtil::login(10010);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));

        StpUtil::logoutByLoginId(10010);

        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testLoginAutoCreatesRefreshTokenWhenEnabled(): void
    {
        $loginResult = StpUtil::login(10011);
        $accessToken = $loginResult->getAccessToken();

        $refreshToken = StpUtil::getRefreshTokenByAccessToken($accessToken);
        $this->assertNotNull($refreshToken);
        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testLoginDoesNotCreateRefreshTokenWhenDisabled(): void
    {
        SaToken::reset();
        SaToken::init([
            'timeout'      => 7200,
            'refreshToken' => false,
        ]);

        $loginResult = StpUtil::login(10012);
        $accessToken = $loginResult->getAccessToken();

        $refreshToken = StpUtil::getRefreshTokenByAccessToken($accessToken);
        $this->assertNull($refreshToken);
    }

    public function testFullRefreshTokenLifecycle(): void
    {
        $loginResult = StpUtil::login(20001);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::getRefreshTokenByAccessToken($accessToken);
        $this->assertNotNull($refreshToken);

        $result = StpUtil::refreshToken($refreshToken);
        $newAccessToken = $result->getAccessToken();
        $newRefreshToken = $result->getRefreshToken();
        $this->assertNotEmpty($newAccessToken);
        $this->assertNotEmpty($newRefreshToken);

        $this->assertFalse(StpUtil::isRefreshTokenValid($refreshToken));
        $this->assertTrue(StpUtil::isRefreshTokenValid($newRefreshToken));

        $loginId = StpUtil::getStpLogic()->getTokenManager()->getLoginIdByToken($newAccessToken);
        $this->assertEquals('20001', $loginId);

        StpUtil::revokeRefreshToken($newRefreshToken);
        $this->assertFalse(StpUtil::isRefreshTokenValid($newRefreshToken));

        $this->assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($newAccessToken));
    }

    public function testRefreshTokenWithDisabledAccount(): void
    {
        $loginResult = StpUtil::login(30001);
        $accessToken = $loginResult->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($accessToken);

        StpUtil::disable(30001, 'login', 1, 3600);

        $this->expectException(SaTokenException::class);
        StpUtil::refreshToken($refreshToken);
    }
}
