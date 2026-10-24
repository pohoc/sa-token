<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;
use SaToken\Util\SaTokenContext;
use SaToken\Util\SaTokenEncryptor;

class TokenManagerTest extends TestCase
{
    protected TokenManager $manager;
    protected SaTokenDaoMemory $dao;

    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'tokenStyle'      => 'uuid',
        ]));
        $this->dao = new SaTokenDaoMemory();
        SaToken::setDao($this->dao);

        $this->manager = new TokenManager();
    }

    protected function tearDown(): void
    {
        SaTokenContext::setContextId('default');
        SaToken::reset();
    }

    public function testCreateTokenValue(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->assertNotEmpty($token);
        $this->assertEquals(36, strlen($token));
    }

    public function testCreateSimpleRandomToken(): void
    {
        SaToken::getConfig()->setTokenStyle('simple-random');
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->assertNotEmpty($token);
        $this->assertEquals(32, strlen($token));
    }

    public function testSaveAndGetToken(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $loginId = $this->manager->getLoginIdByToken($token);
        $this->assertEquals('10001', $loginId);
    }

    public function testPercentEscapeLegacyKeyCollisionCannotAuthenticateAcrossLoginTypes(): void
    {
        $owner = new StpLogic('user%');
        $otherType = new StpLogic('user%25');
        $token = $this->manager->createTokenValue('shared-account', 'user%');
        $this->manager->saveToken($token, 'shared-account', 'user%');

        self::assertNull($otherType->getLoginIdByToken($token));
        self::assertSame('shared-account', $owner->getLoginIdByToken($token));
    }

    public function testLoginTokenListsAreIsolatedAcrossDelimitedLoginTypes(): void
    {
        $userToken = $this->manager->createTokenValue('admin:42', 'user');
        $this->manager->saveToken($userToken, 'admin:42', 'user');
        $adminToken = $this->manager->createTokenValue('42', 'user:admin');
        $this->manager->saveToken($adminToken, '42', 'user:admin');

        self::assertCount(1, $this->manager->getTokenListByLoginId('admin:42', 'user'));
        self::assertCount(1, $this->manager->getTokenListByLoginId('42', 'user:admin'));

        $this->manager->deleteAllTokenByLoginId('admin:42', 'user');

        self::assertFalse($this->manager->isTokenValid($userToken));
        self::assertTrue($this->manager->isTokenValid($adminToken));
    }

    public function testLogoutCanRevokeLegacyTokensFromCollidingAccountIndex(): void
    {
        $userToken = $this->manager->createTokenValue('admin:42', 'user');
        $this->manager->saveToken($userToken, 'admin:42', 'user');
        $adminToken = $this->manager->createTokenValue('42', 'user:admin');
        $this->manager->saveToken($adminToken, '42', 'user:admin');

        $userList = $this->manager->getTokenListByLoginId('admin:42', 'user');
        $adminList = $this->manager->getTokenListByLoginId('42', 'user:admin');
        $this->dao->delete(TokenManager::buildLoginIdKey('user', 'admin:42'));
        $this->dao->delete(TokenManager::buildLoginIdKey('user:admin', '42'));
        $legacyList = array_merge($userList, $adminList);
        $json = json_encode($legacyList);
        self::assertIsString($json);
        $encrypt = new \ReflectionMethod(TokenManager::class, 'encryptValue');
        $encrypted = $encrypt->invoke($this->manager, $json);
        self::assertIsString($encrypted);
        $this->dao->set(TokenManager::LOGIN_ID_PREFIX . 'user:admin:42', $encrypted);

        self::assertSame([$userToken], array_column($this->manager->getTokenListByLoginId('admin:42', 'user'), 'tokenValue'));
        self::assertSame([$adminToken], array_column($this->manager->getTokenListByLoginId('42', 'user:admin'), 'tokenValue'));

        $this->manager->deleteAllTokenByLoginId('admin:42', 'user');

        self::assertFalse($this->manager->isTokenValid($userToken));
        self::assertTrue($this->manager->isTokenValid($adminToken));
    }

    public function testSaveTokenRejectsZeroTimeoutInsteadOfCreatingPermanentToken(): void
    {
        $token = $this->manager->createTokenValue('zero-timeout-user', 'login');

        $this->expectException(SaTokenException::class);
        $this->manager->saveToken($token, 'zero-timeout-user', 'login', '', 0);
    }

    public function testRenewTimeoutRejectsZeroInsteadOfMakingTokenPermanent(): void
    {
        $token = $this->manager->createTokenValue('renew-zero-timeout-user', 'login');
        $this->manager->saveToken($token, 'renew-zero-timeout-user', 'login', '', 300);

        $this->expectException(SaTokenException::class);
        $this->manager->renewTimeout($token, 0);
    }

    public function testSaveTokenRequiresAccountLock(): void
    {
        $loginId = 'save-lock-user';
        $lockKey = 'login:login:' . hash('sha256', $loginId);
        $otherManager = new TokenManager();
        self::assertTrue($otherManager->acquireLock($lockKey));
        $token = $this->manager->createTokenValue($loginId, 'login');

        try {
            $this->manager->saveToken($token, $loginId, 'login');
            self::fail('账号锁被其他请求持有时不能写入 Token');
        } catch (SaTokenException $e) {
            self::assertStringContainsString('同账号', $e->getMessage());
        }

        self::assertNull($this->manager->getLoginIdByToken($token));
        $otherManager->releaseLock($lockKey);
    }

    public function testSaveTokenRejectsInvalidLoginId(): void
    {
        $this->expectException(SaTokenException::class);
        $this->manager->saveToken('invalid-login-id-token', '', 'login');
    }

    public function testTamperedEncryptedLoginIdMakesTokenInvalid(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'timeout' => 300,
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('k', 32),
        ]));

        $token = $this->manager->createTokenValue(10002, 'login');
        $this->manager->saveToken($token, 10002, 'login', 'PC', 300);
        $recordKey = TokenManager::TOKEN_PREFIX . $token;
        $encrypted = $this->dao->get($recordKey);
        self::assertNotNull($encrypted);
        $decoded = base64_decode($encrypted, true);
        self::assertNotFalse($decoded);
        $tampered = chr((ord($decoded[0]) ^ 0xFF) & 0xFF) . substr($decoded, 1);
        $this->dao->set($recordKey, base64_encode($tampered), 300);

        $this->assertNull($this->manager->getLoginIdByToken($token));
    }

    public function testDeleteToken(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $this->manager->deleteToken($token, 10001, 'login');
        $this->assertNull($this->manager->getLoginIdByToken($token));
    }

    public function testDeleteAllTokenByLoginId(): void
    {
        $token1 = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token1, 10001, 'login', 'PC');

        $token2 = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token2, 10001, 'login', 'APP');

        $deleted = $this->manager->deleteAllTokenByLoginId(10001, 'login');
        $this->assertCount(2, $deleted);

        $this->assertNull($this->manager->getLoginIdByToken($token1));
        $this->assertNull($this->manager->getLoginIdByToken($token2));
    }

    public function testDeleteAllTokenByLoginIdRemovesPermanentRefreshTokenMap(): void
    {
        $accessToken = $this->manager->createTokenValue('refresh-map-user', 'login');
        $this->manager->saveToken($accessToken, 'refresh-map-user', 'login', 'PC', -1);
        $refreshToken = $this->manager->createTokenValue('refresh-map-user', 'login', 'srt_');
        $this->manager->saveRefreshToken($refreshToken, $accessToken, 'refresh-map-user', 'login', -1);

        $mapKey = TokenManager::REFRESH_TOKEN_MAP_PREFIX . 'login:refresh-map-user:' . $accessToken;
        self::assertSame($refreshToken, $this->manager->getRefreshTokenByAccessToken('refresh-map-user', 'login', $accessToken));

        $this->manager->deleteAllTokenByLoginId('refresh-map-user', 'login');

        self::assertNull($this->dao->get($mapKey));
        self::assertFalse($this->manager->isRefreshTokenValid($refreshToken));
    }

    public function testRefreshTokenMapDoesNotCollideAcrossTupleComponents(): void
    {
        $accessTokenA = 'access-token-a';
        $accessTokenB = 'access-token-b';
        $refreshTokenA = 'refresh-token-a';
        $refreshTokenB = 'refresh-token-b';
        // These tuples produced the same legacy key: a:b:c:d.
        $this->manager->saveRefreshToken($refreshTokenA, $accessTokenA, 'b:c', 'a', 3600);
        $this->manager->saveRefreshToken($refreshTokenB, $accessTokenB, 'c', 'a:b', 3600);

        self::assertSame($refreshTokenA, $this->manager->getRefreshTokenByAccessToken('b:c', 'a', $accessTokenA));
        self::assertSame($refreshTokenB, $this->manager->getRefreshTokenByAccessToken('c', 'a:b', $accessTokenB));
    }

    public function testAccountLogoutCanFindRefreshTokenAfterAccessTokenExpires(): void
    {
        $loginId = 'short-access-long-refresh-user';
        $accessToken = $this->manager->createTokenValue($loginId, 'login');
        $this->manager->saveToken($accessToken, $loginId, 'login', 'PC', 1);
        $refreshToken = $this->manager->createTokenValue($loginId, 'login', 'srt_');
        $this->manager->saveRefreshToken($refreshToken, $accessToken, $loginId, 'login', 10);

        $indexKey = TokenManager::buildLoginIdKey('login', $loginId);
        self::assertGreaterThan($this->manager->getTokenTimeout($accessToken), $this->dao->getTimeout($indexKey));

        sleep(2);

        self::assertFalse($this->manager->isTokenValid($accessToken));
        self::assertCount(1, $this->manager->getTokenListByLoginId($loginId, 'login'));
        $this->manager->deleteAllTokenByLoginId($loginId, 'login');

        self::assertFalse($this->manager->isRefreshTokenValid($refreshToken));
    }

    public function testRefreshTokenExtendsLegacyAccountIndexDuringUpgrade(): void
    {
        $loginId = 'legacy:refresh-user';
        $loginType = 'user';
        $accessToken = $this->manager->createTokenValue($loginId, $loginType);
        $this->manager->saveToken($accessToken, $loginId, $loginType, 'PC', 1);
        $legacyList = $this->manager->getTokenListByLoginId($loginId, $loginType);
        $this->dao->delete(TokenManager::buildLoginIdKey($loginType, $loginId));
        $json = json_encode($legacyList);
        self::assertIsString($json);
        $encrypt = new \ReflectionMethod(TokenManager::class, 'encryptValue');
        $encrypted = $encrypt->invoke($this->manager, $json);
        self::assertIsString($encrypted);
        $this->dao->set(TokenManager::LOGIN_ID_PREFIX . $loginType . ':' . $loginId, $encrypted);

        $refreshToken = $this->manager->createTokenValue($loginId, $loginType, 'srt_');
        $this->manager->saveRefreshToken($refreshToken, $accessToken, $loginId, $loginType, 10);

        self::assertNotNull($this->dao->get(TokenManager::buildLoginIdKey($loginType, $loginId)));
        sleep(2);
        self::assertCount(1, $this->manager->getTokenListByLoginId($loginId, $loginType));
        $this->manager->deleteAllTokenByLoginId($loginId, $loginType);
        self::assertFalse($this->manager->isRefreshTokenValid($refreshToken));
    }

    public function testTokenTimeout(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $timeout = $this->manager->getTokenTimeout($token);
        $this->assertGreaterThan(0, $timeout);
        $this->assertLessThanOrEqual(3600, $timeout);
    }

    public function testRenewTimeout(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $this->manager->renewTimeout($token, 7200);
        $timeout = $this->manager->getTokenTimeout($token);
        $this->assertGreaterThan(3600, $timeout);
    }

    public function testIsTokenValid(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->assertFalse($this->manager->isTokenValid($token));

        $this->manager->saveToken($token, 10001, 'login', 'PC');
        $this->assertTrue($this->manager->isTokenValid($token));
    }

    public function testDisable(): void
    {
        $this->manager->disable(10001, 'comment', 1, 3600, 'login');
        $this->assertTrue($this->manager->isDisable(10001, 'comment', 'login'));
        $this->assertEquals(1, $this->manager->getDisableLevel(10001, 'comment', 'login'));
    }

    public function testDisableStateIsIsolatedAcrossDelimitedLoginTypes(): void
    {
        $this->manager->disable('42', 'comment', 1, -1, 'user:admin');

        self::assertTrue($this->manager->isDisable('42', 'comment', 'user:admin'));
        self::assertFalse($this->manager->isDisable('admin:42', 'comment', 'user'));

        $this->manager->untieDisable('42', 'comment', 'user:admin');
        self::assertFalse($this->manager->isDisable('42', 'comment', 'user:admin'));
        self::assertFalse($this->manager->isDisable('admin:42', 'comment', 'user'));
    }

    public function testDisableRejectsInvalidDurationsInsteadOfCreatingPermanentBan(): void
    {
        foreach ([0, -2, PHP_INT_MAX] as $duration) {
            try {
                $this->manager->disable(10002, 'comment', 1, $duration, 'login');
                $this->fail("无效封禁时长 {$duration} 应被拒绝");
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('封禁时长', $e->getMessage());
            }

            $this->assertFalse($this->manager->isDisable(10002, 'comment', 'login'));
        }

        $this->manager->disable(10002, 'comment', 1, -1, 'login');
        $this->assertTrue($this->manager->isDisable(10002, 'comment', 'login'));
        $this->assertSame(-1, $this->manager->getDisableTime(10002, 'comment', 'login'));
    }

    public function testUntieDisable(): void
    {
        $this->manager->disable(10001, 'comment', 1, 3600, 'login');
        $this->manager->untieDisable(10001, 'comment', 'login');
        $this->assertFalse($this->manager->isDisable(10001, 'comment', 'login'));
    }

    public function testSafeAuth(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        $this->assertFalse($this->manager->isSafe($token, 'transfer', 'login'));

        $this->manager->openSafe($token, 'transfer', 120, 'login');
        $this->assertTrue($this->manager->isSafe($token, 'transfer', 'login'));

        $this->manager->closeSafe($token, 'transfer', 'login');
        $this->assertFalse($this->manager->isSafe($token, 'transfer', 'login'));
    }

    public function testSwitchTo(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        $this->assertNull($this->manager->getSwitchTo($token, 'login'));

        $this->manager->setSwitchTo($token, 20001, 'login');
        $this->assertEquals('20001', $this->manager->getSwitchTo($token, 'login'));

        $this->manager->clearSwitch($token, 'login');
        $this->assertNull($this->manager->getSwitchTo($token, 'login'));
    }

    public function testSwitchStateDoesNotCollideAcrossLoginTypeAndToken(): void
    {
        $tokenA = 'b:c:1234567890123456';
        $tokenB = 'c:1234567890123456';
        $this->manager->saveToken($tokenA, 'owner-a', 'a', 'PC');
        $this->manager->saveToken($tokenB, 'owner-b', 'a:b', 'PC');

        // These pairs also produced the same legacy key: a:b:c:1234567890123456.
        $this->manager->setSwitchTo($tokenA, 'privileged-user', 'a');

        self::assertSame('privileged-user', $this->manager->getSwitchTo($tokenA, 'a'));
        self::assertNull($this->manager->getSwitchTo($tokenB, 'a:b'));
    }

    public function testPercentEscapeLegacyFallbackCannotBorrowOrClearAnotherTokenSwitch(): void
    {
        $tokenA = 'custom:token:value-123456';
        $tokenB = 'custom%3Atoken%3Avalue-123456';
        $this->manager->saveToken($tokenA, 'administrator', 'login');
        $this->manager->saveToken($tokenB, 'member', 'login');
        $this->manager->setSwitchTo($tokenA, 'protected-account', 'login');

        $logic = new StpLogic('login');
        $this->assertSame('member', $logic->getLoginIdByToken($tokenB));
        SaTokenContext::setRequest(new class ($tokenB) {
            public function __construct(private string $token)
            {
            }

            public function header(string $name): ?string
            {
                return $name === 'satoken' ? $this->token : null;
            }
        });
        self::assertSame('member', $logic->getLoginId(), '另一 token 不应继承带冒号 token 的切换身份');

        $this->manager->clearSwitch($tokenB, 'login');
        self::assertSame('protected-account', $this->manager->getSwitchTo($tokenA, 'login'), '清理 tokenB 状态不能删除 tokenA 的切换状态');
    }

    public function testTokenEncryptDisabledByDefault(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $rawValue = $this->dao->get('satoken:login:token:' . $token);
        $this->assertEquals('10001', $rawValue);
    }

    public function testTokenEncryptEnabled(): void
    {
        $encryptKey = getenv('TEST_ENCRYPT_KEY') ?: 'test-key-placeholder-32-bytes-lo';
        SaToken::getConfig()->setTokenEncrypt(true)->setTokenEncryptKey($encryptKey);
        $this->manager->resetEncryptor();

        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $rawValue = $this->dao->get('satoken:login:token:' . $token);
        $this->assertNotEquals('10001', $rawValue);
        $this->assertNotEquals('', $rawValue);

        $loginId = $this->manager->getLoginIdByToken($token);
        $this->assertEquals('10001', $loginId);
    }

    public function testTokenEncryptPreservesAllOperations(): void
    {
        $aesKey = getenv('TEST_AES_KEY_FOR_TOKEN') ?: 'test-key-placeholder-32-bytes-lo';
        SaToken::getConfig()->setTokenEncrypt(true)->setAesKey($aesKey);
        $this->manager->resetEncryptor();

        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $this->assertTrue($this->manager->isTokenValid($token));
        $this->assertEquals('10001', $this->manager->getLoginIdByToken($token));

        $tokens = $this->manager->getTokenListByLoginId(10001, 'login');
        $this->assertCount(1, $tokens);
        $this->assertEquals($token, $tokens[0]['tokenValue']);

        $this->manager->setSwitchTo($token, 20001, 'login');
        $this->assertEquals('20001', $this->manager->getSwitchTo($token, 'login'));

        $this->manager->openSafe($token, 'transfer', 120, 'login');
        $this->assertTrue($this->manager->isSafe($token, 'transfer', 'login'));

        $this->manager->disable(10001, 'comment', 2, 3600, 'login');
        $this->assertTrue($this->manager->isDisable(10001, 'comment', 'login'));
        $this->assertEquals(2, $this->manager->getDisableLevel(10001, 'comment', 'login'));

        $this->manager->deleteToken($token, 10001, 'login');
        $this->assertNull($this->manager->getLoginIdByToken($token));
    }

    public function testEncryptorDecryptRoundTrip(): void
    {
        $encryptor = new SaTokenEncryptor(true, 'test-encryption-key-at-least-32-bytes');
        $original = 'sensitive-login-id-10001';
        $encrypted = $encryptor->encrypt($original);
        $this->assertNotEquals($original, $encrypted);
        $decrypted = $encryptor->decrypt($encrypted);
        $this->assertEquals($original, $decrypted);
    }

    public function testEncryptorDisabledPassthrough(): void
    {
        $encryptor = new SaTokenEncryptor(false, 'test-key');
        $original = 'plain-value';
        $result = $encryptor->encrypt($original);
        $this->assertEquals($original, $result);
        $result = $encryptor->decrypt($original);
        $this->assertEquals($original, $result);
    }

    public function testEncryptorTamperDetection(): void
    {
        $encryptor = new SaTokenEncryptor(true, 'test-encryption-key-at-least-32-bytes');
        $original = 'secret-data';
        $encrypted = $encryptor->encrypt($original);

        $tampered = substr($encrypted, 0, -4) . base64_encode('XXXX');
        $result = $encryptor->decrypt($tampered);
        $this->assertEquals($tampered, $result);
    }

    public function testReleaseLockDeletesOnlyOwnedLock(): void
    {
        $key = 'login:test-user';
        $lockKey = TokenManager::LOCK_PREFIX . $key;

        $this->assertTrue($this->manager->acquireLock($key, 5));
        $this->assertNotNull($this->dao->get($lockKey));

        $this->dao->set($lockKey, 'other-owner', 5);
        $this->manager->releaseLock($key);

        $this->assertEquals('other-owner', $this->dao->get($lockKey));
    }

    public function testReleaseLockDeletesOwnedLock(): void
    {
        $key = 'login:test-user';
        $lockKey = TokenManager::LOCK_PREFIX . $key;

        $this->assertTrue($this->manager->acquireLock($key, 5));
        $this->manager->releaseLock($key);

        $this->assertNull($this->dao->get($lockKey));
    }

    public function testRenewLockExtendsOnlyTheCurrentOwnerLease(): void
    {
        $key = 'login:renew-user';
        $lockKey = TokenManager::LOCK_PREFIX . $key;

        self::assertTrue($this->manager->acquireLock($key, 1));
        self::assertTrue($this->manager->renewLock($key, 120));
        self::assertGreaterThan(0, $this->dao->getTimeout($lockKey));
        self::assertLessThanOrEqual(120, $this->dao->getTimeout($lockKey));

        $this->dao->set($lockKey, 'replacement-owner', 60);
        self::assertFalse($this->manager->renewLock($key, 120));
        self::assertSame('replacement-owner', $this->dao->get($lockKey));
        self::assertFalse($this->manager->renewLock($key, 120), '丢失租约后不得继续使用本地重入状态');
    }

    public function testReentrantLockRemainsHeldUntilEveryAcquireIsReleased(): void
    {
        $key = 'login:nested-user';
        $otherManager = new TokenManager();

        $this->assertTrue($this->manager->acquireLock($key, 5));
        $this->assertTrue($this->manager->acquireLock($key, 5));
        $this->manager->releaseLock($key);

        $this->assertFalse($otherManager->acquireLock($key, 5), '一次 release 不应释放仍有外层持有者的锁');

        $this->manager->releaseLock($key);
        $this->assertTrue($otherManager->acquireLock($key, 5));
        $otherManager->releaseLock($key);
    }

    public function testExpiredLockCannotBeReenteredAfterAnotherOwnerTakesOver(): void
    {
        $key = 'login:expired-nested-user';
        $lockKey = TokenManager::LOCK_PREFIX . $key;

        self::assertTrue($this->manager->acquireLock($key, 5));
        $this->dao->set($lockKey, 'replacement-owner', 5);

        self::assertFalse($this->manager->acquireLock($key, 5));
        self::assertSame('replacement-owner', $this->dao->get($lockKey));
    }

    public function testLockOwnershipIsIsolatedByRequestContext(): void
    {
        $key = 'login:shared-manager';
        SaTokenContext::setContextId('context-a');
        $this->assertTrue($this->manager->acquireLock($key, 5));

        SaTokenContext::setContextId('context-b');
        $this->assertFalse($this->manager->acquireLock($key, 5));

        SaTokenContext::setContextId('context-a');
        $this->manager->releaseLock($key);
        SaTokenContext::setContextId('context-b');
        $this->assertTrue($this->manager->acquireLock($key, 5));
        $this->manager->releaseLock($key);
    }
}
