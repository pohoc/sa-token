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

class SaTokenDaoPausingRefreshWrite extends SaTokenDaoMemory
{
    public ?\Closure $beforeRefreshWrite = null;

    public function setIfNotExists(string $key, string $value, ?int $timeout = null): bool
    {
        if (str_starts_with($key, TokenManager::REFRESH_TOKEN_PREFIX) && $this->beforeRefreshWrite !== null) {
            $callback = $this->beforeRefreshWrite;
            $this->beforeRefreshWrite = null;
            $callback();
        }

        return parent::setIfNotExists($key, $value, $timeout);
    }
}

class SaTokenDaoFailingTokenDelete extends SaTokenDaoMemory
{
    public bool $failTokenDelete = false;

    public bool $failBulkTokenDelete = false;

    public function compareAndDelete(string $key, string $expectedValue): bool
    {
        if ($this->failTokenDelete && str_starts_with($key, TokenManager::TOKEN_PREFIX)) {
            throw new SaTokenException('simulated token delete failure');
        }

        return parent::compareAndDelete($key, $expectedValue);
    }

    public function deleteMultiple(array $keys): void
    {
        if ($this->failBulkTokenDelete) {
            foreach ($keys as $key) {
                if (str_starts_with($key, TokenManager::TOKEN_PREFIX)) {
                    throw new SaTokenException('simulated bulk token delete failure');
                }
            }
        }

        parent::deleteMultiple($keys);
    }
}

class SaTokenDaoRecreatingRefreshDuringAccountCleanup extends SaTokenDaoMemory
{
    public ?\Closure $duringRefreshAccountRead = null;

    public function get(string $key): ?string
    {
        if (str_starts_with($key, 'satoken:refreshAccount:') && $this->duringRefreshAccountRead !== null) {
            $callback = $this->duringRefreshAccountRead;
            $this->duringRefreshAccountRead = null;
            $callback();
        }

        return parent::get($key);
    }
}

class SaTokenDaoPausingRefreshDelete extends SaTokenDaoMemory
{
    public ?\Closure $afterRefreshRead = null;

    public function get(string $key): ?string
    {
        $value = parent::get($key);
        if (str_starts_with($key, TokenManager::REFRESH_TOKEN_PREFIX) && $this->afterRefreshRead !== null) {
            $callback = $this->afterRefreshRead;
            $this->afterRefreshRead = null;
            $callback($key, $value);
        }

        return $value;
    }
}

class SaTokenDaoInterleavingTokenDelete extends SaTokenDaoMemory
{
    public ?\Closure $beforeTokenDelete = null;

    protected function interleaveBeforeTokenDelete(): void
    {
        if ($this->beforeTokenDelete === null) {
            return;
        }
        $callback = $this->beforeTokenDelete;
        $this->beforeTokenDelete = null;
        $callback();
    }

    public function compareAndDelete(string $key, string $expectedValue): bool
    {
        if (str_starts_with($key, TokenManager::TOKEN_PREFIX) && $this->beforeTokenDelete !== null) {
            $this->interleaveBeforeTokenDelete();
        }

        return parent::compareAndDelete($key, $expectedValue);
    }

    public function deleteMultiple(array $keys): void
    {
        foreach ($keys as $key) {
            if (is_string($key) && str_starts_with($key, TokenManager::TOKEN_PREFIX)) {
                $this->interleaveBeforeTokenDelete();
                break;
            }
        }

        parent::deleteMultiple($keys);
    }
}

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

    public function testStaleRefreshTokenCleanupCannotDeleteReusedCredential(): void
    {
        $dao = new SaTokenDaoPausingRefreshDelete();
        $this->dao = $dao;
        SaToken::setDao($dao);
        $ownerA = 'refresh-delete-owner-a';
        $ownerB = 'refresh-delete-owner-b';
        $accessA = 'refresh-delete-access-a';
        $accessB = 'refresh-delete-access-b';
        $refresh = 'refresh-delete-shared-value';
        $this->manager->saveToken($accessA, $ownerA, 'login', 'PC', 3600);
        $this->manager->saveToken($accessB, $ownerB, 'login', 'PC', 3600);
        $this->manager->saveRefreshToken($refresh, $accessA, $ownerA, 'login', 3600);

        $refreshKey = TokenManager::REFRESH_TOKEN_PREFIX . $refresh;
        $credentialLockKey = TokenManager::LOCK_PREFIX . 'refresh-credential:' . hash('sha256', $refresh);
        $dao->afterRefreshRead = function (string $key, ?string $snapshot) use ($dao, $refreshKey, $credentialLockKey, $refresh, $accessB, $ownerB): void {
            if ($key !== $refreshKey || $snapshot === null) {
                return;
            }

            // The stale cleanup has captured owner A's bytes. Expire its lease,
            // consume/delete that generation, then let owner B reuse the value.
            $dao->delete($credentialLockKey);
            $dao->delete($refreshKey);
            SaTokenContext::setContextId('refresh-reissue-worker');
            try {
                $this->manager->saveRefreshToken($refresh, $accessB, $ownerB, 'login', 3600);
            } finally {
                SaTokenContext::setContextId('default');
            }
        };

        $this->manager->deleteRefreshToken($refresh);

        self::assertSame($ownerB, $this->manager->getRefreshTokenData($refresh)['loginId'] ?? null);
    }

    public function testAccountLogoutCannotBulkDeleteReusedRefreshCredential(): void
    {
        $dao = new SaTokenDaoInterleavingTokenDelete();
        $this->dao = $dao;
        SaToken::setDao($dao);
        $ownerA = 'bulk-logout-refresh-owner-a';
        $ownerB = 'bulk-logout-refresh-owner-b';
        $accessA = 'bulk-logout-refresh-access-a';
        $accessB = 'bulk-logout-refresh-access-b';
        $refresh = 'bulk-logout-refresh-shared-value';
        $this->manager->saveToken($accessA, $ownerA, 'login', 'PC', 3600);
        $this->manager->saveToken($accessB, $ownerB, 'login', 'PC', 3600);
        $this->manager->saveRefreshToken($refresh, $accessA, $ownerA, 'login', 3600);

        $refreshKey = TokenManager::REFRESH_TOKEN_PREFIX . $refresh;
        $dao->beforeTokenDelete = function () use ($dao, $refreshKey, $refresh, $accessB, $ownerB): void {
            // The logout selected owner A's refresh key. Reuse it for owner B
            // immediately before the old access-token generation is revoked.
            $dao->delete($refreshKey);
            SaTokenContext::setContextId('bulk-delete-reissue-worker');
            try {
                $this->manager->saveRefreshToken($refresh, $accessB, $ownerB, 'login', 3600);
            } finally {
                SaTokenContext::setContextId('default');
            }
        };

        $this->manager->deleteAllTokenByLoginId($ownerA, 'login');

        self::assertSame($ownerB, $this->manager->getRefreshTokenData($refresh)['loginId'] ?? null);
    }

    public function testAccountLogoutCannotDeleteReusedAccessTokenGeneration(): void
    {
        $dao = new SaTokenDaoInterleavingTokenDelete();
        $this->dao = $dao;
        SaToken::setDao($dao);
        $ownerA = 'bulk-logout-token-owner-a';
        $ownerB = 'bulk-logout-token-owner-b';
        $token = 'bulk-logout-token-shared-value';
        $this->manager->saveToken($token, $ownerA, 'old-type', 'PC', 3600);

        $tokenKey = TokenManager::TOKEN_PREFIX . $token;
        $tokenLockKey = TokenManager::LOCK_PREFIX . 'token-value:' . hash('sha256', $token);
        $dao->beforeTokenDelete = function () use ($dao, $tokenKey, $tokenLockKey, $token, $ownerB): void {
            $dao->delete($tokenKey);
            $dao->delete(TokenManager::TOKEN_SESSION_LINEAGE_PREFIX . $token);
            $dao->delete($tokenLockKey);
            SaTokenContext::setContextId('bulk-token-reissue-worker');
            try {
                $this->manager->saveToken($token, $ownerB, 'new-type', 'PC', 3600);
            } finally {
                SaTokenContext::setContextId('default');
            }
        };

        $this->manager->deleteAllTokenByLoginId($ownerA, 'old-type');

        // The old logout's bearer is blacklisted, so a concurrent replacement
        // must receive a fresh value instead of making the old copy valid.
        self::assertNull($this->manager->getLoginIdByToken($token));
        self::assertTrue($this->manager->isBlacklisted($token));
        $replacementTokens = $this->manager->getTokenListByLoginId($ownerB, 'new-type');
        self::assertCount(1, $replacementTokens);
        $replacementToken = $replacementTokens[0]['tokenValue'];
        self::assertIsString($replacementToken);
        self::assertNotSame($token, $replacementToken);
        self::assertSame($ownerB, $this->manager->getLoginIdByToken($replacementToken));
    }

    public function testNearExpiryRevocationMarkerDoesNotBecomePermanent(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public function getTimeout(string $key): int
            {
                if (str_starts_with($key, TokenManager::TOKEN_PREFIX)) {
                    return 0;
                }
                return parent::getTimeout($key);
            }
        };
        $this->dao = $dao;
        SaToken::setDao($dao);
        $token = $this->manager->saveToken('near-expiry-token-value', 'near-expiry-user', 'login', 'PC', 3600);

        $this->manager->deleteToken($token, 'near-expiry-user', 'login');

        $blacklistTimeout = $dao->getTimeout(TokenManager::BLACKLIST_PREFIX . $token);
        self::assertNotSame(-1, $blacklistTimeout, '零秒 TTL 应转换成有限的一秒保留期');
        self::assertLessThanOrEqual(1, $blacklistTimeout);
    }

    public function testDeletedRefreshTokenCannotBeReissuedToAnotherAccount(): void
    {
        $accessA = $this->manager->saveToken('refresh-owner-a-access', 'refresh-owner-a', 'login', 'PC', 3600);
        $accessB = $this->manager->saveToken('refresh-owner-b-access', 'refresh-owner-b', 'login', 'PC', 3600);
        $refresh = 'srt_reused-refresh-bearer-value';
        $this->manager->saveRefreshToken($refresh, $accessA, 'refresh-owner-a', 'login', 3600);
        $this->manager->deleteRefreshToken($refresh);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('该凭据已消费');
        $this->manager->saveRefreshToken($refresh, $accessB, 'refresh-owner-b', 'login', 3600);
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

    public function testLogoutDoesNotRevokeTokenFromAnotherLoginTypeViaStaleIndex(): void
    {
        $owner = new StpLogic('owner');
        $otherType = new StpLogic('other');
        $token = $otherType->login('shared-login-id')->getAccessToken();
        $ownerListKey = TokenManager::buildLoginIdKey('owner', 'shared-login-id');
        $this->dao->set($ownerListKey, json_encode([[
            'tokenValue' => $token,
            'deviceType' => '',
            'createTime' => time(),
        ]], JSON_THROW_ON_ERROR), 3600);

        $this->manager->deleteAllTokenByLoginId('shared-login-id', 'owner');

        self::assertSame('shared-login-id', $otherType->getLoginIdByToken($token));
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

    public function testDeleteTokenDoesNotRemoveAccountIndexWhenBearerRevocationFails(): void
    {
        $dao = new SaTokenDaoFailingTokenDelete();
        SaToken::setDao($dao);
        $manager = new TokenManager();
        $token = $manager->createTokenValue('user-1', 'login');
        $manager->saveToken($token, 'user-1', 'login', 'PC', 3600);
        $dao->failTokenDelete = true;

        try {
            $manager->deleteToken($token, 'user-1', 'login');
            self::fail('Expected the simulated bearer revocation failure');
        } catch (SaTokenException $exception) {
            self::assertSame('simulated token delete failure', $exception->getMessage());
        }

        self::assertSame('user-1', $manager->getLoginIdByToken($token));
        self::assertCount(1, $manager->getTokenListByLoginId('user-1', 'login'));

        $dao->failTokenDelete = false;
        $manager->deleteToken($token, 'user-1', 'login');
        self::assertNull($manager->getLoginIdByToken($token));
        self::assertSame([], $manager->getTokenListByLoginId('user-1', 'login'));
    }

    public function testDeleteTokenCannotDeleteAnotherAccountsToken(): void
    {
        $token = $this->manager->createTokenValue('victim', 'login');
        $this->manager->saveToken($token, 'victim', 'login', 'PC', 3600);

        $this->manager->deleteToken($token, 'attacker', 'login');

        self::assertSame('victim', $this->manager->getLoginIdByToken($token));
    }

    public function testDeleteTokenCannotDeleteTokenFromAnotherLoginType(): void
    {
        $token = $this->manager->createTokenValue('victim', 'admin');
        $this->manager->saveToken($token, 'victim', 'admin', 'PC', 3600);

        $this->manager->deleteToken($token, 'victim', 'user');

        self::assertSame('victim', $this->manager->getLoginIdByToken($token));
    }

    public function testDeleteTokenCannotDeleteReusedBearerThroughStaleLoginTypeIndex(): void
    {
        $token = 'reused-cross-login-type-token';
        $this->manager->saveToken($token, 'same-user', 'old', 'PC', 3600);
        $this->manager->saveToken('old-type-keep-token', 'same-user', 'old', 'mobile', 3600);

        // An expired bearer can disappear while another old-type session
        // keeps its account index alive. Simulate its reuse by another type.
        $this->dao->delete(TokenManager::TOKEN_PREFIX . $token);
        $this->dao->delete(TokenManager::TOKEN_SESSION_LINEAGE_PREFIX . $token);
        $this->manager->saveToken($token, 'same-user', 'new', 'PC', 3600);

        $this->manager->deleteToken($token, 'same-user', 'old');

        self::assertSame('same-user', $this->manager->getLoginIdByToken($token));
        self::assertSame('new', $this->manager->getTokenSessionLoginType($token));
    }

    public function testSaveRefreshTokenRejectsAccessTokenOwnedByAnotherAccount(): void
    {
        $accessToken = $this->manager->createTokenValue('victim', 'login');
        $this->manager->saveToken($accessToken, 'victim', 'login', 'PC', 3600);
        $refreshToken = $this->manager->createTokenValue('attacker', 'login', 'srt_');

        try {
            $this->manager->saveRefreshToken($refreshToken, $accessToken, 'attacker', 'login', 3600);
            self::fail('Expected refresh-token association to be rejected');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('不属于指定账号', $exception->getMessage());
        }

        self::assertNull($this->manager->getRefreshTokenData($refreshToken));
        self::assertSame('victim', $this->manager->getLoginIdByToken($accessToken));
    }

    public function testSaveRefreshTokenRejectsUnknownAccessToken(): void
    {
        try {
            $this->manager->saveRefreshToken('unknown-access-refresh', 'unknown-access', 'victim', 'login', 3600);
            self::fail('Expected unknown access token to be rejected');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('AccessToken 无效', $exception->getMessage());
        }

        self::assertNull($this->manager->getRefreshTokenData('unknown-access-refresh'));
    }

    public function testSaveRefreshTokenDoesNotSurviveAccountRevocationAfterLeaseLoss(): void
    {
        $dao = new SaTokenDaoPausingRefreshWrite();
        SaToken::setDao($dao);
        $manager = new TokenManager();
        $loginId = 'refresh-lease-revocation-user';
        $loginType = 'login';
        $accessToken = $manager->createTokenValue($loginId, $loginType);
        $manager->saveToken($accessToken, $loginId, $loginType, 'PC', 3600);
        $refreshToken = $manager->createTokenValue($loginId, $loginType, 'srt_');

        $dao->beforeRefreshWrite = static function () use ($dao, $loginId, $loginType): void {
            $accountLock = TokenManager::LOCK_PREFIX . 'login:' . $loginType . ':' . hash('sha256', $loginId);
            $dao->delete($accountLock);
            (new TokenManager())->deleteAllTokenByLoginId($loginId, $loginType);
        };

        try {
            $manager->saveRefreshToken($refreshToken, $accessToken, $loginId, $loginType, 3600);
            self::fail('失去账号锁租约后的 RefreshToken 保存必须失败');
        } catch (SaTokenException $exception) {
            self::assertTrue(
                str_contains($exception->getMessage(), '已失效')
                || str_contains($exception->getMessage(), '正在签发或消费')
            );
        }

        self::assertFalse($manager->isRefreshTokenValid($refreshToken));
        self::assertNull($manager->getRefreshTokenByAccessToken($loginId, $loginType, $accessToken));
        self::assertNull((new StpLogic($loginType, $manager))->getLoginIdByToken($accessToken));
    }

    public function testAccountLogoutCannotDeleteRefreshTokenFromNewSessionAfterLockLeaseLoss(): void
    {
        $dao = new SaTokenDaoRecreatingRefreshDuringAccountCleanup();
        SaToken::setDao($dao);
        $manager = new TokenManager();
        $loginId = 'refresh-account-cleanup-lease-user';
        $loginType = 'login';

        $oldAccessToken = $manager->createTokenValue($loginId, $loginType);
        $manager->saveToken($oldAccessToken, $loginId, $loginType, 'PC', 3600);
        $oldRefreshToken = $manager->createTokenValue($loginId, $loginType, 'srt_');
        $manager->saveRefreshToken($oldRefreshToken, $oldAccessToken, $loginId, $loginType, 3600);

        $newAccessToken = '';
        $newRefreshToken = '';
        $dao->duringRefreshAccountRead = function () use ($dao, $loginId, $loginType, &$newAccessToken, &$newRefreshToken): void {
            // The bulk logout has removed the old access and refresh records.
            // Let a second worker take over its expired account lock and commit
            // a fresh session immediately before the stale cleanup reads the
            // current refresh-token account index.
            $dao->delete(TokenManager::LOCK_PREFIX . 'login:' . $loginType . ':' . hash('sha256', $loginId));
            $newManager = new TokenManager();
            $newAccessToken = $newManager->createTokenValue($loginId, $loginType);
            $newManager->saveToken($newAccessToken, $loginId, $loginType, 'mobile', 3600);
            $newRefreshToken = $newManager->createTokenValue($loginId, $loginType, 'srt_');
            $newManager->saveRefreshToken($newRefreshToken, $newAccessToken, $loginId, $loginType, 3600);
        };

        try {
            $manager->deleteAllTokenByLoginId($loginId, $loginType);
            self::fail('失去账号锁租约的旧登出操作必须停止清理');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('租约已失效', $exception->getMessage());
        }

        self::assertNotSame('', $newAccessToken);
        self::assertNotSame('', $newRefreshToken);
        self::assertSame($loginId, $manager->getLoginIdByToken($newAccessToken));
        self::assertNull($manager->getRefreshTokenData($oldRefreshToken));
        self::assertNotNull(
            $manager->getRefreshTokenData($newRefreshToken),
            '过期账号锁的清理者不能撤销新持有者刚签发的 RefreshToken'
        );
    }

    public function testSaveRefreshTokenValidatesStatelessJwtOwner(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'activityTimeout' => -1,
        ]));
        $logic = new StpLogic('login', $this->manager);
        $accessToken = $logic->loginStateless('victim');

        try {
            $this->manager->saveRefreshToken('stateless-refresh-token', $accessToken, 'attacker', 'login', 3600);
            self::fail('Expected stateless JWT owner mismatch to be rejected');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('不属于指定账号', $exception->getMessage());
        }

        self::assertNull($this->manager->getRefreshTokenData('stateless-refresh-token'));
        $this->manager->saveRefreshToken('valid-stateless-refresh-token', $accessToken, 'victim', 'login', 3600);
        $refreshData = $this->manager->getRefreshTokenData('valid-stateless-refresh-token');
        self::assertIsArray($refreshData);
        self::assertSame('victim', $refreshData['loginId'] ?? null);
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

    public function testDeleteAllTokensKeepsAccountIndexWhenBearerDeletionFails(): void
    {
        $dao = new SaTokenDaoFailingTokenDelete();
        SaToken::setDao($dao);
        $manager = new TokenManager();
        $token = $manager->createTokenValue('user-2', 'login');
        $manager->saveToken($token, 'user-2', 'login', 'PC', 3600);
        $dao->failTokenDelete = true;

        try {
            $manager->deleteAllTokenByLoginId('user-2', 'login');
            self::fail('Expected the simulated bearer deletion failure');
        } catch (SaTokenException $exception) {
            self::assertSame('simulated token delete failure', $exception->getMessage());
        }

        self::assertSame('user-2', $manager->getLoginIdByToken($token));
        self::assertCount(1, $manager->getTokenListByLoginId('user-2', 'login'));

        $dao->failTokenDelete = false;
        $manager->deleteAllTokenByLoginId('user-2', 'login');
        self::assertNull($manager->getLoginIdByToken($token));
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
        $accessTokenA = $this->manager->createTokenValue('b:c', 'a');
        $accessTokenB = $this->manager->createTokenValue('c', 'a:b');
        $refreshTokenA = 'refresh-token-a';
        $refreshTokenB = 'refresh-token-b';
        $this->manager->saveToken($accessTokenA, 'b:c', 'a');
        $this->manager->saveToken($accessTokenB, 'c', 'a:b');
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

    public function testCopiedEncryptedAccountIndexCannotDiscloseAnotherAccountBearer(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'timeout' => 3600,
            'tokenEncrypt' => true,
            'aesKey' => 'account-index-context-test-key-32-bytes',
        ]));

        $ownerToken = $this->manager->createTokenValue('account-index-owner', 'login');
        $this->manager->saveToken($ownerToken, 'account-index-owner', 'login');
        $victimToken = $this->manager->createTokenValue('account-index-victim', 'login');
        $this->manager->saveToken($victimToken, 'account-index-victim', 'login');

        $ownerKey = TokenManager::buildLoginIdKey('login', 'account-index-owner');
        $victimKey = TokenManager::buildLoginIdKey('login', 'account-index-victim');
        $victimIndex = $this->dao->get($victimKey);
        self::assertNotNull($victimIndex);

        // Simulate a storage record transplant: the writer can copy a valid
        // encrypted value but cannot forge or decrypt the victim's index.
        $this->dao->set($ownerKey, $victimIndex);

        try {
            $this->manager->getTokenListByLoginId('account-index-owner', 'login');
            self::fail('A context-bound index copied from another account must be rejected');
        } catch (SaTokenException $exception) {
            self::assertSame('Token 存储数据完整性校验失败', $exception->getMessage());
        }
        self::assertSame(
            $victimIndex,
            $this->dao->get($victimKey),
            'Rejecting a foreign index must not mutate the victim account record'
        );
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

    public function testLegacyRefreshIndexMigrationCannotOverwriteConcurrentLogin(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public ?string $triggerKey = null;
            public ?\Closure $duringRead = null;

            public function getTimeout(string $key): int
            {
                $timeout = parent::getTimeout($key);
                if ($key === $this->triggerKey && $this->duringRead !== null) {
                    $callback = $this->duringRead;
                    $this->duringRead = null;
                    $callback();
                }

                return $timeout;
            }
        };
        SaToken::setDao($dao);
        $manager = new TokenManager();
        $loginId = 'legacy-refresh-race-user';
        $loginType = 'user';
        $accessToken = $manager->createTokenValue($loginId, $loginType);
        $manager->saveToken($accessToken, $loginId, $loginType, 'PC', 3600);

        $loginIdKey = TokenManager::buildLoginIdKey($loginType, $loginId);
        $legacyList = $manager->getTokenListByLoginId($loginId, $loginType);
        $encrypt = new \ReflectionMethod(TokenManager::class, 'encryptValue');
        $legacyValue = $encrypt->invoke($manager, json_encode($legacyList));
        self::assertIsString($legacyValue);
        $dao->delete($loginIdKey);
        $dao->set(TokenManager::LOGIN_ID_PREFIX . $loginType . ':' . $loginId, $legacyValue);

        $freshToken = null;
        $dao->triggerKey = TokenManager::TOKEN_PREFIX . $accessToken;
        $dao->duringRead = function () use ($dao, $loginId, $loginType, &$freshToken): void {
            // Simulate the old request's 30-second account-lock lease expiring
            // while it scans a large legacy index. A new login then commits its
            // V2 list before the old migration attempts to write.
            $accountLock = TokenManager::LOCK_PREFIX . 'login:' . $loginType . ':' . hash('sha256', $loginId);
            $dao->delete($accountLock);

            $concurrentManager = new TokenManager();
            $freshToken = $concurrentManager->createTokenValue($loginId, $loginType);
            $concurrentManager->saveToken($freshToken, $loginId, $loginType, 'mobile', 3600);
        };

        $refreshToken = $manager->createTokenValue($loginId, $loginType, 'srt_');
        try {
            $manager->saveRefreshToken($refreshToken, $accessToken, $loginId, $loginType, 7200);
            self::fail('失去账号锁租约的迁移请求不得继续绑定 RefreshToken');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('锁', $exception->getMessage());
        }

        self::assertIsString($freshToken);
        self::assertContains($freshToken, array_column($manager->getTokenListByLoginId($loginId, $loginType), 'tokenValue'));
        self::assertFalse($manager->isRefreshTokenValid($refreshToken));
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

    public function testUntieDisableSerializesWithAnInProgressAccountOperation(): void
    {
        $loginId = 'disable-unlock-race';
        $this->manager->disable($loginId, 'login', 1, 3600, 'login');
        $lockKey = 'login:login:' . hash('sha256', $loginId);

        SaTokenContext::setContextId('disable-lock-owner');
        $otherManager = new TokenManager();
        self::assertTrue($otherManager->acquireLock($lockKey, 30));
        SaTokenContext::setContextId('default');

        try {
            $this->manager->untieDisable($loginId, 'login', 'login');
            self::fail('账号锁被其他请求持有时，解封必须等待而不能越过封禁状态变更');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('处理中', $exception->getMessage());
        } finally {
            SaTokenContext::setContextId('disable-lock-owner');
            $otherManager->releaseLock($lockKey);
            SaTokenContext::setContextId('default');
        }

        self::assertTrue($this->manager->isDisable($loginId, 'login', 'login'));
    }

    public function testStaleUntieDisableCannotDeleteANewerBanAfterLeaseExpires(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public ?\Closure $duringDisableRead = null;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if (str_starts_with($key, 'satoken:disable:') && $this->duringDisableRead !== null) {
                    $callback = $this->duringDisableRead;
                    $this->duringDisableRead = null;
                    $callback();
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $loginId = 'stale-disable-unban';
        $this->manager->disable($loginId, 'login', 1, 3600, 'login');
        $lockKey = 'login:login:' . hash('sha256', $loginId);
        $dao->duringDisableRead = function () use ($dao, $lockKey, $loginId): void {
            // The unban has read the old record. Simulate its lease expiring,
            // then let another request install a newer ban before its CAS.
            $dao->delete(TokenManager::LOCK_PREFIX . $lockKey);
            SaTokenContext::setContextId('new-disable-owner');
            try {
                (new TokenManager())->disable($loginId, 'login', 2, 3600, 'login');
            } finally {
                SaTokenContext::setContextId('default');
            }
        };

        try {
            $this->manager->untieDisable($loginId, 'login', 'login');
            self::fail('过期租约的解封不得删除更新后的封禁记录');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('并发变更', $exception->getMessage());
        }

        self::assertTrue($this->manager->isDisable($loginId, 'login', 'login'));
        self::assertSame(2, $this->manager->getDisableLevel($loginId, 'login', 'login'));
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

    public function testCopiedRefreshTokenMapRecordCannotExposeAnotherAccountsCredential(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('p', 32),
            'aesKey' => str_repeat('p', 32),
        ]));
        $logic = new StpLogic('login', $this->manager);
        $ownerAccess = $logic->login('owner')->getAccessToken();
        $ownerRefresh = $logic->createRefreshToken($ownerAccess, 3600);
        $otherAccess = $logic->login('other')->getAccessToken();
        $logic->createRefreshToken($otherAccess, 3600);
        $ownerMapKey = TokenManager::REFRESH_TOKEN_MAP_PREFIX . 'login:owner:' . $ownerAccess;
        $otherMapKey = TokenManager::REFRESH_TOKEN_MAP_PREFIX . 'login:other:' . $otherAccess;
        $otherMapRecord = $this->dao->get($otherMapKey);
        self::assertNotNull($otherMapRecord);
        $this->dao->set($ownerMapKey, $otherMapRecord);

        self::assertNull($this->manager->getRefreshTokenByAccessToken('owner', 'login', $ownerAccess));
    }

    public function testOpenSafeRejectsNonPositiveWindow(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', -1);

        try {
            $this->manager->openSafe($token, 'transfer', 0, 'login');
            self::fail('安全窗口不能为零');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('正整数', $exception->getMessage());
        }
    }

    public function testOpenSafeRejectsDurationThatWouldOverflowExpiry(): void
    {
        SaToken::getConfig()->setTimeout(-1);
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', -1);

        try {
            $this->manager->openSafe($token, 'transfer', PHP_INT_MAX, 'login');
            self::fail('安全窗口超出可表示时间时必须拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('可表示', $exception->getMessage());
        }
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

    public function testSetSwitchToRejectsInvalidIdentityValues(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        foreach ([null, '', false, true, [], new \stdClass()] as $invalidLoginId) {
            try {
                $this->manager->setSwitchTo($token, $invalidLoginId, 'login');
                self::fail('底层身份切换不得接受空值、布尔值或非标量值');
            } catch (SaTokenException $exception) {
                self::assertStringContainsString('非空、非布尔标量', $exception->getMessage());
            }
        }

        self::assertNull($this->manager->getSwitchTo($token, 'login'));
    }

    public function testSetSwitchToRejectsOversizedIdentityValues(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        try {
            $this->manager->setSwitchTo($token, str_repeat('x', TokenManager::MAX_LOGIN_ID_BYTES + 1), 'login');
            self::fail('身份切换不能存储超长目标 loginId');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('loginId 长度无效', $exception->getMessage());
        }

        self::assertNull($this->manager->getSwitchTo($token, 'login'));
    }

    public function testOpenSafeBoundsServiceNameAndPerTokenRegistry(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        try {
            $this->manager->openSafe($token, str_repeat('s', TokenManager::MAX_SERVICE_NAME_BYTES + 1), 60, 'login');
            self::fail('安全场景 service 名称必须有长度上限');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('service 长度不能超过', $exception->getMessage());
        }

        for ($index = 0; $index < TokenManager::MAX_SAFE_SERVICES_PER_TOKEN; $index++) {
            $this->manager->openSafe($token, 'scope-' . $index, 60, 'login');
        }

        try {
            $this->manager->openSafe($token, 'scope-overflow', 60, 'login');
            self::fail('单个 Token 的安全场景索引必须有数量上限');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('安全场景数量不能超过', $exception->getMessage());
        }

        $registeredServices = (new \ReflectionMethod(TokenManager::class, 'getSafeServices'))
            ->invoke($this->manager, $token, 'login');
        self::assertIsArray($registeredServices);
        self::assertCount(TokenManager::MAX_SAFE_SERVICES_PER_TOKEN, $registeredServices);

        // Renewing an already indexed service remains valid at the limit.
        $this->manager->openSafe($token, 'scope-0', 60, 'login');
    }

    public function testDisableRejectsOversizedLoginIdBeforeWriting(): void
    {
        $loginId = str_repeat('d', TokenManager::MAX_LOGIN_ID_BYTES + 1);
        $lockKey = TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', $loginId);

        try {
            $this->manager->disable($loginId, 'login', 1, 60, 'login');
            self::fail('封禁入口必须拒绝超长 loginId');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('loginId 长度无效', $exception->getMessage());
        }

        self::assertNull($this->dao->get($lockKey));
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

    public function testInjectedTokenManagerDoesNotKeepOldEncryptionKeyAfterRotation(): void
    {
        $oldKey = 'old-injected-token-manager-key-32-bytes';
        $newKey = 'new-injected-token-manager-key-32-bytes';
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => $oldKey,
        ]));

        $manager = new TokenManager();
        $logic = new StpLogic('login', $manager);
        $token = $manager->createTokenValue('rotation-user', 'login');
        $token = $manager->saveToken($token, 'rotation-user', 'login');
        self::assertSame('rotation-user', $logic->getLoginIdByToken($token));

        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => $newKey,
        ]));

        self::assertNull($manager->getLoginIdByToken($token), '手动注入的 TokenManager 不得在密钥轮换后继续解密旧会话记录');
    }

    public function testInjectedTokenManagerDoesNotKeepOldJwtKeyAfterRotation(): void
    {
        $oldKey = 'old-injected-token-manager-jwt-key-32-bytes';
        $newKey = 'new-injected-token-manager-jwt-key-32-bytes';
        SaToken::setConfig(new SaTokenConfig([
            'jwtMode' => 'mixed',
            'jwtSecretKey' => $oldKey,
        ]));

        $manager = new TokenManager();
        $token = $manager->createTokenValue('rotation-user', 'login');
        $token = $manager->saveToken($token, 'rotation-user', 'login');
        self::assertSame('rotation-user', $manager->getLoginIdByToken($token));

        SaToken::setConfig(new SaTokenConfig([
            'jwtMode' => 'mixed',
            'jwtSecretKey' => $newKey,
        ]));

        self::assertNull($manager->getLoginIdByToken($token), 'TokenManager 不得在 JWT 密钥轮换后继续接受旧签名');
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
