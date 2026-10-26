<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;
use SaToken\Util\SaTokenContext;

class StpLogicAdvancedTest extends TestCase
{
    protected SaTokenDaoMemory $dao;
    protected StpLogic $logic;

    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        $this->dao = new SaTokenDaoMemory();
        SaToken::setDao($this->dao);
        $this->logic = new StpLogic('login');
    }

    protected function tearDown(): void
    {
        SaTokenContext::clear();
        SaToken::reset();
    }

    private function loginAndInjectToken(mixed $loginId = 10001, ?SaLoginParameter $param = null): string
    {
        $loginResult = $this->logic->login($loginId, $param);
        $token = $loginResult->getAccessToken();
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->with('satoken')->willReturn([$token]);
        SaTokenContext::setRequest($request);
        return $token;
    }

    public function testNonConcurrentModeKicksPreviousSession(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'concurrent'      => false,
            'isShare'         => true,
            'maxLoginCount'   => 12,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));

        $logic = new StpLogic('login');
        $loginResult1 = $logic->login(10001, new SaLoginParameter(['deviceType' => 'PC']));
        $token1 = $loginResult1->getAccessToken();
        $this->assertTrue($logic->getTokenManager()->isTokenValid($token1));

        $loginResult2 = $logic->login(10001, new SaLoginParameter(['deviceType' => 'PC']));
        $token2 = $loginResult2->getAccessToken();
        $this->assertFalse($logic->getTokenManager()->isTokenValid($token1));
        $this->assertTrue($logic->getTokenManager()->isTokenValid($token2));
    }

    public function testTokenManagerInjectionViaConstructor(): void
    {
        $customTokenManager = new TokenManager();
        $logic = new StpLogic('login', $customTokenManager);
        $this->assertSame($customTokenManager, $logic->getTokenManager());
    }

    public function testSetTokenManager(): void
    {
        $originalManager = $this->logic->getTokenManager();
        $newManager = new TokenManager();
        $this->logic->setTokenManager($newManager);
        $this->assertSame($newManager, $this->logic->getTokenManager());
        $this->assertNotSame($originalManager, $this->logic->getTokenManager());
    }

    public function testLoginWithTokenEncryptStoresEncryptedLoginId(): void
    {
        $aesKey = getenv('TEST_AES_KEY_32') ?: 'test-key-placeholder-32-bytes-lo';
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
            'tokenEncrypt'    => true,
            'aesKey'          => $aesKey,
        ]));

        $logic = new StpLogic('login');
        $loginResult = $logic->login(10001);
        $token = $loginResult->getAccessToken();

        $rawValue = $this->dao->get('satoken:login:token:' . $token);
        $this->assertNotNull($rawValue);
        $this->assertNotEquals('10001', $rawValue);

        $loginId = $logic->getTokenManager()->getLoginIdByToken($token);
        $this->assertEquals('10001', $loginId);
    }

    public function testEncryptedTokenRecordCannotBeCopiedToAnotherToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('t', 32),
            'aesKey' => str_repeat('t', 32),
        ]));
        $owner = $this->logic->login('owner')->getAccessToken();
        $other = $this->logic->login('other')->getAccessToken();
        $ownerRecord = $this->dao->get(TokenManager::TOKEN_PREFIX . $owner);
        $ownerLineage = $this->dao->get(TokenManager::TOKEN_SESSION_LINEAGE_PREFIX . $owner);
        self::assertNotNull($ownerRecord);
        self::assertNotNull($ownerLineage);
        $this->dao->set(TokenManager::TOKEN_PREFIX . $other, $ownerRecord);
        $this->dao->set(TokenManager::TOKEN_SESSION_LINEAGE_PREFIX . $other, $ownerLineage);

        self::assertNull($this->logic->getTokenManager()->getLoginIdByToken($other));
    }

    public function testEncryptedRefreshTokenRecordCannotBeCopiedToAnotherTokenKey(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('r', 32),
            'aesKey' => str_repeat('r', 32),
        ]));
        $victimAccessToken = $this->logic->login('victim')->getAccessToken();
        $victimRefreshToken = $this->logic->createRefreshToken($victimAccessToken, 3600);
        $attackerAccessToken = $this->logic->login('attacker')->getAccessToken();
        $attackerRefreshToken = $this->logic->createRefreshToken($attackerAccessToken, 3600);
        $victimRecord = $this->dao->get(TokenManager::REFRESH_TOKEN_PREFIX . $victimRefreshToken);
        self::assertNotNull($victimRecord);
        $this->dao->set(TokenManager::REFRESH_TOKEN_PREFIX . $attackerRefreshToken, $victimRecord);

        self::assertNull($this->logic->getTokenManager()->getRefreshTokenData($attackerRefreshToken));
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $this->logic->refreshToken($attackerRefreshToken);
    }

    public function testEncryptedSwitchIdentityCannotBeCopiedToAnotherToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('i', 32),
            'aesKey' => str_repeat('i', 32),
        ]));
        $victimToken = $this->logic->login('victim')->getAccessToken();
        $attackerToken = $this->logic->login('attacker')->getAccessToken();
        $this->logic->getTokenManager()->setSwitchTo($victimToken, 'administrator', 'login');
        $victimSwitch = $this->dao->get(TokenManager::SWITCH_PREFIX . 'login:' . $victimToken);
        self::assertNotNull($victimSwitch);
        $this->dao->set(TokenManager::SWITCH_PREFIX . 'login:' . $attackerToken, $victimSwitch);
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->with('satoken')->willReturn([$attackerToken]);
        SaTokenContext::setRequest($request);

        self::assertSame('attacker', $this->logic->getLoginId());
    }

    public function testEncryptedSafeWindowCannotBeCopiedToAnotherToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('s', 32),
            'aesKey' => str_repeat('s', 32),
        ]));
        $victimToken = $this->logic->login('victim')->getAccessToken();
        $attackerToken = $this->logic->login('attacker')->getAccessToken();
        $this->logic->getTokenManager()->openSafe($victimToken, 'pay', 3600, 'login');
        $serviceKey = hash('sha256', 'pay');
        $tokenKey = hash('sha256', $victimToken);
        $attackerKey = hash('sha256', $attackerToken);
        $victimSafeState = $this->dao->get('satoken:safe:v2:login:' . $tokenKey . ':' . $serviceKey);
        self::assertNotNull($victimSafeState);
        $this->dao->set('satoken:safe:v2:login:' . $attackerKey . ':' . $serviceKey, $victimSafeState);
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->with('satoken')->willReturn([$attackerToken]);
        SaTokenContext::setRequest($request);

        self::assertFalse($this->logic->isSafe('pay'));
    }

    public function testEncryptedActivityAndFingerprintRecordsCannotBeCopiedToAnotherToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('a', 32),
            'aesKey' => str_repeat('a', 32),
            'activityTimeout' => 3600,
        ]));
        $owner = $this->logic->login('owner')->getAccessToken();
        $other = $this->logic->login('other')->getAccessToken();
        $ownerActivityKey = TokenManager::LAST_ACTIVE_PREFIX . $owner;
        $otherActivityKey = TokenManager::LAST_ACTIVE_PREFIX . $other;
        $ownerFingerprintKey = TokenManager::FINGERPRINT_PREFIX . $owner;
        $otherFingerprintKey = TokenManager::FINGERPRINT_PREFIX . $other;
        $this->logic->getTokenManager()->updateLastActiveToNow($owner);
        $this->logic->getTokenManager()->saveFingerprint($owner, 'owner-fingerprint', 3600);
        $ownerActivity = $this->dao->get($ownerActivityKey);
        $ownerFingerprint = $this->dao->get($ownerFingerprintKey);
        self::assertNotNull($ownerActivity);
        self::assertNotNull($ownerFingerprint);
        $this->dao->set($otherActivityKey, $ownerActivity);
        $this->dao->set($otherFingerprintKey, $ownerFingerprint);

        self::assertNull($this->logic->getTokenManager()->getLastActiveTime($other));
        self::assertNull($this->logic->getTokenManager()->getFingerprint($other));
    }

    public function testLoginWithTokenEncryptSmCryptoType(): void
    {
        if (!class_exists(\CryptoSm\SM4\Sm4::class)) {
            $this->markTestSkipped('CryptoSm extension not available');
        }

        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
            'tokenEncrypt'    => true,
            'cryptoType'      => 'sm',
            'sm4Key'          => '0123456789abcdef0123456789abcdef',
        ]));

        $logic = new StpLogic('login');
        $loginResult = $logic->login(10001);
        $token = $loginResult->getAccessToken();

        $rawValue = $this->dao->get('satoken:login:token:' . $token);
        $this->assertNotNull($rawValue);
        $this->assertNotEquals('10001', $rawValue);

        $loginId = $logic->getTokenManager()->getLoginIdByToken($token);
        $this->assertEquals('10001', $loginId);
    }

    public function testLogoutRemovesTokenFromDao(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
            'isReadHeader'    => true,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        $this->logic = new StpLogic('login');

        $token = $this->loginAndInjectToken(10001);

        $this->assertTrue($this->logic->getTokenManager()->isTokenValid($token));
        $this->assertNotNull($this->dao->get('satoken:login:token:' . $token));

        $this->logic->logout();

        $this->assertFalse($this->logic->getTokenManager()->isTokenValid($token));
        $this->assertNull($this->dao->get('satoken:login:token:' . $token));
    }

    public function testGetTokenSessionReturnsSessionWithCorrectTimeout(): void
    {
        $timeout = 7200;
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => $timeout,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
            'isReadHeader'    => true,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        $this->logic = new StpLogic('login');
        $loginResult = $this->logic->login(10001);
        $token = $loginResult->getAccessToken();

        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->with('satoken')->willReturn([$token]);
        SaTokenContext::setRequest($request);

        $session = $this->logic->getTokenSession();
        $this->assertNotNull($session);

        $session->set('test', 'value');

        $sessionTimeout = $this->dao->getTimeout('satoken:tokenSession:' . $token);
        $this->assertGreaterThan(0, $sessionTimeout);
        $this->assertLessThanOrEqual($timeout, $sessionTimeout);
    }
}
