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
