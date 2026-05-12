<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\StpUtil;
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
        $this->assertFalse($result->hasRefreshToken());

        $this->assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($result->getAccessToken()));
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

        $this->expectException(SaTokenException::class);
        StpUtil::refreshToken($refreshToken);
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
