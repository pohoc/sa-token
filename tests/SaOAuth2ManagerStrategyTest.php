<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\SaOAuth2Config;
use SaToken\OAuth2\SaOAuth2Manager;
use SaToken\OAuth2\Strategy\AuthorizationCodeStrategy;
use SaToken\OAuth2\Strategy\ClientCredentialsStrategy;
use SaToken\OAuth2\Strategy\PasswordStrategy;
use SaToken\SaToken;

class SaOAuth2ManagerStrategyTest extends TestCase
{
    protected SaOAuth2Manager $manager;
    protected SaOAuth2Config $config;
    protected SaOAuth2Client $testClient;

    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        SaToken::setDao(new SaTokenDaoMemory());

        $this->config = new SaOAuth2Config([
            'grantTypes'          => ['authorization_code', 'password', 'client_credentials'],
            'codeTimeout'         => 300,
            'accessTokenTimeout'  => 7200,
            'refreshTokenTimeout' => 86400,
            'isNewRefreshToken'   => true,
        ]);

        $this->manager = new SaOAuth2Manager($this->config);

        $this->testClient = new SaOAuth2Client([
            'clientId'     => 'test-client',
            'clientSecret' => 'mock-client-secret-for-testing',
            'clientName'   => 'Test Client',
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes'   => ['authorization_code', 'password', 'client_credentials'],
            'scopes'       => ['read', 'write'],
        ]);

        $this->manager->registerClient($this->testClient);
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testGetAuthorizationCodeStrategyReturnsCorrectInstance(): void
    {
        $strategy = $this->manager->getAuthorizationCodeStrategy();
        $this->assertInstanceOf(AuthorizationCodeStrategy::class, $strategy);
    }

    public function testGetPasswordStrategyReturnsCorrectInstance(): void
    {
        $strategy = $this->manager->getPasswordStrategy();
        $this->assertInstanceOf(PasswordStrategy::class, $strategy);
    }

    public function testGetClientCredentialsStrategyReturnsCorrectInstance(): void
    {
        $strategy = $this->manager->getClientCredentialsStrategy();
        $this->assertInstanceOf(ClientCredentialsStrategy::class, $strategy);
    }

    public function testFullAuthorizationCodeFlowViaManager(): void
    {
        $code = $this->manager->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'read'
        );
        $this->assertNotEmpty($code->getCode());
        $this->assertEquals('test-client', $code->getClientId());
        $this->assertEquals(10001, $code->getLoginId());

        $accessToken = $this->manager->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            'mock-client-secret-for-testing',
            'https://example.com/callback'
        );
        $this->assertNotEmpty($accessToken->getAccessToken());
        $this->assertEquals('Bearer', $accessToken->getTokenType());
        $this->assertEquals(10001, $accessToken->getLoginId());
        $this->assertEquals('test-client', $accessToken->getClientId());

        $validated = $this->manager->validateAccessToken($accessToken->getAccessToken());
        $this->assertNotNull($validated);
        $this->assertEquals($accessToken->getAccessToken(), $validated->getAccessToken());
        $this->assertEquals(10001, $validated->getLoginId());

        $this->manager->revokeAccessToken($accessToken->getAccessToken());
        $revoked = $this->manager->validateAccessToken($accessToken->getAccessToken());
        $this->assertNull($revoked);
    }

    public function testTokenByPasswordViaManager(): void
    {
        $this->manager->getHandle()->setUserCredentialsValidator(function (string $username, string $password): ?int {
            if ($username === 'admin' && $password === 'secret') {
                return 20001;
            }
            return null;
        });

        $accessToken = $this->manager->tokenByPassword(
            'test-client',
            'mock-client-secret-for-testing',
            'admin',
            'secret',
            'read'
        );

        $this->assertNotEmpty($accessToken->getAccessToken());
        $this->assertEquals(20001, $accessToken->getLoginId());
        $this->assertEquals('test-client', $accessToken->getClientId());
        $this->assertEquals('read', $accessToken->getScope());
    }

    public function testTokenByClientCredentialsViaManager(): void
    {
        $accessToken = $this->manager->tokenByClientCredentials(
            'test-client',
            'mock-client-secret-for-testing',
            'read'
        );

        $this->assertNotEmpty($accessToken->getAccessToken());
        $this->assertEquals('client:test-client', $accessToken->getLoginId());
        $this->assertEquals('test-client', $accessToken->getClientId());
        $this->assertEquals('read', $accessToken->getScope());
    }

    public function testRefreshTokenViaManager(): void
    {
        $code = $this->manager->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'read'
        );
        $accessToken = $this->manager->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            'mock-client-secret-for-testing',
            'https://example.com/callback'
        );

        $refreshToken = $accessToken->getRefreshToken();
        $this->assertNotNull($refreshToken);

        $newAccessToken = $this->manager->refreshToken(
            $refreshToken,
            'test-client',
            'mock-client-secret-for-testing'
        );

        $this->assertNotEmpty($newAccessToken->getAccessToken());
        $this->assertNotEquals($accessToken->getAccessToken(), $newAccessToken->getAccessToken());
        $this->assertEquals(10001, $newAccessToken->getLoginId());
        $this->assertEquals('test-client', $newAccessToken->getClientId());
        $this->assertNotNull($newAccessToken->getRefreshToken());
    }
}
