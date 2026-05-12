<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\Data\SaOAuth2RefreshToken;
use SaToken\OAuth2\SaOAuth2Config;
use SaToken\OAuth2\SaOAuth2Handle;
use SaToken\OAuth2\SaOAuth2Manager;
use SaToken\SaToken;

/**
 * OAuth2 模块完整测试
 *
 * 覆盖：授权码模式、密码模式、客户端凭证模式、刷新令牌、
 *       令牌验证/撤销、客户端注册、配置、数据类
 */
class SaOAuth2Test extends TestCase
{
    protected SaOAuth2Handle $handle;
    protected SaOAuth2Config $config;
    protected SaOAuth2Client $testClient;
    protected string $clientSecret;

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

        $this->handle = new SaOAuth2Handle($this->config);

        $this->clientSecret = getenv('TEST_OAUTH2_CLIENT_SECRET') ?: 'test-key-placeholder-32-bytes-lo';
        $this->testClient = new SaOAuth2Client([
            'clientId'     => 'test-client',
            'clientSecret' => $this->clientSecret,
            'clientName'   => 'Test Client',
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes'   => ['authorization_code', 'password', 'client_credentials'],
            'scopes'       => ['read', 'write'],
        ]);

        $this->handle->registerClient($this->testClient);
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    // ======== 客户端注册 ========

    public function testRegisterClient(): void
    {
        $client = $this->handle->getClient('test-client');
        $this->assertNotNull($client);
        $this->assertEquals('test-client', $client->getClientId());
        $this->assertEquals('Test Client', $client->getClientName());
    }

    public function testGetUnregisteredClient(): void
    {
        $this->assertNull($this->handle->getClient('unknown'));
    }

    // ======== 授权码模式 ========

    public function testGenerateAuthorizationCode(): void
    {
        $code = $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'read'
        );

        $this->assertNotEmpty($code->getCode());
        $this->assertEquals('test-client', $code->getClientId());
        $this->assertEquals(10001, $code->getLoginId());
        $this->assertEquals('https://example.com/callback', $code->getRedirectUri());
        $this->assertEquals('read', $code->getScope());
        $this->assertFalse($code->isUsed());
        $this->assertFalse($code->isExpired());
    }

    public function testGenerateAuthorizationCodeWithUnregisteredClient(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未注册的客户端');
        $this->handle->generateAuthorizationCode('unknown', 10001, 'https://example.com/callback');
    }

    public function testGenerateAuthorizationCodeWithInvalidRedirectUri(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未注册的回调地址');
        $this->handle->generateAuthorizationCode('test-client', 10001, 'https://evil.com/callback');
    }

    public function testExchangeTokenByCode(): void
    {
        $code = $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'read'
        );

        $accessToken = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );

        $this->assertNotEmpty($accessToken->getAccessToken());
        $this->assertEquals('Bearer', $accessToken->getTokenType());
        $this->assertEquals(7200, $accessToken->getExpiresIn());
        $this->assertEquals('read', $accessToken->getScope());
        $this->assertEquals(10001, $accessToken->getLoginId());
        $this->assertEquals('test-client', $accessToken->getClientId());
        $this->assertNotNull($accessToken->getRefreshToken());
    }

    public function testExchangeTokenByCodeWithInvalidCode(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('无效的授权码');
        $this->handle->exchangeTokenByCode('mock-invalid-code', 'test-client', $this->clientSecret);
    }

    public function testExchangeTokenByCodeWithWrongSecret(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('客户端密钥错误');
        $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', 'mock-wrong-secret');
    }

    public function testExchangeTokenByCodeWithWrongClientId(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('客户端 ID 不匹配');
        $this->handle->exchangeTokenByCode($code->getCode(), 'wrong-client', $this->clientSecret);
    }

    public function testExchangeTokenByCodeTwice(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');

        // 第一次成功
        $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret);

        // 第二次应失败（授权码已删除/已使用）
        $this->expectException(SaTokenException::class);
        $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret);
    }

    // ======== 刷新令牌 ========

    public function testRefreshToken(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret);

        $refreshToken = $accessToken->getRefreshToken();
        $this->assertNotNull($refreshToken);

        $newAccessToken = $this->handle->refreshToken($refreshToken, 'test-client', $this->clientSecret);
        $this->assertNotEmpty($newAccessToken->getAccessToken());
        $this->assertNotEquals($accessToken->getAccessToken(), $newAccessToken->getAccessToken());
    }

    public function testRefreshTokenWithInvalidToken(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('无效的刷新令牌');
        $this->handle->refreshToken('mock-invalid-refresh-token', 'test-client', $this->clientSecret);
    }

    public function testRefreshTokenWithWrongClientId(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret);

        // 注册另一个客户端
        $otherClient = new SaOAuth2Client([
            'clientId'     => 'other-client',
            'clientSecret' => 'mock-other-secret',
        ]);
        $this->handle->registerClient($otherClient);

        $refreshToken = $accessToken->getRefreshToken();
        $this->assertNotNull($refreshToken);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('客户端 ID 不匹配');
        $this->handle->refreshToken($refreshToken, 'other-client', 'mock-other-secret');
    }

    // ======== 密码模式 ========

    public function testTokenByPassword(): void
    {
        $this->handle->setUserCredentialsValidator(function (string $username, string $password): ?int {
            if ($username === 'mock-user' && $password === 'mock-password') {
                return 10001;
            }
            return null;
        });

        $accessToken = $this->handle->tokenByPassword('test-client', $this->clientSecret, 'mock-user', 'mock-password', 'read');
        $this->assertNotEmpty($accessToken->getAccessToken());
        $this->assertEquals(10001, $accessToken->getLoginId());
        $this->assertEquals('read', $accessToken->getScope());
    }

    public function testTokenByPasswordWithWrongCredentials(): void
    {
        $this->handle->setUserCredentialsValidator(function (string $username, string $password): ?int {
            return null;
        });

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('用户名或密码错误');
        $this->handle->tokenByPassword('test-client', $this->clientSecret, 'mock-user', 'mock-wrong-pass');
    }

    public function testTokenByPasswordUnsupportedGrantType(): void
    {
        $config = new SaOAuth2Config(['grantTypes' => ['authorization_code']]);
        $handle = new SaOAuth2Handle($config);
        $handle->registerClient($this->testClient);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('不支持密码模式');
        $handle->tokenByPassword('test-client', $this->clientSecret, 'mock-user', 'mock-password');
    }

    // ======== 客户端凭证模式 ========

    public function testTokenByClientCredentials(): void
    {
        $accessToken = $this->handle->tokenByClientCredentials('test-client', $this->clientSecret, 'read');
        $this->assertNotEmpty($accessToken->getAccessToken());
        $this->assertEquals('client:test-client', $accessToken->getLoginId());
        $this->assertEquals('read', $accessToken->getScope());
    }

    public function testTokenByClientCredentialsUnsupportedGrantType(): void
    {
        $config = new SaOAuth2Config(['grantTypes' => ['authorization_code']]);
        $handle = new SaOAuth2Handle($config);
        $handle->registerClient($this->testClient);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('不支持客户端凭证模式');
        $handle->tokenByClientCredentials('test-client', $this->clientSecret);
    }

    // ======== 验证/撤销访问令牌 ========

    public function testValidateAccessToken(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret);

        $validated = $this->handle->validateAccessToken($accessToken->getAccessToken());
        $this->assertNotNull($validated);
        $this->assertEquals(10001, $validated->getLoginId());
        $this->assertEquals('test-client', $validated->getClientId());
    }

    public function testValidateInvalidAccessToken(): void
    {
        $this->assertNull($this->handle->validateAccessToken('mock-invalid-token'));
    }

    public function testRevokeAccessToken(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret);

        $this->assertNotNull($this->handle->validateAccessToken($accessToken->getAccessToken()));

        $this->handle->revokeAccessToken($accessToken->getAccessToken());
        $this->assertNull($this->handle->validateAccessToken($accessToken->getAccessToken()));
    }

    // ======== SaOAuth2Manager 测试 ========

    public function testManagerWithArrayConfig(): void
    {
        $manager = new SaOAuth2Manager([
            'grantTypes'         => ['authorization_code'],
            'accessTokenTimeout' => 3600,
        ]);

        $this->assertEquals(3600, $manager->getConfig()->getAccessTokenTimeout());
        $this->assertNotNull($manager->getHandle());
    }

    public function testManagerWithConfigObject(): void
    {
        $config = new SaOAuth2Config(['accessTokenTimeout' => 1800]);
        $manager = new SaOAuth2Manager($config);
        $this->assertEquals(1800, $manager->getConfig()->getAccessTokenTimeout());
    }

    public function testManagerAuthorizationCodeFlow(): void
    {
        $manager = new SaOAuth2Manager($this->config);
        $manager->registerClient($this->testClient);

        $code = $manager->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $manager->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');

        $this->assertNotEmpty($accessToken->getAccessToken());
    }

    // ======== 数据类测试 ========

    public function testSaOAuth2AccessTokenDataClass(): void
    {
        $token = new SaOAuth2AccessToken([
            'accessToken'  => 'at-123',
            'expiresIn'    => 3600,
            'tokenType'    => 'Bearer',
            'refreshToken' => 'rt-456',
            'scope'        => 'read',
            'loginId'      => 10001,
            'clientId'     => 'client-1',
        ]);

        $this->assertEquals('at-123', $token->getAccessToken());
        $this->assertEquals(3600, $token->getExpiresIn());
        $this->assertEquals('Bearer', $token->getTokenType());
        $this->assertEquals('rt-456', $token->getRefreshToken());
        $this->assertEquals('read', $token->getScope());
        $this->assertEquals(10001, $token->getLoginId());
        $this->assertEquals('client-1', $token->getClientId());

        // toArray
        $arr = $token->toArray();
        $this->assertEquals('at-123', $arr['accessToken']);
        $this->assertEquals(10001, $arr['loginId']);

        // toResponseArray
        $responseArr = $token->toResponseArray();
        $this->assertEquals('at-123', $responseArr['access_token']);
        $this->assertEquals(3600, $responseArr['expires_in']);
        $this->assertEquals('Bearer', $responseArr['token_type']);
        $this->assertEquals('read', $responseArr['scope']);
        $this->assertEquals('rt-456', $responseArr['refresh_token']);
    }

    public function testSaOAuth2AccessTokenToResponseArrayWithoutRefreshToken(): void
    {
        $token = new SaOAuth2AccessToken(['accessToken' => 'at-123']);
        $responseArr = $token->toResponseArray();
        $this->assertArrayNotHasKey('refresh_token', $responseArr);
    }

    public function testSaOAuth2AuthorizationCodeDataClass(): void
    {
        $code = new SaOAuth2AuthorizationCode([
            'code'        => 'abc123',
            'clientId'    => 'client-1',
            'loginId'     => 10001,
            'redirectUri' => 'https://example.com/callback',
            'scope'       => 'read',
            'expiresIn'   => 60,
        ]);

        $this->assertEquals('abc123', $code->getCode());
        $this->assertEquals('client-1', $code->getClientId());
        $this->assertEquals(10001, $code->getLoginId());
        $this->assertEquals('https://example.com/callback', $code->getRedirectUri());
        $this->assertEquals('read', $code->getScope());
        $this->assertFalse($code->isUsed());
        $this->assertFalse($code->isExpired());

        // markUsed
        $code->markUsed();
        $this->assertTrue($code->isUsed());

        // toArray
        $arr = $code->toArray();
        $this->assertEquals('abc123', $arr['code']);
    }

    public function testSaOAuth2RefreshTokenDataClass(): void
    {
        $rt = new SaOAuth2RefreshToken([
            'refreshToken' => 'rt-abc',
            'accessToken'  => 'at-123',
            'clientId'     => 'client-1',
            'loginId'      => 10001,
            'scope'        => 'read',
            'expiresIn'    => 86400,
        ]);

        $this->assertEquals('rt-abc', $rt->getRefreshToken());
        $this->assertEquals('at-123', $rt->getAccessToken());
        $this->assertEquals('client-1', $rt->getClientId());
        $this->assertEquals(10001, $rt->getLoginId());

        $arr = $rt->toArray();
        $this->assertEquals('rt-abc', $arr['refreshToken']);
        $this->assertEquals('at-123', $arr['accessToken']);
    }

    public function testSaOAuth2ClientDataClass(): void
    {
        $client = new SaOAuth2Client([
            'clientId'     => 'c-1',
            'clientSecret' => 's-1',
            'clientName'   => 'My App',
            'redirectUris' => ['https://a.com', 'https://b.com'],
            'grantTypes'   => ['authorization_code', 'password'],
            'scopes'       => ['read', 'write'],
        ]);

        $this->assertEquals('c-1', $client->getClientId());
        $this->assertEquals('s-1', $client->getClientSecret());
        $this->assertEquals('My App', $client->getClientName());
        $this->assertCount(2, $client->getRedirectUris());
        $this->assertCount(2, $client->getGrantTypes());
        $this->assertCount(2, $client->getScopes());
    }

    // ======== SaOAuth2Config 测试 ========

    public function testSaOAuth2ConfigDefaults(): void
    {
        $config = new SaOAuth2Config();
        $this->assertEquals(['authorization_code'], $config->getGrantTypes());
        $this->assertEquals(60, $config->getCodeTimeout());
        $this->assertEquals(7200, $config->getAccessTokenTimeout());
        $this->assertEquals(-1, $config->getRefreshTokenTimeout());
        $this->assertFalse($config->isNewRefreshToken());
    }

    public function testSaOAuth2ConfigFromArray(): void
    {
        $config = new SaOAuth2Config([
            'grantTypes'          => ['password'],
            'codeTimeout'         => 120,
            'accessTokenTimeout'  => 3600,
            'refreshTokenTimeout' => 86400,
            'isNewRefreshToken'   => true,
        ]);

        $this->assertEquals(['password'], $config->getGrantTypes());
        $this->assertEquals(120, $config->getCodeTimeout());
        $this->assertEquals(3600, $config->getAccessTokenTimeout());
        $this->assertEquals(86400, $config->getRefreshTokenTimeout());
        $this->assertTrue($config->isNewRefreshToken());
    }
}
