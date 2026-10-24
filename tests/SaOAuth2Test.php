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
use SaToken\OAuth2\Strategy\ImplicitStrategy;
use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

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
            'grantTypes'   => ['authorization_code', 'password', 'client_credentials', 'refresh_token'],
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

    public function testMissingClientIpDoesNotCreateSharedLockoutBucket(): void
    {
        SaTokenContext::setRequest(null);
        $this->config->setClientSecretMaxFailures(1);

        try {
            $this->handle->tokenByClientCredentials('test-client', 'wrong-secret', 'read');
            $this->fail('错误客户端密钥应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertSame('客户端密钥错误', $e->getMessage());
        }

        $token = $this->handle->tokenByClientCredentials('test-client', $this->clientSecret, 'read');
        $this->assertNotEmpty($token->getAccessToken());
    }

    public function testClientSecretRotationIsObservedByOtherHandleInstances(): void
    {
        $otherHandle = new SaOAuth2Handle($this->config);
        $this->assertNotNull($otherHandle->getClient('test-client'));

        $rotatedClient = new SaOAuth2Client(array_merge($this->testClient->toArray(), [
            'clientSecret' => 'rotated-client-secret-32-bytes-long',
        ]));
        $this->handle->registerClient($rotatedClient);

        $this->expectException(SaTokenException::class);
        $otherHandle->tokenByClientCredentials('test-client', $this->clientSecret);
    }

    public function testAccessTokenIssuanceRequiresRegisteredClientAndValidLoginId(): void
    {
        try {
            $this->handle->generateAccessToken('unknown-client', 10001);
            $this->fail('不能为未注册客户端签发令牌');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('未注册的客户端', $e->getMessage());
        }

        foreach ([null, '', false, true, [], new \stdClass()] as $loginId) {
            try {
                $this->handle->generateAccessToken('test-client', $loginId);
                $this->fail('无效 loginId 不得获得 OAuth 令牌');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('loginId', $e->getMessage());
            }
        }
    }

    public function testImplicitStrategyHonorsGlobalGrantTypeAllowList(): void
    {
        $client = new SaOAuth2Client([
            'clientId' => 'implicit-default-client',
            'clientSecret' => 'client-secret',
            'redirectUris' => ['https://example.com/callback'],
        ]);
        $this->handle->registerClient($client);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未被授权使用此授权模式');
        (new ImplicitStrategy($this->handle))->authorize(
            'implicit-default-client',
            10001,
            '',
            'https://example.com/callback'
        );
    }

    public function testPublicClientCannotInheritImplicitGrantFromGlobalAllowList(): void
    {
        $config = new SaOAuth2Config(['grantTypes' => ['authorization_code', 'implicit']]);
        $handle = new SaOAuth2Handle($config);
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'public-implicit-client',
            'clientSecret' => '',
            'redirectUris' => ['https://example.com/callback'],
            // Empty means global grant allowlist for confidential clients.
            'grantTypes'   => [],
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('公开客户端只允许使用授权码模式');
        (new ImplicitStrategy($handle))->authorize(
            'public-implicit-client',
            10001,
            '',
            'https://example.com/callback'
        );
    }

    public function testImplicitStrategyRequiresRegisteredRedirectUri(): void
    {
        $config = new SaOAuth2Config(['grantTypes' => ['authorization_code', 'implicit']]);
        $handle = new SaOAuth2Handle($config);
        $handle->registerClient(new SaOAuth2Client([
            'clientId' => 'implicit-client',
            'clientSecret' => 'client-secret',
            'redirectUris' => ['https://example.com/callback'],
        ]));
        $strategy = new ImplicitStrategy($handle);

        try {
            $strategy->authorize('implicit-client', 10001);
            $this->fail('隐式授权必须提供 redirect_uri');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('必须提供', $e->getMessage());
        }

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未注册的回调地址');
        $strategy->authorize('implicit-client', 10001, '', 'https://attacker.example/callback');
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

    public function testAuthorizationCodeIssuanceHonorsClientGrantAllowList(): void
    {
        $this->handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'password-only-client',
            'clientSecret' => 'password-only-secret',
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes'   => ['password'],
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未被授权使用此授权模式');
        $this->handle->generateAuthorizationCode(
            'password-only-client',
            10001,
            'https://example.com/callback'
        );
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

    public function testRedirectUriRejectsUserInfoAndFragments(): void
    {
        foreach ([
            'https://user@example.com/callback',
            'https://example.com/callback#access_token',
            'https://example.com/callback#',
        ] as $redirectUri) {
            try {
                $this->handle->generateAuthorizationCode('test-client', 10001, $redirectUri);
                $this->fail('回调地址中的 userinfo/fragment 必须拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('不能包含用户信息或片段', $e->getMessage());
            }
        }
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
        $this->handle->exchangeTokenByCode('mock-invalid-code', 'test-client', $this->clientSecret, 'https://example.com/callback');

        // 不携带 redirect_uri 的换token请求必须被直接拒绝（RFC 6749 §4.1.3）
        try {
            $this->handle->exchangeTokenByCode('mock-invalid-code', 'test-client', $this->clientSecret);
            $this->fail('缺少 redirect_uri 的换token请求应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('redirect_uri', $e->getMessage());
        }
    }

    public function testExchangeTokenByCodeWithWrongSecret(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('客户端密钥错误');
        $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', 'mock-wrong-secret', 'https://example.com/callback');
    }

    public function testWrongClientSecretFromOneIpDoesNotLockOutOtherClientRequests(): void
    {
        $this->config->setClientSecretMaxFailures(2);
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.10'));

        for ($attempt = 0; $attempt < 2; $attempt++) {
            try {
                $this->handle->exchangeTokenByCode(
                    $code->getCode(),
                    'test-client',
                    'wrong-secret',
                    'https://example.com/callback'
                );
                $this->fail('错误客户端密钥必须被拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('客户端密钥错误', $e->getMessage());
            }
        }

        SaTokenContext::setRequest($this->requestFromIp('192.0.2.20'));
        $accessToken = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );

        $this->assertNotEmpty($accessToken->getAccessToken());
    }

    protected function requestFromIp(string $ip): object
    {
        return new class ($ip) {
            public function __construct(private string $ip)
            {
            }

            public function getClientIp(): string
            {
                return $this->ip;
            }
        };
    }

    public function testExchangeTokenByCodeWithWrongClientId(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');

        // 未注册客户端直接拒绝
        try {
            $this->handle->exchangeTokenByCode($code->getCode(), 'unknown-client', $this->clientSecret, 'https://example.com/callback');
            $this->fail('未注册客户端应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('未注册的客户端', $e->getMessage());
        }

        // 已注册但非授权码归属的客户端，必须拒绝
        $otherClient = new SaOAuth2Client([
            'clientId'     => 'other-client',
            'clientSecret' => 'mock-other-secret-long-enough',
            'grantTypes'   => ['authorization_code'],
            'redirectUris' => ['https://example.com/callback'],
        ]);
        $this->handle->registerClient($otherClient);

        try {
            $this->handle->exchangeTokenByCode($code->getCode(), 'other-client', 'mock-other-secret-long-enough', 'https://example.com/callback');
            $this->fail('授权码不得由其他客户端兑换');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('客户端 ID 不匹配', $e->getMessage());
        }

        $redeemed = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $this->assertNotEmpty($redeemed->getAccessToken(), '错误客户端的尝试不得烧毁合法授权码');
    }

    public function testExchangeTokenByCodeTwice(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');

        // 第一次成功
        $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');

        // 第二次应失败（授权码已删除/已使用）
        $this->expectException(SaTokenException::class);
        $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
    }

    // ======== 刷新令牌 ========

    public function testRefreshToken(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');

        $refreshToken = $accessToken->getRefreshToken();
        $this->assertNotNull($refreshToken);

        $newAccessToken = $this->handle->refreshToken($refreshToken, 'test-client', $this->clientSecret);
        $this->assertNotEmpty($newAccessToken->getAccessToken());
        $this->assertNotEquals($accessToken->getAccessToken(), $newAccessToken->getAccessToken());
    }

    public function testRefreshFamilyMetadataStaysBoundedAndOldReuseRevokesCurrentDescendants(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $originalRefreshToken = $accessToken->getRefreshToken();
        self::assertNotNull($originalRefreshToken);

        $getRefreshData = new \ReflectionMethod($this->handle, 'getRefreshTokenData');
        $originalData = $getRefreshData->invoke($this->handle, $originalRefreshToken);
        self::assertInstanceOf(SaOAuth2RefreshToken::class, $originalData);
        $familyMarkerKey = 'oauth2:family:' . hash('sha256', $originalData->getFamilyId());

        $refreshToken = $originalRefreshToken;
        for ($rotation = 0; $rotation < 5; $rotation++) {
            $accessToken = $this->handle->refreshToken($refreshToken, 'test-client', $this->clientSecret);
            $refreshToken = $accessToken->getRefreshToken();
            self::assertNotNull($refreshToken);

            $markerJson = SaToken::getDao()->get($familyMarkerKey);
            self::assertNotNull($markerJson);
            $marker = json_decode($markerJson, true);
            self::assertIsArray($marker);
            $familyTokens = $marker['tokens'] ?? [];
            $familyRefreshTokens = $marker['childRts'] ?? [];
            self::assertIsArray($familyTokens);
            self::assertIsArray($familyRefreshTokens);
            self::assertLessThanOrEqual(2, count($familyTokens));
            self::assertLessThanOrEqual(1, count($familyRefreshTokens));
        }

        try {
            $this->handle->refreshToken($originalRefreshToken, 'test-client', $this->clientSecret);
            $this->fail('旧 refresh token 重放必须撤销整个活跃家族');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('已被使用', $e->getMessage());
        }

        $this->assertNull($this->handle->validateAccessToken($accessToken->getAccessToken()));
        $this->assertNull($getRefreshData->invoke($this->handle, $refreshToken));
    }

    public function testRefreshTokenReplayRevokesTheWholeFamily(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $oldRefreshToken = $initial->getRefreshToken();
        $this->assertNotNull($oldRefreshToken);

        $rotated = $this->handle->refreshToken($oldRefreshToken, 'test-client', $this->clientSecret);
        $childRefreshToken = $rotated->getRefreshToken();
        $this->assertNotNull($childRefreshToken);
        $this->assertNotNull($this->handle->validateAccessToken($rotated->getAccessToken()));

        try {
            $this->handle->refreshToken($oldRefreshToken, 'test-client', $this->clientSecret);
            $this->fail('重放旧刷新令牌应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('已被使用', $e->getMessage());
        }

        $this->assertNull($this->handle->validateAccessToken($rotated->getAccessToken()));
        try {
            $this->handle->refreshToken($childRefreshToken, 'test-client', $this->clientSecret);
            $this->fail('家族撤销后，派生刷新令牌必须失效');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无效的刷新令牌', $e->getMessage());
        }
    }

    public function testLegacyRefreshTokenReplayRevokesMigratedFamilyDescendants(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $legacyRefreshToken = $initial->getRefreshToken();
        self::assertNotNull($legacyRefreshToken);

        // 模拟升级前写入的 refresh token：存储记录没有 familyId 字段。
        $legacyKey = 'oauth2:rt:' . $legacyRefreshToken;
        $legacyData = json_decode((string) SaToken::getDao()->get($legacyKey), true);
        self::assertIsArray($legacyData);
        unset($legacyData['familyId']);
        SaToken::getDao()->set($legacyKey, json_encode($legacyData, JSON_THROW_ON_ERROR), 86400);

        $rotated = $this->handle->refreshToken($legacyRefreshToken, 'test-client', $this->clientSecret);
        $childRefreshToken = $rotated->getRefreshToken();
        self::assertNotNull($childRefreshToken);
        self::assertNotNull($this->handle->validateAccessToken($rotated->getAccessToken()));

        try {
            $this->handle->refreshToken($legacyRefreshToken, 'test-client', $this->clientSecret);
            self::fail('重放旧格式 refresh token 应撤销迁移后的整个家族');
        } catch (SaTokenException $e) {
            self::assertStringContainsString('已被使用', $e->getMessage());
        }

        self::assertNull($this->handle->validateAccessToken($rotated->getAccessToken()));
        self::assertNull(SaToken::getDao()->get('oauth2:rt:' . $childRefreshToken));
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
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');

        // 注册另一个客户端
        $otherClient = new SaOAuth2Client([
            'clientId'     => 'other-client',
            'clientSecret' => 'mock-other-secret-long-enough',
            'grantTypes'   => ['refresh_token'],
        ]);
        $this->handle->registerClient($otherClient);

        $refreshToken = $accessToken->getRefreshToken();
        $this->assertNotNull($refreshToken);
        try {
            $this->handle->refreshToken($refreshToken, 'other-client', 'mock-other-secret-long-enough');
            $this->fail('刷新令牌不得由其他客户端使用');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('客户端 ID 不匹配', $e->getMessage());
        }

        $refreshed = $this->handle->refreshToken($refreshToken, 'test-client', $this->clientSecret);
        $this->assertNotEmpty($refreshed->getAccessToken(), '错误客户端的尝试不得烧毁合法刷新令牌');
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

    public function testPasswordGrantRejectsScopesOutsideClientAllowList(): void
    {
        $this->handle->registerClient(new SaOAuth2Client([
            'clientId' => 'restricted-password-client',
            'clientSecret' => 'restricted-password-secret',
            'grantTypes' => ['password'],
            'scopes' => ['read'],
        ]));
        $this->handle->setUserCredentialsValidator(static function (): int {
            throw new \RuntimeException('scope must be rejected before checking user credentials');
        });

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未授予的 scope');
        $this->handle->tokenByPassword(
            'restricted-password-client',
            'restricted-password-secret',
            'user',
            'password',
            'read admin'
        );
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

    public function testTokenByPasswordTreatsFalseValidatorResultAsFailure(): void
    {
        $this->handle->setUserCredentialsValidator(static fn (): bool => false);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('用户名或密码错误');
        $this->handle->tokenByPassword('test-client', $this->clientSecret, 'mock-user', 'wrong-password');
    }

    public function testTokenByPasswordDoesNotTreatTrueAsLoginId(): void
    {
        $this->handle->setUserCredentialsValidator(static fn (): bool => true);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('用户名或密码错误');
        $this->handle->tokenByPassword('test-client', $this->clientSecret, 'mock-user', 'password');
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

    public function testClientCredentialsGrantRejectsScopesOutsideClientAllowList(): void
    {
        $this->handle->registerClient(new SaOAuth2Client([
            'clientId' => 'restricted-service-client',
            'clientSecret' => 'restricted-service-secret',
            'grantTypes' => ['client_credentials'],
            'scopes' => ['read'],
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未授予的 scope');
        $this->handle->tokenByClientCredentials(
            'restricted-service-client',
            'restricted-service-secret',
            'read admin'
        );
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
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');

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
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');

        $this->assertNotNull($this->handle->validateAccessToken($accessToken->getAccessToken()));

        $this->handle->revokeAccessToken($accessToken->getAccessToken());
        $this->assertNull($this->handle->validateAccessToken($accessToken->getAccessToken()));
    }

    public function testRevokingRotatedAccessTokenAlsoRevokesReturnedRefreshToken(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $rotated = $this->handle->refreshToken((string) $initial->getRefreshToken(), 'test-client', $this->clientSecret);
        $rotatedRefreshToken = $rotated->getRefreshToken();
        $this->assertNotNull($rotatedRefreshToken);

        $this->handle->revokeAccessToken($rotated->getAccessToken());
        $this->assertNull($this->handle->validateAccessToken($rotated->getAccessToken()));

        try {
            $this->handle->refreshToken($rotatedRefreshToken, 'test-client', $this->clientSecret);
            $this->fail('撤销访问令牌后，其返回的刷新令牌也必须失效');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无效的刷新令牌', $e->getMessage());
        }
    }

    public function testRevokingAccessTokenRacingRefreshRevokesRotatedToken(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
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
        $this->handle->registerClient($this->testClient);

        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $oldAccessToken = $initial->getAccessToken();
        $rotated = null;
        $dao->triggerKey = 'oauth2:at:' . $oldAccessToken;
        $dao->afterRead = function () use ($initial, &$rotated): void {
            $rotated = $this->handle->refreshToken((string) $initial->getRefreshToken(), 'test-client', $this->clientSecret);
        };

        $this->handle->revokeAccessToken($oldAccessToken);

        self::assertNotNull($rotated);
        self::assertNull($this->handle->validateAccessToken($rotated->getAccessToken()));
        self::assertNull($dao->get('oauth2:rt:' . $rotated->getRefreshToken()));
    }

    public function testRevokingRotatedAwayAccessTokenRevokesItsCurrentFamilyDescendant(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $rotated = $this->handle->refreshToken((string) $initial->getRefreshToken(), 'test-client', $this->clientSecret);

        $this->handle->revokeAccessToken($initial->getAccessToken());

        self::assertNull($this->handle->validateAccessToken($rotated->getAccessToken()));
        self::assertNull(SaToken::getDao()->get('oauth2:rt:' . $rotated->getRefreshToken()));
    }

    public function testRefreshTokenRotationCanBeDisabled(): void
    {
        $this->config->setIsNewRefreshToken(false);
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $this->assertNotNull($initial->getRefreshToken());

        $rotated = $this->handle->refreshToken((string) $initial->getRefreshToken(), 'test-client', $this->clientSecret);
        $this->assertNull($rotated->getRefreshToken());
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

    public function testSaOAuth2ConfigRejectsInvalidTimeouts(): void
    {
        foreach ([0, -2, PHP_INT_MAX] as $timeout) {
            foreach (['codeTimeout', 'accessTokenTimeout', 'refreshTokenTimeout'] as $setter) {
                try {
                    (new SaOAuth2Config())->{'set' . ucfirst($setter)}($timeout);
                    $this->fail("{$setter} 不应接受无效有效期 {$timeout}");
                } catch (SaTokenException $e) {
                    $this->assertStringContainsString('有效期', $e->getMessage());
                }
            }
        }

        foreach (['codeTimeout', 'accessTokenTimeout'] as $setter) {
            try {
                (new SaOAuth2Config())->{'set' . ucfirst($setter)}(-1);
                $this->fail("{$setter} 不应接受永不过期哨兵");
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('有效期', $e->getMessage());
            }
        }

        $config = new SaOAuth2Config(['refreshTokenTimeout' => -1]);
        $this->assertSame(-1, $config->getRefreshTokenTimeout());
    }
}
