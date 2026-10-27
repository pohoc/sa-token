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
use SaToken\Security\SaAntiBruteUtil;
use SaToken\StpUtil;
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
            'grantTypes'          => ['authorization_code', 'password', 'client_credentials', 'refresh_token'],
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

    public function testRegisterClientRejectsShortConfidentialSecret(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('clientSecret 至少需要 32 字节');

        $this->handle->registerClient(new SaOAuth2Client([
            'clientId' => 'weak-secret-client',
            'clientSecret' => 'short-secret',
            'grantTypes' => ['client_credentials'],
        ]));
    }

    public function testOAuthRejectsOversizedCredentialsBeforeStorageLookup(): void
    {
        self::assertNull($this->handle->getClient(str_repeat('c', 1025)));
        self::assertNull($this->handle->validateAccessToken(str_repeat('t', 4097)));

        try {
            $this->handle->refreshToken(str_repeat('r', 4097), 'test-client', $this->clientSecret);
            self::fail('超长刷新令牌必须在 DAO 查询和锁处理前被拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('刷新令牌长度无效', $exception->getMessage());
        }

        try {
            $this->handle->exchangeTokenByCode(str_repeat('c', 4097), 'test-client', $this->clientSecret);
            self::fail('超长授权码必须被拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('授权码长度无效', $exception->getMessage());
        }
    }

    public function testOAuthRejectsOversizedClientSecretsBeforeComparison(): void
    {
        try {
            $this->handle->tokenByClientCredentials('test-client', str_repeat('s', 4097));
            self::fail('超长客户端密钥必须在比较前被拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('client_secret 长度不能超过', $exception->getMessage());
        }
    }

    public function testOAuthRejectsOversizedClientIdsBeforeStorageLookup(): void
    {
        try {
            $this->handle->tokenByClientCredentials(str_repeat('i', 1025), $this->clientSecret);
            self::fail('超长客户端 ID 必须在 DAO 查询前被拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('client_id 长度无效', $exception->getMessage());
        }
    }

    public function testPasswordGrantRejectsDisabledLoginId(): void
    {
        SaToken::getConfig()->setAntiBruteMaxFailures(0)->setAntiBruteIpMaxFailures(0);
        $loginId = 'disabled-oauth-user';
        StpUtil::disable($loginId, 'login', 1, 3600);
        $this->handle->setUserCredentialsValidator(static fn (): string => 'disabled-oauth-user');

        $this->expectException(\SaToken\Exception\DisableServiceException::class);
        $this->handle->tokenByPassword('test-client', $this->clientSecret, 'disabled-user', 'correct-password');
    }

    public function testAuthenticationRejectsLegacyShortSecret(): void
    {
        SaToken::getDao()->set('oauth2:client:legacy-weak-client', \SaToken\Util\SaFoxUtil::toJson([
            'clientId' => 'legacy-weak-client',
            'clientSecret' => 'short-secret',
            'grantTypes' => ['client_credentials'],
        ]), null);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('客户端密钥长度不足');
        $this->handle->tokenByClientCredentials('legacy-weak-client', 'short-secret');
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

    public function testPasswordValidatorExceptionCountsAsAuthenticationFailure(): void
    {
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.30'));
        $expected = new SaTokenException('credential backend rejected credentials');
        $this->handle->setUserCredentialsValidator(static function () use ($expected): never {
            throw $expected;
        });

        try {
            $this->handle->tokenByPassword('test-client', $this->clientSecret, 'throwing-user', 'bad-password');
            $this->fail('Validator exception should propagate');
        } catch (SaTokenException $exception) {
            $this->assertSame($expected->getMessage(), $exception->getMessage());
        }

        $this->assertSame(1, SaAntiBruteUtil::getFailCount('throwing-user'));
    }

    public function testPasswordGrantRejectsOversizedCredentialsBeforeValidator(): void
    {
        $validatorCalls = 0;
        $this->handle->setUserCredentialsValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return 'unexpected-user';
        });

        foreach ([
            [str_repeat('u', 1025), 'password', 'username 长度无效'],
            ['username', str_repeat('p', 4097), 'password 长度无效'],
        ] as [$username, $password, $message]) {
            try {
                $this->handle->tokenByPassword('test-client', $this->clientSecret, $username, $password);
                self::fail('超长密码授权凭据必须拒绝');
            } catch (SaTokenException $exception) {
                self::assertStringContainsString($message, $exception->getMessage());
            }
        }

        self::assertSame(0, $validatorCalls);
    }

    public function testPasswordGrantRechecksClientSecretAfterCredentialValidation(): void
    {
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.44'));
        $this->handle->setUserCredentialsValidator(function (): string {
            $rotatedClient = new SaOAuth2Client(array_merge($this->testClient->toArray(), [
                'clientSecret' => 'rotated-oauth-client-secret-32-bytes',
            ]));
            $this->handle->registerClient($rotatedClient);

            return 'password-rotation-user';
        });

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('客户端密钥错误');
        $this->handle->tokenByPassword('test-client', $this->clientSecret, 'user', 'password');
    }

    public function testPasswordGrantRecheckFailureReleasesSourceConcurrencyReservation(): void
    {
        SaToken::setConfig(SaToken::getConfig()
            ->setAntiBruteMaxFailures(0)
            ->setAntiBruteIpMaxFailures(1)
            ->setAntiBruteLockDuration(60));
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.44'));
        $this->handle->setUserCredentialsValidator(function (): string {
            $rotatedClient = new SaOAuth2Client(array_merge($this->testClient->toArray(), [
                'clientSecret' => 'rotated-oauth-client-secret-32-bytes',
            ]));
            $this->handle->registerClient($rotatedClient);

            return 'password-rotation-user';
        });

        try {
            $this->handle->tokenByPassword('test-client', $this->clientSecret, 'user', 'password');
            self::fail('客户端密钥轮换后不得签发令牌');
        } catch (SaTokenException $exception) {
            self::assertSame('客户端密钥错误', $exception->getMessage());
        }

        SaTokenContext::setRequest($this->requestFromIp('192.0.2.44'));
        SaAntiBruteUtil::checkAndThrow('another-user');
        SaAntiBruteUtil::clearCurrentSourceFailures('another-user');
    }

    public function testImplicitAuthorizationRejectsRedirectRevokedDuringScopeValidation(): void
    {
        $this->config->setGrantTypes(['authorization_code', 'implicit']);
        $client = new SaOAuth2Client([
            'clientId' => 'implicit-race-client',
            'clientSecret' => 'implicit-race-client-secret-32-bytes',
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes' => ['implicit'],
            'scopes' => ['read'],
        ]);
        $this->handle->registerClient($client);
        $dao = new class () extends SaTokenDaoMemory {
            public int $clientReadCount = 0;
            public ?\Closure $afterScopeRead = null;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($key === 'oauth2:client:implicit-race-client') {
                    $this->clientReadCount++;
                    if ($this->afterScopeRead !== null && $this->clientReadCount === 3) {
                        $callback = $this->afterScopeRead;
                        $this->afterScopeRead = null;
                        $callback();
                    }
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($client);
        $dao->clientReadCount = 0;
        $dao->afterScopeRead = function () use ($client): void {
            $revokedClient = new SaOAuth2Client(array_merge($client->toArray(), [
                'redirectUris' => ['https://other.example/callback'],
            ]));
            $this->handle->registerClient($revokedClient);
        };

        $strategy = new \SaToken\OAuth2\Strategy\ImplicitStrategy($this->handle);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未注册的回调地址');
        $strategy->authorize(
            'implicit-race-client',
            'implicit-race-user',
            'read',
            'https://example.com/callback'
        );
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

    public function testGenericAccessTokenSignerCannotBeCalledDirectly(): void
    {
        $this->handle->registerClient(new SaOAuth2Client([
            'clientId' => 'public-pkce-client',
            'clientSecret' => '',
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes' => ['authorization_code'],
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('通用访问令牌签发仅供内部授权流程使用');
        $this->handle->generateAccessToken('public-pkce-client', 'attacker-chosen-user', '', '', true, '', false, 'authorization_code');
    }

    public function testAccessTokenIssuanceEnforcesExplicitClientGrantType(): void
    {
        $client = new SaOAuth2Client([
            'clientId' => 'authorization-code-only-client',
            'clientSecret' => 'authorization-code-only-secret-32-bytes',
            'grantTypes' => ['authorization_code'],
            'scopes' => ['read'],
        ]);
        $this->handle->registerClient($client);

        try {
            $this->handle->generateImplicitAccessToken(
                'authorization-code-only-client',
                10001,
                'https://example.com/callback',
                'read',
                ''
            );
            self::fail('直接签发入口不得绕过客户端的授权类型白名单');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('未被授权', $exception->getMessage());
        }
    }

    public function testAccessTokenIssuanceRejectsMissingGrantType(): void
    {
        $client = new SaOAuth2Client([
            'clientId' => 'client-credentials-only',
            'clientSecret' => 'client-credentials-only-secret-32-bytes',
            'grantTypes' => ['client_credentials'],
        ]);
        $this->handle->registerClient($client);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('通用访问令牌签发仅供内部授权流程使用');
        $this->handle->generateAccessToken('client-credentials-only', 'arbitrary-user');
    }

    public function testOAuth2CredentialsExpireAtTheirExactExpirySecond(): void
    {
        $expiry = time();
        $code = new SaOAuth2AuthorizationCode([
            'createTime' => $expiry - 60,
            'expiresIn' => 60,
        ]);
        $accessToken = new SaOAuth2AccessToken([
            'createTime' => $expiry - 60,
            'expiresIn' => 60,
        ]);

        self::assertTrue($code->isExpired(), '授权码在 exp 边界必须失效');
        self::assertTrue($accessToken->isExpired(), 'Access Token 在 exp 边界必须失效');
    }

    public function testAuthorizationCodeWithInvalidLifetimeMetadataFailsClosedWithoutDaoTtl(): void
    {
        foreach ([0, -1, time() + 60, PHP_INT_MAX] as $createTime) {
            $code = new SaOAuth2AuthorizationCode([
                'createTime' => $createTime,
                'expiresIn' => 60,
            ]);
            self::assertTrue($code->isExpired(), '无效的授权码创建时间必须视为过期');
        }

        $overflowingCode = new SaOAuth2AuthorizationCode([
            'createTime' => time(),
            'expiresIn' => PHP_INT_MAX,
        ]);
        self::assertTrue($overflowingCode->isExpired(), '超出可表示范围的授权码有效期必须拒绝');

        $dao = new class () extends SaTokenDaoMemory {
            public function set(string $key, string $value, ?int $timeout = null): void
            {
                parent::set($key, $value, null);
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);

        $codeValue = 'oauth2-authorization-code-future-created-at';
        $codeKey = 'oauth2:code:' . $codeValue;
        $dao->set($codeKey, \SaToken\Util\SaFoxUtil::toJson([
            'code' => $codeValue,
            'clientId' => 'test-client',
            'loginId' => 10001,
            'redirectUri' => 'https://example.com/callback',
            'scope' => '',
            'expiresIn' => 60,
            'createTime' => time() + 60,
        ]));

        try {
            $this->handle->exchangeTokenByCode($codeValue, 'test-client', $this->clientSecret, 'https://example.com/callback');
            self::fail('无效时间元数据的授权码不得签发访问令牌');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('已过期', $exception->getMessage());
        }
        self::assertNotNull($dao->get($codeKey), '无效元数据预检失败时授权码不应被消费');
    }

    public function testAccessTokenWithInvalidLifetimeMetadataFailsClosed(): void
    {
        foreach ([0, -1, time() + 60, PHP_INT_MAX] as $createTime) {
            $token = new SaOAuth2AccessToken([
                'createTime' => $createTime,
                'expiresIn' => 3600,
            ]);
            self::assertTrue($token->isExpired(), '无效的访问令牌创建时间必须视为过期');
        }

        $invalidLifetimeToken = new SaOAuth2AccessToken([
            'createTime' => time(),
            'expiresIn' => PHP_INT_MAX,
        ]);
        self::assertTrue($invalidLifetimeToken->isExpired(), '超出可表示范围的访问令牌有效期必须拒绝');

        $tokenValue = 'oauth2-access-token-invalid-created-at';
        SaToken::getDao()->set('oauth2:at:' . $tokenValue, \SaToken\Util\SaFoxUtil::toJson([
            'accessToken' => $tokenValue,
            'expiresIn' => 3600,
            'tokenType' => 'Bearer',
            'refreshToken' => null,
            'scope' => 'read',
            'loginId' => 10001,
            'clientId' => 'test-client',
            'createTime' => 0,
            'idToken' => '',
        ]));
        self::assertNull($this->handle->validateAccessToken($tokenValue));
    }

    public function testClientWithoutScopeAllowlistCannotSelfAssignScopes(): void
    {
        $client = new SaOAuth2Client([
            'clientId' => 'scope-less-client',
            'clientSecret' => 'scope-less-client-secret-at-least-32-bytes',
            'grantTypes' => ['client_credentials'],
        ]);
        $this->handle->registerClient($client);

        try {
            $this->handle->tokenByClientCredentials('scope-less-client', 'scope-less-client-secret-at-least-32-bytes', 'admin');
            self::fail('未配置 scope 白名单的客户端不能自行声明权限');
        } catch (SaTokenException $e) {
            self::assertStringContainsString('scope 白名单', $e->getMessage());
        }

        self::assertNotEmpty($this->handle->tokenByClientCredentials('scope-less-client', 'scope-less-client-secret-at-least-32-bytes')->getAccessToken());
    }

    public function testImplicitStrategyHonorsGlobalGrantTypeAllowList(): void
    {
        $client = new SaOAuth2Client([
            'clientId' => 'implicit-default-client',
            'clientSecret' => 'oauth-test-client-secret-at-least-32-bytes',
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
            'clientSecret' => 'oauth-test-client-secret-at-least-32-bytes',
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

    public function testImplicitStrategyNeverIssuesRefreshToken(): void
    {
        $config = new SaOAuth2Config([
            'grantTypes'          => ['authorization_code', 'implicit'],
            'refreshTokenTimeout' => 86400,
            'isNewRefreshToken'   => true,
        ]);
        $handle = new SaOAuth2Handle($config);
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'implicit-no-refresh-client',
            'clientSecret' => 'oauth-implicit-test-secret-at-least-32-bytes',
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes'   => ['implicit'],
        ]));

        $token = (new ImplicitStrategy($handle))->authorize(
            'implicit-no-refresh-client',
            10001,
            '',
            'https://example.com/callback'
        );

        self::assertNull($token->getRefreshToken());
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

    public function testScopeIsDeduplicatedBeforePersistenceAndTokenIssuance(): void
    {
        $code = $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'write read read write'
        );
        self::assertSame('write read', $code->getScope());

        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback', 'write read read');
        $token = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        self::assertSame('write read', $token->getScope());
    }

    public function testOversizedScopeIsRejectedBeforeTokenIssuance(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('scope 长度不能超过');

        $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback', str_repeat('read ', 820));
    }

    public function testOversizedOidcNonceIsRejectedBeforeAuthorizationCodePersistence(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('OIDC nonce 长度不能超过');

        $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'read',
            '',
            '',
            str_repeat('n', 1025)
        );
    }

    public function testAuthorizationCodeIssuanceHonorsClientGrantAllowList(): void
    {
        $this->handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'password-only-client',
            'clientSecret' => 'oauth-password-only-secret-with-32-bytes',
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

    public function testRedirectUriRejectsOversizedValuesBeforeAuthorizationCodeStorage(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('回调地址长度不能超过');
        $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/' . str_repeat('a', 4096)
        );
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

    public function testRedirectUriRejectsBackslashesAndControlCharactersEvenWhenRegistered(): void
    {
        foreach ([
            'https://example.com/callback\\@evil.example/',
            "https://example.com/callback\t",
            "https://example.com/callback\n",
            "https://example.com/callback\x7f",
        ] as $redirectUri) {
            $this->testClient->setRedirectUris([$redirectUri]);
            $this->handle->registerClient($this->testClient);

            try {
                $this->handle->generateAuthorizationCode('test-client', 10001, $redirectUri);
                $this->fail('歧义回调地址必须拒绝，即使已配置在客户端 allowlist 中');
            } catch (SaTokenException $e) {
                $this->assertSame('回调地址包含歧义字符', $e->getMessage());
            }
        }
    }

    public function testRedirectUriRejectsNonHttpSchemesOnLocalhost(): void
    {
        $redirectUri = 'javascript://localhost/callback';
        $this->testClient->setRedirectUris([$redirectUri]);
        $this->handle->registerClient($this->testClient);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('回调地址必须使用 HTTPS 协议');
        $this->handle->generateAuthorizationCode('test-client', 10001, $redirectUri);
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

    public function testRemovingRedirectUriRevokesPendingAuthorizationCodesWithoutConsumingThem(): void
    {
        $oldRedirectUri = 'https://example.com/callback';
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, $oldRedirectUri);
        $this->testClient->setRedirectUris(['https://new.example.com/callback']);
        $this->handle->registerClient($this->testClient);

        try {
            $this->handle->exchangeTokenByCode(
                $code->getCode(),
                'test-client',
                $this->clientSecret,
                $oldRedirectUri
            );
            self::fail('客户端移除的 redirect_uri 不得继续兑换待处理授权码');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('未注册的回调地址', $exception->getMessage());
        }

        $codeKey = 'oauth2:code:' . $code->getCode();
        self::assertNotNull(SaToken::getDao()->get($codeKey), '被拒绝的回调地址不得消费授权码');

        // Restoring the allowlist demonstrates that rejection above did not
        // burn the code; the current policy remains authoritative at exchange.
        $this->testClient->setRedirectUris([$oldRedirectUri]);
        $this->handle->registerClient($this->testClient);
        $token = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            $oldRedirectUri
        );
        self::assertNotEmpty($token->getAccessToken());
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
            'clientSecret' => 'oauth-other-client-secret-with-at-least-32-bytes',
            'grantTypes'   => ['authorization_code'],
            'redirectUris' => ['https://example.com/callback'],
        ]);
        $this->handle->registerClient($otherClient);

        try {
            $this->handle->exchangeTokenByCode($code->getCode(), 'other-client', 'oauth-other-client-secret-with-at-least-32-bytes', 'https://example.com/callback');
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

    public function testAuthorizationCodeExchangeRejectsRedirectRevokedDuringValidation(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public int $clientReadCount = 0;
            public ?\Closure $afterValidatedClientRead = null;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($key === 'oauth2:client:test-client') {
                    $this->clientReadCount++;
                    if ($this->afterValidatedClientRead !== null && $this->clientReadCount === 3) {
                        $callback = $this->afterValidatedClientRead;
                        $this->afterValidatedClientRead = null;
                        $callback();
                    }
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);
        $code = $this->handle->generateAuthorizationCode('test-client', 'redirect-revocation-race', 'https://example.com/callback');
        $dao->clientReadCount = 0;
        $dao->afterValidatedClientRead = function (): void {
            $revokedClient = new SaOAuth2Client(array_merge($this->testClient->toArray(), [
                'redirectUris' => ['https://other.example/callback'],
            ]));
            $this->handle->registerClient($revokedClient);
        };

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未注册的回调地址');
        $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );
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

    public function testRefreshRejectsClientSecretRotationBeforeRefreshTokenConsumption(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public int $clientReadCount = 0;

            public ?\Closure $afterValidatedClientRead = null;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($key === 'oauth2:client:test-client') {
                    $this->clientReadCount++;
                    if ($this->afterValidatedClientRead !== null && $this->clientReadCount === 2) {
                        $callback = $this->afterValidatedClientRead;
                        $this->afterValidatedClientRead = null;
                        $callback();
                    }
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);
        $code = $this->handle->generateAuthorizationCode('test-client', 'secret-rotation-refresh', 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );
        $refreshToken = $accessToken->getRefreshToken();
        self::assertNotNull($refreshToken);

        $dao->clientReadCount = 0;
        $dao->afterValidatedClientRead = function (): void {
            $rotatedClient = new SaOAuth2Client(array_merge($this->testClient->toArray(), [
                'clientSecret' => 'rotated-refresh-secret-with-at-least-32-bytes',
            ]));
            $this->handle->registerClient($rotatedClient);
        };

        try {
            $this->handle->refreshToken($refreshToken, 'test-client', $this->clientSecret);
            self::fail('客户端密钥轮换后，旧密钥不得消费刷新令牌');
        } catch (SaTokenException $exception) {
            self::assertSame('客户端密钥错误', $exception->getMessage());
        }

        $rotatedSecret = 'rotated-refresh-secret-with-at-least-32-bytes';
        self::assertNotEmpty($this->handle->refreshToken($refreshToken, 'test-client', $rotatedSecret)->getAccessToken());
    }

    public function testGloballyDisabledGrantCannotBeUsedByPreviouslyRegisteredClient(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );
        $refreshToken = $accessToken->getRefreshToken();
        self::assertNotNull($refreshToken);

        // Runtime global policy must still be able to disable a grant even if
        // a client's persisted allowlist has not yet been updated.
        $this->config->setGrantTypes(['authorization_code']);

        try {
            $this->handle->refreshToken($refreshToken, 'test-client', $this->clientSecret);
            self::fail('全局关闭 refresh_token 后不得继续使用已有客户端凭据');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('全局配置未启用', $exception->getMessage());
        }
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

    public function testRefreshReplayMarkersOutliveLongerAccessTokens(): void
    {
        $this->config->setAccessTokenTimeout(7200);
        $this->config->setRefreshTokenTimeout(60);
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $oldRefreshToken = (string) $initial->getRefreshToken();
        $getRefreshData = new \ReflectionMethod($this->handle, 'getRefreshTokenData');
        $initialData = $getRefreshData->invoke($this->handle, $oldRefreshToken);
        self::assertInstanceOf(SaOAuth2RefreshToken::class, $initialData);
        $rotated = $this->handle->refreshToken($oldRefreshToken, 'test-client', $this->clientSecret);

        $markerKey = 'oauth2:family:' . hash('sha256', $initialData->getFamilyId());
        $consumedKey = 'oauth2:rt:consumed:' . hash('sha256', $oldRefreshToken);

        self::assertGreaterThanOrEqual(7200, SaToken::getDao()->getTimeout($markerKey));
        self::assertGreaterThanOrEqual(7200, SaToken::getDao()->getTimeout($consumedKey));
        self::assertNotSame('', $rotated->getAccessToken());
    }

    public function testConsumedRefreshMarkerRetainsOriginalLifetimeAfterPolicyShrink(): void
    {
        $originalTimeout = 30 * 86400;
        $this->config->setRefreshTokenTimeout($originalTimeout);
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $oldRefreshToken = (string) $initial->getRefreshToken();
        $getRefreshData = new \ReflectionMethod($this->handle, 'getRefreshTokenData');
        $initialData = $getRefreshData->invoke($this->handle, $oldRefreshToken);
        self::assertInstanceOf(SaOAuth2RefreshToken::class, $initialData);

        // Existing tokens keep the expiry embedded at issuance when operators
        // shorten the policy for newly issued refresh tokens.
        $this->config->setRefreshTokenTimeout(86400);
        $firstRotated = $this->handle->refreshToken($oldRefreshToken, 'test-client', $this->clientSecret);
        $this->handle->refreshToken((string) $firstRotated->getRefreshToken(), 'test-client', $this->clientSecret);

        $consumedKey = 'oauth2:rt:consumed:' . hash('sha256', $oldRefreshToken);
        $familyMarkerKey = 'oauth2:family:' . hash('sha256', $initialData->getFamilyId());
        $expectedRemaining = $initialData->getCreateTime() + $initialData->getExpiresIn() - time();
        self::assertGreaterThanOrEqual($expectedRemaining, SaToken::getDao()->getTimeout($consumedKey));
        self::assertGreaterThanOrEqual($expectedRemaining, SaToken::getDao()->getTimeout($familyMarkerKey));
    }

    public function testRefreshTokenLeaseExpiryCannotResurrectARevokedFamily(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public bool $trackRefreshWrites = false;
            public bool $refreshWritten = false;
            public ?\Closure $onFamilyReadAfterRefreshWrite = null;
            public ?string $newAccessTokenKey = null;
            public ?string $newRefreshTokenKey = null;

            public function set(string $key, string $value, ?int $timeout = null): void
            {
                parent::set($key, $value, $timeout);
                if ($this->trackRefreshWrites && str_starts_with($key, 'oauth2:at:')) {
                    $this->newAccessTokenKey = $key;
                }
                if ($this->trackRefreshWrites && str_starts_with($key, 'oauth2:rt:')) {
                    if (!str_starts_with($key, 'oauth2:rt:consumed:') && !str_starts_with($key, 'oauth2:rt:used:')) {
                        $this->refreshWritten = true;
                        $this->newRefreshTokenKey = $key;
                    }
                }
            }

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($this->refreshWritten && str_starts_with($key, 'oauth2:family:')
                    && $this->onFamilyReadAfterRefreshWrite !== null) {
                    $callback = $this->onFamilyReadAfterRefreshWrite;
                    $this->onFamilyReadAfterRefreshWrite = null;
                    $callback();
                }
                return $value;
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);

        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $oldRefreshToken = (string) $initial->getRefreshToken();
        $dao->trackRefreshWrites = true;
        $dao->onFamilyReadAfterRefreshWrite = function () use ($dao, $oldRefreshToken): void {
            // Model the 120-second distributed lock lease expiring while its
            // original owner is paused after persisting the rotated credentials.
            $dao->delete('oauth2:refresh:token:' . hash('sha256', $oldRefreshToken));
            $consumedFamily = $dao->get('oauth2:rt:consumed:' . hash('sha256', $oldRefreshToken));
            self::assertIsString($consumedFamily);
            $dao->delete('oauth2:refresh:family:' . hash('sha256', $consumedFamily));
            try {
                $this->handle->refreshToken($oldRefreshToken, 'test-client', $this->clientSecret);
                self::fail('重放旧刷新令牌必须撤销家族');
            } catch (SaTokenException $exception) {
                self::assertStringContainsString('已被使用', $exception->getMessage());
            }
        };

        try {
            $this->handle->refreshToken($oldRefreshToken, 'test-client', $this->clientSecret);
            self::fail('租约过期后发现家族撤销，刷新必须失败关闭');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('家族状态已变更', $exception->getMessage());
        }

        self::assertNotNull($dao->newAccessTokenKey);
        self::assertNotNull($dao->newRefreshTokenKey);
        self::assertNull($dao->get($dao->newAccessTokenKey));
        self::assertNull($dao->get($dao->newRefreshTokenKey));
    }

    public function testRefreshTokenReplayAfterConsumeBeforeMarkerRevokesFamily(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public bool $pauseAfterRefreshConsume = false;
            public ?\Closure $onRefreshConsumed = null;
            public ?string $refreshTokenKey = null;
            public ?string $newAccessTokenKey = null;
            public ?string $newRefreshTokenKey = null;

            public function compareAndUpdate(string $key, string $expectedValue, string $newValue): bool
            {
                $updated = parent::compareAndUpdate($key, $expectedValue, $newValue);
                if ($updated && $this->pauseAfterRefreshConsume && $key === $this->refreshTokenKey) {
                    $this->pauseAfterRefreshConsume = false;
                    $this->onRefreshConsumed?->__invoke();
                }
                return $updated;
            }

            public function set(string $key, string $value, ?int $timeout = null): void
            {
                parent::set($key, $value, $timeout);
                if (str_starts_with($key, 'oauth2:at:') && !str_starts_with($key, 'oauth2:at:family:')) {
                    $this->newAccessTokenKey = $key;
                }
                if (str_starts_with($key, 'oauth2:rt:')
                    && !str_starts_with($key, 'oauth2:rt:consumed:')
                    && !str_starts_with($key, 'oauth2:rt:used:')) {
                    $this->newRefreshTokenKey = $key;
                }
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);

        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $initial = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $oldRefreshToken = (string) $initial->getRefreshToken();
        $initialData = (new \ReflectionMethod($this->handle, 'getRefreshTokenData'))->invoke($this->handle, $oldRefreshToken);
        self::assertInstanceOf(SaOAuth2RefreshToken::class, $initialData);
        $dao->refreshTokenKey = 'oauth2:rt:' . $oldRefreshToken;
        $dao->newAccessTokenKey = null;
        $dao->newRefreshTokenKey = null;
        $dao->pauseAfterRefreshConsume = true;
        $dao->onRefreshConsumed = function () use ($dao, $oldRefreshToken, $initialData): void {
            // Simulate a process pause after atomic consumption long enough for
            // its refresh-lock lease to expire, then replay the same token.
            $dao->delete('oauth2:refresh:token:' . hash('sha256', $oldRefreshToken));
            $dao->delete('oauth2:refresh:family:' . hash('sha256', $initialData->getFamilyId()));
            try {
                $this->handle->refreshToken($oldRefreshToken, 'test-client', $this->clientSecret);
            } catch (SaTokenException) {
                // The replay is expected to fail; the original owner must also
                // observe the replay tombstone before it can issue descendants.
            }
        };

        try {
            $this->handle->refreshToken($oldRefreshToken, 'test-client', $this->clientSecret);
            self::fail('在重放标记建立前发生的刷新令牌重放必须撤销家族并阻止原请求签发');
        } catch (SaTokenException $exception) {
            self::assertTrue(
                str_contains($exception->getMessage(), '家族已撤销')
                || str_contains($exception->getMessage(), '家族状态已变更')
                || str_contains($exception->getMessage(), '已被使用'),
                $exception->getMessage()
            );
        }

        self::assertNull($dao->newAccessTokenKey);
        self::assertNull($dao->newRefreshTokenKey);
        self::assertNull($this->handle->validateAccessToken($initial->getAccessToken()));
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

    public function testExpiredRefreshTokenIsRejectedEvenWhenDaoIgnoresTtl(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public function set(string $key, string $value, ?int $timeout = null): void
            {
                parent::set($key, $value, null);
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);

        $refreshToken = 'expired-refresh-token';
        $key = 'oauth2:rt:' . $refreshToken;
        $dao->set($key, json_encode([
            'refreshToken' => $refreshToken,
            'accessToken' => 'expired-access-token',
            'clientId' => 'test-client',
            'loginId' => 10001,
            'scope' => 'read',
            'expiresIn' => 60,
            'createTime' => time() - 120,
            'familyId' => 'expired-family',
        ], JSON_THROW_ON_ERROR));

        try {
            $this->handle->refreshToken($refreshToken, 'test-client', $this->clientSecret);
            self::fail('DAO 未执行 TTL 时，过期刷新令牌也必须被拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('已过期', $exception->getMessage());
        }

        self::assertNotNull($dao->get($key), '预检发现过期时不应消费刷新令牌');

        $malformedRefreshToken = 'refresh-token-without-expiry-metadata';
        $malformedKey = 'oauth2:rt:' . $malformedRefreshToken;
        $dao->set($malformedKey, json_encode([
            'refreshToken' => $malformedRefreshToken,
            'accessToken' => 'legacy-access-token',
            'clientId' => 'test-client',
            'loginId' => 10001,
            'scope' => 'read',
            'expiresIn' => 60,
            'familyId' => 'malformed-family',
        ], JSON_THROW_ON_ERROR));

        try {
            $this->handle->refreshToken($malformedRefreshToken, 'test-client', $this->clientSecret);
            self::fail('缺少过期元数据的刷新令牌必须 fail closed');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('数据无效', $exception->getMessage());
        }
        self::assertNotNull($dao->get($malformedKey));
    }

    public function testRefreshTokenWithInvalidLifetimeMetadataFailsClosedWithoutDaoTtl(): void
    {
        foreach ([0, -1, time() + 60, PHP_INT_MAX] as $createTime) {
            $token = new SaOAuth2RefreshToken([
                'createTime' => $createTime,
                'expiresIn' => 3600,
            ]);
            self::assertTrue($token->isExpired(), '无效的刷新令牌创建时间必须视为过期');
        }

        $overflowingToken = new SaOAuth2RefreshToken([
            'createTime' => time(),
            'expiresIn' => PHP_INT_MAX,
        ]);
        self::assertTrue($overflowingToken->isExpired(), '超出可表示范围的刷新令牌有效期必须拒绝');

        $dao = new class () extends SaTokenDaoMemory {
            public function set(string $key, string $value, ?int $timeout = null): void
            {
                parent::set($key, $value, null);
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);

        foreach ([time() + 60, time() - 60] as $createTime) {
            $refreshToken = 'refresh-token-invalid-time-' . $createTime;
            $key = 'oauth2:rt:' . $refreshToken;
            $dao->set($key, json_encode([
                'refreshToken' => $refreshToken,
                'accessToken' => 'access-token-invalid-time',
                'clientId' => 'test-client',
                'loginId' => 10001,
                'scope' => 'read',
                'expiresIn' => $createTime > time() ? 3600 : PHP_INT_MAX,
                'createTime' => $createTime,
                'familyId' => 'invalid-time-family',
            ], JSON_THROW_ON_ERROR));

            try {
                $this->handle->refreshToken($refreshToken, 'test-client', $this->clientSecret);
                self::fail('无效生命周期元数据的刷新令牌必须被拒绝');
            } catch (SaTokenException $exception) {
                self::assertStringContainsString('已过期', $exception->getMessage());
            }
            self::assertNotNull($dao->get($key), '生命周期预检失败时刷新令牌不应被消费');
        }
    }

    public function testRefreshTokenWithWrongClientId(): void
    {
        $code = $this->handle->generateAuthorizationCode('test-client', 10001, 'https://example.com/callback');
        $accessToken = $this->handle->exchangeTokenByCode($code->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');

        // 注册另一个客户端
        $otherClient = new SaOAuth2Client([
            'clientId'     => 'other-client',
            'clientSecret' => 'oauth-other-client-secret-with-at-least-32-bytes',
            'grantTypes'   => ['refresh_token'],
        ]);
        $this->handle->registerClient($otherClient);

        $refreshToken = $accessToken->getRefreshToken();
        $this->assertNotNull($refreshToken);
        try {
            $this->handle->refreshToken($refreshToken, 'other-client', 'oauth-other-client-secret-with-at-least-32-bytes');
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

    public function testTokenByPasswordRejectsScopesOutsideClientAllowlist(): void
    {
        $client = new SaOAuth2Client([
            'clientId' => 'password-scope-client',
            'clientSecret' => 'password-scope-client-secret-32-bytes',
            'grantTypes' => ['password'],
            'scopes' => ['read'],
        ]);
        $this->handle->registerClient($client);
        $this->handle->setUserCredentialsValidator(static fn (): int => 10001);
        SaTokenContext::setRequest($this->requestFromIp('192.0.2.31'));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未授予的 scope');
        $this->handle->tokenByPassword(
            'password-scope-client',
            'password-scope-client-secret-32-bytes',
            'user',
            'valid-password',
            'admin'
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

    public function testClientCredentialsRejectsSecretRotationDuringValidation(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public ?\Closure $afterClientSnapshot = null;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($key === 'oauth2:client:test-client' && $this->afterClientSnapshot !== null) {
                    $callback = $this->afterClientSnapshot;
                    $this->afterClientSnapshot = null;
                    $callback();
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);
        $dao->afterClientSnapshot = function (): void {
            $rotatedClient = new SaOAuth2Client(array_merge($this->testClient->toArray(), [
                'clientSecret' => 'rotated-client-secret-with-at-least-32-bytes',
            ]));
            $this->handle->registerClient($rotatedClient);
        };

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('客户端密钥错误');
        $this->handle->tokenByClientCredentials('test-client', $this->clientSecret, 'read');
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

    public function testAccessTokenRecordCannotBeCopiedToAnotherTokenKey(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('o', 32),
        ]));
        $this->handle->registerClient($this->testClient);
        $owner = $this->handle->tokenByClientCredentials('test-client', $this->clientSecret, 'read');
        $sourceKey = 'oauth2:at:' . $owner->getAccessToken();
        $otherToken = str_repeat('x', 64);
        $raw = SaToken::getDao()->get($sourceKey);
        self::assertNotNull($raw);
        SaToken::getDao()->set('oauth2:at:' . $otherToken, $raw, 7200);

        self::assertNull($this->handle->validateAccessToken($otherToken));
    }

    public function testEncryptedRefreshTokenRecordCannotBeCopiedToAnotherTokenKey(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('r', 32),
        ]));
        $this->handle->registerClient($this->testClient);
        $victimCode = $this->handle->generateAuthorizationCode('test-client', 'victim', 'https://example.com/callback');
        $victim = $this->handle->exchangeTokenByCode($victimCode->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $attackerCode = $this->handle->generateAuthorizationCode('test-client', 'attacker', 'https://example.com/callback');
        $attacker = $this->handle->exchangeTokenByCode($attackerCode->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $victimRefreshToken = $victim->getRefreshToken();
        $attackerRefreshToken = $attacker->getRefreshToken();
        if ($victimRefreshToken === null || $victimRefreshToken === ''
            || $attackerRefreshToken === null || $attackerRefreshToken === '') {
            self::fail('Authorization code exchange did not issue refresh tokens');
        }

        $dao = SaToken::getDao();
        $victimRecord = $dao->get('oauth2:rt:' . $victimRefreshToken);
        self::assertNotNull($victimRecord);
        $dao->set('oauth2:rt:' . $attackerRefreshToken, $victimRecord, 3600);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('存储记录与凭据不匹配');
        $this->handle->refreshToken($attackerRefreshToken, 'test-client', $this->clientSecret);
    }

    public function testEncryptedClientRecordCannotBeCopiedToAnotherClientKey(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('c', 32),
        ]));
        $this->handle->registerClient($this->testClient);
        $otherClientId = 'other-client';
        $this->handle->registerClient(new SaOAuth2Client([
            'clientId' => $otherClientId,
            'clientSecret' => str_repeat('d', 32),
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes' => ['authorization_code'],
            'scopes' => ['read'],
        ]));

        $dao = SaToken::getDao();
        $ownerRecord = $dao->get('oauth2:client:test-client');
        self::assertNotNull($ownerRecord);
        $dao->set('oauth2:client:' . $otherClientId, $ownerRecord);

        self::assertNull($this->handle->getClient($otherClientId));
    }

    public function testAuthorizationCodeRecordCannotBeCopiedToAnotherCodeKey(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('a', 32),
        ]));
        $this->handle->registerClient($this->testClient);
        $owner = $this->handle->generateAuthorizationCode('test-client', 'owner', 'https://example.com/callback');
        $other = $this->handle->generateAuthorizationCode('test-client', 'other', 'https://example.com/callback');

        $dao = SaToken::getDao();
        $ownerKey = 'oauth2:code:' . $owner->getCode();
        $otherKey = 'oauth2:code:' . $other->getCode();
        $dao->set($ownerKey, (string) $dao->get($otherKey), 300);

        $getAuthorizationCode = new \ReflectionMethod($this->handle, 'getAuthorizationCode');
        self::assertNull($getAuthorizationCode->invoke($this->handle, $owner->getCode()));
        self::assertNotNull($dao->get($otherKey));
    }

    public function testConsumedRefreshTombstoneCannotBeCopiedToAnotherRefreshKey(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('m', 32),
        ]));
        $this->handle->registerClient($this->testClient);
        $victimCode = $this->handle->generateAuthorizationCode('test-client', 'victim', 'https://example.com/callback');
        $victim = $this->handle->exchangeTokenByCode($victimCode->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $attackerCode = $this->handle->generateAuthorizationCode('test-client', 'attacker', 'https://example.com/callback');
        $attacker = $this->handle->exchangeTokenByCode($attackerCode->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $victimRefreshToken = $victim->getRefreshToken();
        $attackerRefreshToken = $attacker->getRefreshToken();
        if ($victimRefreshToken === null || $victimRefreshToken === ''
            || $attackerRefreshToken === null || $attackerRefreshToken === '') {
            self::fail('Authorization code exchange did not issue refresh tokens');
        }

        $descendant = $this->handle->refreshToken($victimRefreshToken, 'test-client', $this->clientSecret);
        $dao = SaToken::getDao();
        $tombstone = $dao->get('oauth2:rt:' . $victimRefreshToken);
        self::assertNotNull($tombstone);
        $dao->set('oauth2:rt:' . $attackerRefreshToken, $tombstone, 3600);

        try {
            $this->handle->refreshToken($attackerRefreshToken, 'test-client', $this->clientSecret);
            self::fail('A copied consumed marker must not be treated as a replay of another refresh token');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('消费记录与凭据不匹配', $exception->getMessage());
        }
        self::assertNotNull($this->handle->validateAccessToken($descendant->getAccessToken()));
    }

    public function testCopiedConsumedRefreshIndexCannotRevokeAnotherFamily(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('i', 32),
        ]));
        $this->handle->registerClient($this->testClient);

        $victimCode = $this->handle->generateAuthorizationCode('test-client', 'victim', 'https://example.com/callback');
        $victim = $this->handle->exchangeTokenByCode($victimCode->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $victimDescendant = $this->handle->refreshToken((string) $victim->getRefreshToken(), 'test-client', $this->clientSecret);

        $otherCode = $this->handle->generateAuthorizationCode('test-client', 'other', 'https://example.com/callback');
        $other = $this->handle->exchangeTokenByCode($otherCode->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $victimConsumedKey = 'oauth2:rt:consumed:' . hash('sha256', (string) $victim->getRefreshToken());
        $otherConsumedKey = 'oauth2:rt:consumed:' . hash('sha256', (string) $other->getRefreshToken());
        $dao = SaToken::getDao();
        $dao->set($otherConsumedKey, (string) $dao->get($victimConsumedKey), 3600);

        $otherDescendant = $this->handle->refreshToken((string) $other->getRefreshToken(), 'test-client', $this->clientSecret);

        self::assertNotNull($this->handle->validateAccessToken($victimDescendant->getAccessToken()));
        self::assertNotNull($this->handle->validateAccessToken($otherDescendant->getAccessToken()));
    }

    public function testOAuth2HandleUsesRotatedStorageEncryptionKey(): void
    {
        $oldKey = 'old-oauth2-storage-encryption-key-32-bytes';
        $newKey = 'new-oauth2-storage-encryption-key-32-bytes';
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => $oldKey,
        ]));
        $handle = new SaOAuth2Handle($this->config);
        $handle->registerClient($this->testClient);
        $accessToken = $handle->tokenByClientCredentials('test-client', $this->clientSecret, 'read');
        self::assertNotNull($handle->validateAccessToken($accessToken->getAccessToken()));

        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => $newKey,
        ]));

        try {
            $handle->validateAccessToken($accessToken->getAccessToken());
            self::fail('OAuth2 存储密钥轮换后，旧密文访问令牌必须失效');
        } catch (SaTokenException $e) {
            self::assertStringContainsString('完整性校验失败', $e->getMessage());
        }
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

    public function testCopiedAccessTokenFamilyIndexCannotRevokeAnotherFamily(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => str_repeat('f', 32),
        ]));
        $this->handle->registerClient($this->testClient);

        $dao = SaToken::getDao();
        $firstCode = $this->handle->generateAuthorizationCode('test-client', 'first-user', 'https://example.com/callback');
        $first = $this->handle->exchangeTokenByCode($firstCode->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $firstDescendant = $this->handle->refreshToken((string) $first->getRefreshToken(), 'test-client', $this->clientSecret);

        $secondCode = $this->handle->generateAuthorizationCode('test-client', 'second-user', 'https://example.com/callback');
        $second = $this->handle->exchangeTokenByCode($secondCode->getCode(), 'test-client', $this->clientSecret, 'https://example.com/callback');
        $secondDescendant = $this->handle->refreshToken((string) $second->getRefreshToken(), 'test-client', $this->clientSecret);

        $firstFamilyKey = 'oauth2:at:family:' . hash('sha256', $first->getAccessToken());
        $secondFamilyKey = 'oauth2:at:family:' . hash('sha256', $second->getAccessToken());
        $dao->set($firstFamilyKey, (string) $dao->get($secondFamilyKey), 3600);

        $this->handle->revokeAccessToken($first->getAccessToken());

        self::assertNotNull($this->handle->validateAccessToken($firstDescendant->getAccessToken()));
        self::assertNotNull($this->handle->validateAccessToken($secondDescendant->getAccessToken()));
    }

    public function testFamilyRevocationRetriesWhenRefreshUpdatesMarkerAfterSnapshotRead(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public ?string $raceKey = null;
            public ?string $racingMarker = null;
            public bool $raceOnRead = false;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($this->raceOnRead && $key === $this->raceKey) {
                    $this->raceOnRead = false;
                    parent::set($key, (string) $this->racingMarker, 3600);
                }
                return $value;
            }
        };
        SaToken::setDao($dao);
        $this->handle->registerClient($this->testClient);

        $familyId = 'family-race';
        $familyMarkerKey = 'oauth2:family:' . hash('sha256', $familyId);
        $dao->set($familyMarkerKey, json_encode([
            'tokens' => ['old-access'],
            'childRts' => [],
            'clientId' => 'test-client',
            'revokedAt' => time(),
        ], JSON_THROW_ON_ERROR), 3600);
        $dao->set('oauth2:at:new-access', json_encode([
            'refreshToken' => 'new-refresh',
        ], JSON_THROW_ON_ERROR), 3600);
        $dao->set('oauth2:rt:new-refresh', 'refresh-record', 3600);

        // Simulate a refresh request that wins the marker CAS after revocation
        // read its snapshot but before it writes the revoked state.
        $dao->raceKey = $familyMarkerKey;
        $dao->racingMarker = json_encode([
            'tokens' => ['new-access'],
            'childRts' => ['new-refresh'],
            'clientId' => 'test-client',
            'revokedAt' => time(),
        ], JSON_THROW_ON_ERROR);
        $dao->raceOnRead = true;

        $revokeFamily = new \ReflectionMethod($this->handle, 'revokeTokenFamily');
        $revokeFamily->invoke($this->handle, $familyMarkerKey);

        $revoked = json_decode((string) $dao->get($familyMarkerKey), true);
        self::assertIsArray($revoked);
        self::assertTrue($revoked['revoked'] ?? false);
        self::assertSame(['new-access'], $revoked['tokens'] ?? null);
        self::assertNull($dao->get('oauth2:at:new-access'));
        self::assertNull($dao->get('oauth2:rt:new-refresh'));
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
