<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\Data\SaOAuth2IdToken;
use SaToken\OAuth2\SaOAuth2Config;
use SaToken\OAuth2\SaOAuth2Handle;
use SaToken\OAuth2\Strategy\ImplicitStrategy;
use SaToken\SaToken;

class SaOAuth2OpenIdTest extends TestCase
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
            'jwtSecretKey'    => 'test-jwt-secret-key-for-oauth2-id-token-32b',
        ]));
        SaToken::setDao(new SaTokenDaoMemory());

        $this->config = new SaOAuth2Config([
            'grantTypes'          => ['authorization_code', 'password', 'client_credentials'],
            'codeTimeout'         => 300,
            'accessTokenTimeout'  => 7200,
            'refreshTokenTimeout' => 86400,
            'isNewRefreshToken'   => true,
            'openIdMode'          => true,
            'issuer'              => 'https://my-app.example.com',
        ]);

        $this->handle = new SaOAuth2Handle($this->config);

        $this->clientSecret = getenv('TEST_OAUTH2_CLIENT_SECRET') ?: 'test-key-placeholder-32-bytes-lo';
        $this->testClient = new SaOAuth2Client([
            'clientId'     => 'test-client',
            'clientSecret' => $this->clientSecret,
            'clientName'   => 'Test Client',
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes'   => ['authorization_code', 'password', 'client_credentials'],
            'scopes'       => ['read', 'write', 'openid', 'profile'],
        ]);

        $this->handle->registerClient($this->testClient);
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testGenerateIdToken(): void
    {
        $idToken = $this->handle->generateIdToken('test-client', 10001, 'openid profile');

        $this->assertInstanceOf(SaOAuth2IdToken::class, $idToken);
        $this->assertEquals('10001', $idToken->getSubject());
        $this->assertEquals('test-client', $idToken->getAudience());
        $this->assertEquals('https://my-app.example.com', $idToken->getIssuer());
        $this->assertNotEmpty($idToken->getIdToken());
        $this->assertGreaterThan(0, $idToken->getIssuedAt());
        $this->assertGreaterThan($idToken->getIssuedAt(), $idToken->getExpiresAt());
    }

    public function testGenerateIdTokenRejectsPayloadThatCannotBeEncoded(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('OAuth2 ID Token Payload 无法编码为 JSON');

        $this->handle->generateIdToken('test-client', "invalid-\xB1-subject", 'openid');
    }

    public function testGenerateIdTokenRejectsShortSigningKey(): void
    {
        SaToken::setConfig(new SaTokenConfig(['jwtSecretKey' => 'short-secret']));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('至少需要 32 字节');
        $this->handle->generateIdToken('test-client', 10001, 'openid');
    }

    public function testGenerateIdTokenRejectsInvalidIssuer(): void
    {
        $config = new SaOAuth2Config([
            'openIdMode' => true,
            'issuer' => 'http://my-app.example.com',
        ]);
        $handle = new SaOAuth2Handle($config);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('HTTPS issuer URL');
        $handle->generateIdToken('test-client', 10001, 'openid');
    }

    public function testOpenIdTokenIssuanceFailsBeforePersistingAccessTokenWithoutIssuer(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'openIdMode' => true,
        ]));
        $handle->registerClient($this->testClient);
        $before = SaToken::getDao()->size();

        try {
            $handle->generateAccessToken('test-client', 10001, 'openid');
            self::fail('OIDC access token issuance must reject a missing issuer');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('HTTPS issuer URL', $exception->getMessage());
        }

        self::assertSame($before, SaToken::getDao()->size());
    }

    public function testInvalidIssuerDoesNotConsumeAuthorizationCode(): void
    {
        $this->config->setIssuer('');
        $code = $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'openid profile'
        );

        try {
            $this->handle->exchangeTokenByCode(
                $code->getCode(),
                'test-client',
                $this->clientSecret,
                'https://example.com/callback'
            );
            self::fail('OIDC code exchange must reject a missing issuer');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('HTTPS issuer URL', $exception->getMessage());
        }

        $this->config->setIssuer('https://my-app.example.com');
        $token = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );
        self::assertNotEmpty($token->getIdToken());
    }

    public function testIdTokenContainsJwtString(): void
    {
        $idToken = $this->handle->generateIdToken('test-client', 10001, 'openid');
        $jwtStr = $idToken->getIdToken();

        $this->assertNotEmpty($jwtStr);

        $parts = explode('.', $jwtStr);
        $this->assertCount(3, $parts, 'id_token should be a JWT with 3 base64 parts separated by dots');

        foreach ($parts as $part) {
            $decoded = base64_decode(strtr($part, '-_', '+/'), true);
            $this->assertNotFalse($decoded, 'Each JWT part should be valid base64url');
        }

        $headerDecoded = base64_decode(strtr($parts[0], '-_', '+/'), true);
        $this->assertNotFalse($headerDecoded);
        $header = json_decode($headerDecoded, true);
        $this->assertIsArray($header);
        $this->assertEquals('JWT', $header['typ']);
        $this->assertEquals('HS256', $header['alg']);

        $payloadDecoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
        $this->assertNotFalse($payloadDecoded);
        $payload = json_decode($payloadDecoded, true);
        $this->assertIsArray($payload);
        $this->assertEquals('10001', $payload['sub']);
        $this->assertEquals('test-client', $payload['aud']);
        $this->assertEquals('https://my-app.example.com', $payload['iss']);
    }

    public function testAccessTokenIncludesIdTokenWhenOpenIdMode(): void
    {
        $code = $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'openid profile'
        );

        $accessToken = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );

        $this->assertInstanceOf(SaOAuth2AccessToken::class, $accessToken);
        $this->assertNotEmpty($accessToken->getIdToken(), 'Access token should include id_token when openIdMode is enabled and scope contains openid');

        $parts = explode('.', $accessToken->getIdToken());
        $this->assertCount(3, $parts, 'id_token should be a valid JWT');
    }

    public function testAuthorizationNonceIsPresentInReturnedAndStoredIdToken(): void
    {
        $nonce = 'client-generated-oidc-nonce';
        $code = $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'openid profile',
            nonce: $nonce
        );

        $issued = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );
        $stored = $this->handle->validateAccessToken($issued->getAccessToken());

        self::assertNotNull($stored);
        self::assertSame($issued->getIdToken(), $stored->getIdToken());
        $idTokenParts = explode('.', $stored->getIdToken());
        self::assertCount(3, $idTokenParts);
        $payloadJson = base64_decode(strtr($idTokenParts[1], '-_', '+/') . str_repeat('=', (4 - strlen($idTokenParts[1]) % 4) % 4), true);
        self::assertIsString($payloadJson);
        $payload = json_decode($payloadJson, true);
        self::assertIsArray($payload);
        self::assertSame($nonce, $payload['nonce'] ?? null);
    }

    public function testClientCredentialsCannotMintOpenIdOrRefreshTokens(): void
    {
        $clientId = 'machine-client';
        $secret = 'machine-client-secret-with-at-least-32-bytes';
        $client = new SaOAuth2Client([
            'clientId' => $clientId,
            'clientSecret' => $secret,
            'grantTypes' => ['client_credentials'],
            'scopes' => ['read', 'openid'],
        ]);
        $this->handle->registerClient($client);

        $accessToken = $this->handle->tokenByClientCredentials($clientId, $secret, 'read');
        self::assertSame('', $accessToken->getIdToken());
        self::assertNull($accessToken->getRefreshToken());

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('client_credentials 不允许请求 openid scope');
        $this->handle->tokenByClientCredentials($clientId, $secret, 'openid');
    }

    public function testPasswordGrantCannotMintOpenIdToken(): void
    {
        $this->handle->setUserCredentialsValidator(static fn (): int => 10001);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('OpenID Connect 不支持密码授权请求 openid scope');
        $this->handle->tokenByPassword(
            'test-client',
            $this->clientSecret,
            'user',
            'password',
            'openid profile'
        );
    }

    public function testImplicitOpenIdFlowRequiresNonceAndIncludesAccessTokenHash(): void
    {
        $implicitClient = new SaOAuth2Client([
            'clientId' => 'implicit-client',
            'clientSecret' => 'implicit-client-secret-at-least-32-bytes',
            'redirectUris' => ['https://example.com/callback'],
            'grantTypes' => ['implicit'],
            'scopes' => ['openid', 'profile'],
        ]);
        $this->handle->registerClient($implicitClient);
        $strategy = new ImplicitStrategy($this->handle);

        try {
            $strategy->authorize('implicit-client', 10001, 'openid profile', 'https://example.com/callback');
            self::fail('OIDC implicit flow must reject a missing nonce');
        } catch (SaTokenException $exception) {
            self::assertSame('OpenID Connect 隐式授权必须提供 nonce', $exception->getMessage());
        }

        $nonce = 'implicit-client-nonce';
        $accessToken = $strategy->authorize(
            'implicit-client',
            10001,
            'openid profile',
            'https://example.com/callback',
            $nonce
        );
        $parts = explode('.', $accessToken->getIdToken());
        self::assertCount(3, $parts);
        $payloadJson = base64_decode(strtr($parts[1], '-_', '+/') . str_repeat('=', (4 - strlen($parts[1]) % 4) % 4), true);
        self::assertIsString($payloadJson);
        $payload = json_decode($payloadJson, true);
        self::assertIsArray($payload);
        self::assertSame($nonce, $payload['nonce'] ?? null);
        self::assertSame(
            rtrim(strtr(base64_encode(substr(hash('sha256', $accessToken->getAccessToken(), true), 0, 16)), '+/', '-_'), '='),
            $payload['at_hash'] ?? null
        );
    }

    public function testScopeContainsOpenid(): void
    {
        $handle = new class ($this->config) extends SaOAuth2Handle {
            public function testScopeContainsOpenid(string $scope): bool
            {
                return $this->scopeContainsOpenid($scope);
            }
        };

        $this->assertTrue($handle->testScopeContainsOpenid('openid profile'));
        $this->assertTrue($handle->testScopeContainsOpenid('openid'));
        $this->assertFalse($handle->testScopeContainsOpenid('profile email'));
        $this->assertFalse($handle->testScopeContainsOpenid(''));
    }

    public function testCheckScopeValidatesCorrectly(): void
    {
        $code = $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'read write'
        );

        $accessToken = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );

        $this->assertTrue($this->handle->checkScope($accessToken->getAccessToken(), 'read'));
        $this->assertTrue($this->handle->checkScope($accessToken->getAccessToken(), 'write'));
        $this->assertFalse($this->handle->checkScope($accessToken->getAccessToken(), 'admin'));
        $this->assertFalse($this->handle->checkScope($accessToken->getAccessToken(), ''));
        $this->assertFalse($this->handle->checkScope($accessToken->getAccessToken(), ' '));
    }

    public function testWhitespaceOnlyScopeIsRejected(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('scope 不能只包含空白字符');
        $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            '   '
        );
    }

    public function testCheckScopeAndThrowThrowsOnMissingScope(): void
    {
        $code = $this->handle->generateAuthorizationCode(
            'test-client',
            10001,
            'https://example.com/callback',
            'read write'
        );

        $accessToken = $this->handle->exchangeTokenByCode(
            $code->getCode(),
            'test-client',
            $this->clientSecret,
            'https://example.com/callback'
        );

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('权限不足，缺少 scope: admin');
        $this->handle->checkScopeAndThrow($accessToken->getAccessToken(), 'admin');
    }
}
