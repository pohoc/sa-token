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
            'scopes'       => ['read', 'write', 'openid'],
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
