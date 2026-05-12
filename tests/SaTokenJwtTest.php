<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Exception\SaTokenException;
use SaToken\Plugin\SaTokenJwt;

class SaTokenJwtTest extends TestCase
{
    protected SaTokenJwt $jwt;

    protected function setUp(): void
    {
        $secretKey = getenv('TEST_JWT_SECRET_KEY') ?: 'test-key-placeholder-32-bytes-lo';
        $this->jwt = new SaTokenJwt(['jwtSecretKey' => $secretKey]);
    }

    // ---- Create Token ----

    public function testCreateToken(): void
    {
        $token = $this->jwt->createToken(10001, 'login');
        $this->assertNotEmpty($token);
        $this->assertStringContainsString('.', $token); // JWT 格式：header.payload.signature
    }

    public function testCreateTokenWithTimeout(): void
    {
        $token = $this->jwt->createToken(10001, 'login', 3600);
        $this->assertNotEmpty($token);

        $payload = $this->jwt->parseToken($token);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertGreaterThan(time(), $payload['exp']);
    }

    public function testCreateTokenWithoutTimeout(): void
    {
        $token = $this->jwt->createToken(10001, 'login');
        $payload = $this->jwt->parseToken($token);
        $this->assertArrayNotHasKey('exp', $payload);
    }

    public function testCreateTokenContainsRequiredClaims(): void
    {
        $token = $this->jwt->createToken(10001, 'login');
        $payload = $this->jwt->parseToken($token);

        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('jti', $payload);
        $this->assertArrayHasKey('sub', $payload);
        $this->assertArrayHasKey('type', $payload);
        $this->assertEquals('10001', $payload['sub']);
        $this->assertEquals('login', $payload['type']);
    }

    public function testCreateTokenWithDifferentLoginIds(): void
    {
        $token1 = $this->jwt->createToken(10001, 'login');
        $token2 = $this->jwt->createToken(20002, 'login');

        $payload1 = $this->jwt->parseToken($token1);
        $payload2 = $this->jwt->parseToken($token2);

        $this->assertEquals('10001', $payload1['sub']);
        $this->assertEquals('20002', $payload2['sub']);
    }

    public function testCreateTokenWithDifferentLoginTypes(): void
    {
        $token = $this->jwt->createToken(10001, 'admin');
        $payload = $this->jwt->parseToken($token);
        $this->assertEquals('admin', $payload['type']);
    }

    // ---- Parse Token ----

    public function testParseToken(): void
    {
        $token = $this->jwt->createToken(10001, 'login', 3600);
        $payload = $this->jwt->parseToken($token);

        $this->assertIsArray($payload);
        $this->assertEquals('10001', $payload['sub']);
        $this->assertEquals('login', $payload['type']);
    }

    public function testParseTokenExpired(): void
    {
        $token = $this->jwt->createToken(10001, 'login', 1);
        sleep(2);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('JWT Token 已过期');
        $this->jwt->parseToken($token);
    }

    public function testParseTokenInvalidSignature(): void
    {
        $token = $this->jwt->createToken(10001, 'login');
        // 篡改 Token
        $parts = explode('.', $token);
        $parts[1] = base64_encode(base64_decode($parts[1], true) . 'tampered');
        $tamperedToken = implode('.', $parts);

        $this->expectException(SaTokenException::class);
        $this->jwt->parseToken($tamperedToken);
    }

    public function testParseTokenMalformed(): void
    {
        $this->expectException(SaTokenException::class);
        $this->jwt->parseToken('not-a-jwt-token');
    }

    // ---- getLoginId ----

    public function testGetLoginId(): void
    {
        $token = $this->jwt->createToken(10001, 'login');
        $this->assertEquals('10001', $this->jwt->getLoginId($token));
    }

    public function testGetLoginIdWithInvalidToken(): void
    {
        $this->assertNull($this->jwt->getLoginId('invalid-token'));
    }

    // ---- getLoginType ----

    public function testGetLoginType(): void
    {
        $token = $this->jwt->createToken(10001, 'admin');
        $this->assertEquals('admin', $this->jwt->getLoginType($token));
    }

    public function testGetLoginTypeWithInvalidToken(): void
    {
        $this->assertEquals('', $this->jwt->getLoginType('invalid-token'));
    }

    // ---- Secret Key ----

    public function testNoSecretKey(): void
    {
        $jwt = new SaTokenJwt([]);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('JWT 密钥未配置');
        $jwt->createToken(10001, 'login');
    }

    public function testParseTokenNoSecretKey(): void
    {
        $jwt = new SaTokenJwt([]);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('JWT 密钥未配置');
        $jwt->parseToken('some.token.value');
    }

    public function testWrongSecretKey(): void
    {
        $token = $this->jwt->createToken(10001, 'login');

        $wrongJwt = new SaTokenJwt(['jwtSecretKey' => 'wrong-secret-key-at-least-32-bytes-long']);
        $this->expectException(SaTokenException::class);
        $wrongJwt->parseToken($token);
    }

    public function testSecretKeyTooShort(): void
    {
        $jwt = new SaTokenJwt(['jwtSecretKey' => 'short']);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('JWT 密钥长度不足');
        $jwt->createToken(10001, 'login');
    }
}
