<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Exception\SaTokenException;
use SaToken\Plugin\SaTokenJwt;
use SaToken\SaToken;

class SaTokenJwtSmTest extends TestCase
{
    private bool $smAvailable = false;

    protected function setUp(): void
    {
        SaToken::reset();
        $this->smAvailable = class_exists(\CryptoSm\SM3\Sm3::class);
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    private function skipIfSmUnavailable(): void
    {
        if (!$this->smAvailable) {
            $this->markTestSkipped('CryptoSm SM3 extension not available');
        }
    }

    public function testCreateTokenWithSmProducesJwtWithAlgSm3(): void
    {
        $this->skipIfSmUnavailable();

        $secretKey = getenv('TEST_JWT_SM_SECRET_KEY') ?: 'test-key-placeholder-32-bytes-lo';
        $jwt = new SaTokenJwt([
            'jwtSecretKey' => $secretKey,
            'cryptoType' => 'sm',
        ]);

        $token = $jwt->createToken(10001, 'login');
        $this->assertNotEmpty($token);

        $parts = explode('.', $token);
        $this->assertCount(3, $parts);

        $decoded = base64_decode(strtr($parts[0], '-_', '+/'), true);
        $this->assertNotFalse($decoded);
        $header = json_decode($decoded, true);
        $this->assertNotNull($header);
        $this->assertEquals('SM3', is_array($header) ? ($header['alg'] ?? null) : null);
    }

    public function testParseTokenWithSm3SignedJwt(): void
    {
        $this->skipIfSmUnavailable();

        $secretKey = getenv('TEST_JWT_SM_SECRET_KEY') ?: 'sm-secret-key-for-testing-at-least-32b';
        $jwt = new SaTokenJwt([
            'jwtSecretKey' => $secretKey,
            'cryptoType' => 'sm',
        ]);

        $token = $jwt->createToken(10001, 'login', 3600);
        $payload = $jwt->parseToken($token);

        $this->assertEquals('10001', $payload['sub']);
        $this->assertEquals('login', $payload['type']);
        $this->assertArrayHasKey('exp', $payload);
    }

    public function testGetLoginIdAndLoginTypeWithSm3Jwt(): void
    {
        $this->skipIfSmUnavailable();

        $secretKey = getenv('TEST_JWT_SM_SECRET_KEY') ?: 'sm-secret-key-for-testing-at-least-32b';
        $jwt = new SaTokenJwt([
            'jwtSecretKey' => $secretKey,
            'cryptoType' => 'sm',
        ]);

        $token = $jwt->createToken(20002, 'admin');

        $this->assertEquals('20002', $jwt->getLoginId($token));
        $this->assertEquals('admin', $jwt->getLoginType($token));
    }

    public function testExpiredSm3JwtThrowsException(): void
    {
        $this->skipIfSmUnavailable();

        $secretKey = getenv('TEST_JWT_SM_SECRET_KEY') ?: 'sm-secret-key-for-testing-at-least-32b';
        $jwt = new SaTokenJwt([
            'jwtSecretKey' => $secretKey,
            'cryptoType' => 'sm',
        ]);

        $token = $jwt->createToken(10001, 'login', 1);
        sleep(2);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('JWT Token 已过期');
        $jwt->parseToken($token);
    }

    public function testTamperedSm3JwtThrowsException(): void
    {
        $this->skipIfSmUnavailable();

        $secretKey = getenv('TEST_JWT_SM_SECRET_KEY') ?: 'sm-secret-key-for-testing-at-least-32b';
        $jwt = new SaTokenJwt([
            'jwtSecretKey' => $secretKey,
            'cryptoType' => 'sm',
        ]);

        $token = $jwt->createToken(10001, 'login');
        $parts = explode('.', $token);
        $parts[1] = base64_encode(base64_decode(strtr($parts[1], '-_', '+/'), true) . 'tampered');
        $tamperedToken = implode('.', $parts);

        $this->expectException(SaTokenException::class);
        $jwt->parseToken($tamperedToken);
    }

    public function testWrongSecretKeyFailsVerification(): void
    {
        $this->skipIfSmUnavailable();

        $secretKey = getenv('TEST_JWT_SM_SECRET_KEY') ?: 'sm-secret-key-for-testing-at-least-32b';
        $jwt = new SaTokenJwt([
            'jwtSecretKey' => $secretKey,
            'cryptoType' => 'sm',
        ]);

        $token = $jwt->createToken(10001, 'login');

        $wrongJwt = new SaTokenJwt([
            'jwtSecretKey' => 'wrong-sm-secret-key-at-least-32-bytes',
            'cryptoType' => 'sm',
        ]);

        $this->expectException(SaTokenException::class);
        $wrongJwt->parseToken($token);
    }
}
