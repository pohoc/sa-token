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

    public function testUnknownCryptoTypeIsRejected(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('不支持的加密类型');

        new SaTokenJwt(['cryptoType' => 'smm']);
    }

    public function testParseTokenRejectsAlgorithmOutsideConfiguredCryptoType(): void
    {
        $token = $this->jwt->createToken(10001, 'login');
        $smConfiguredJwt = new SaTokenJwt([
            'jwtSecretKey' => getenv('TEST_JWT_SECRET_KEY') ?: 'test-key-placeholder-32-bytes-lo',
            'cryptoType' => 'sm',
        ]);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('算法与当前 cryptoType 配置不匹配');
        $smConfiguredJwt->parseToken($token);
    }

    public function testParseTokenRejectsNonCanonicalSignatureBase64Url(): void
    {
        $token = $this->jwt->createToken('user-1', 'login', 3600);
        [$header, $payload, $signature] = explode('.', $token);
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $lastIndex = strpos($alphabet, substr($signature, -1));
        self::assertIsInt($lastIndex);
        $aliasSignature = substr($signature, 0, -1) . $alphabet[$lastIndex ^ 1];
        $alias = $header . '.' . $payload . '.' . $aliasSignature;

        self::assertNotSame($token, $alias);
        $this->expectException(SaTokenException::class);
        $this->jwt->parseToken($alias);
    }

    public function testParseTokenRejectsOversizedInputBeforeDecoding(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('JWT Token 长度无效');

        $this->jwt->parseToken('header.payload.' . str_repeat('x', 65536));
    }

    public function testCreateTokenRejectsOversizedClaims(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('JWT Token 超过最大允许长度');

        $this->jwt->createToken('user-1', 'login', 3600, ['large_claim' => str_repeat('x', 65536)]);
    }

    public function testCreateTokenRejectsInvalidLoginIdTypes(): void
    {
        foreach ([null, '', false, true, [], new \stdClass()] as $loginId) {
            try {
                $this->jwt->createToken($loginId, 'login');
                $this->fail('无效 loginId 应被拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('loginId', $e->getMessage());
            }
        }
    }

    public function testCreateTokenWithTimeout(): void
    {
        $token = $this->jwt->createToken(10001, 'login', 3600);
        $this->assertNotEmpty($token);

        $payload = $this->jwt->parseToken($token);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertGreaterThan(time(), $payload['exp']);
    }

    public function testCreateTokenRejectsInvalidNonPositiveTimeouts(): void
    {
        foreach ([0, -2] as $timeout) {
            try {
                $this->jwt->createToken(10001, 'login', $timeout);
                $this->fail('无效 JWT 有效期必须被拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('有效期', $e->getMessage());
            }
        }
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

    public function testExtraClaimsCannotOverrideReservedSecurityClaims(): void
    {
        $token = $this->jwt->createToken(10001, 'login', null, [
            'sub' => 'attacker',
            'type' => 'admin',
            'exp' => time() + 86400,
            'iat' => 0,
            'jti' => 'reused-id',
            'nbf' => 0,
            'iss' => 'untrusted-issuer',
            'aud' => 'untrusted-audience',
            'satoken_gen' => 99,
            'custom' => 'kept',
        ]);
        $payload = $this->jwt->parseToken($token);

        $this->assertSame('10001', $payload['sub']);
        $this->assertSame('login', $payload['type']);
        $this->assertArrayNotHasKey('exp', $payload);
        $this->assertGreaterThan(0, $payload['iat']);
        $this->assertNotSame('reused-id', $payload['jti']);
        $this->assertArrayNotHasKey('nbf', $payload);
        $this->assertArrayNotHasKey('iss', $payload);
        $this->assertArrayNotHasKey('aud', $payload);
        $this->assertArrayNotHasKey('satoken_gen', $payload);
        $this->assertSame('kept', $payload['custom']);
    }

    public function testMixedTokenCannotInjectStatelessGenerationClaim(): void
    {
        $token = $this->jwt->createMixedToken(10001, 'login', null, ['satoken_gen' => 99]);
        $payload = $this->jwt->parseToken($token);

        $this->assertArrayNotHasKey('satoken_gen', $payload);
        $this->assertArrayNotHasKey('satoken_gen', $this->jwt->getExtraClaims($token));
    }

    public function testCreateTokenRejectsClaimsThatCannotBeEncoded(): void
    {
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $this->expectExceptionMessage('JWT Header 或 Payload 无法编码为 JSON');

        $this->jwt->createToken(10001, 'login', null, ['not-a-json-number' => NAN]);
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

    public function testParseTokenRejectsInvalidExpirationAndFutureNotBefore(): void
    {
        $secretKey = getenv('TEST_JWT_SECRET_KEY') ?: 'test-key-placeholder-32-bytes-lo';

        foreach ([['exp' => 'never'], ['exp' => null], ['nbf' => 'yesterday'], ['nbf' => time() + 3600]] as $claims) {
            $token = $this->createSignedToken($secretKey, array_merge([
                'sub' => '10001',
                'type' => 'login',
            ], $claims));

            try {
                $this->jwt->parseToken($token);
                $this->fail('无效时间声明应被拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('JWT Token', $e->getMessage());
            }
        }
    }

    /** @param array<string, mixed> $payload */
    private function createSignedToken(string $secretKey, array $payload): string
    {
        $encode = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
        $header = $encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256'], JSON_THROW_ON_ERROR));
        $body = $encode(json_encode($payload, JSON_THROW_ON_ERROR));
        $signingInput = $header . '.' . $body;

        return $signingInput . '.' . $encode(hash_hmac('sha256', $signingInput, $secretKey, true));
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
