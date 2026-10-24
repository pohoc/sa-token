<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Auth\SaHttpAuth;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

class SaHttpAuthTest extends TestCase
{
    protected TestResponseTracker $responseTracker;

    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        SaToken::setDao(new SaTokenDaoMemory());

        $this->responseTracker = new TestResponseTracker();
        SaTokenContext::setResponse($this->responseTracker);
    }

    public function testDigestParserRejectsDuplicateAndMalformedFields(): void
    {
        $auth = new SaHttpAuth();

        self::assertSame([], $auth->parseDigestHeader('Digest username="alice", Username="mallory"'));
        self::assertSame([], $auth->parseDigestHeader('Digest username="alice" junk, nonce="n"'));
        self::assertSame(['username' => 'alice', 'nonce' => 'n'], $auth->parseDigestHeader('Digest username="alice", nonce="n"'));
        self::assertSame(['realm' => 'tenant"\\one'], $auth->parseDigestHeader('Digest realm="tenant\\"\\\\one"'));
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaTokenContext::clear();
    }

    public function testCheckBasicWithValidCredentials(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name): array {
            if ($name === 'Authorization') {
                return ['Basic ' . base64_encode('admin:123456')];
            }
            return [];
        });
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(function (string $username, string $password): ?string {
            if ($username === 'admin' && $password === '123456') {
                return 'admin';
            }
            return null;
        });
        $auth->checkBasic();
        $this->assertTrue(true);
    }

    public function testCheckBasicRejectsDuplicateAuthorizationHeaders(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Basic ' . base64_encode('admin:first'), 'Basic ' . base64_encode('admin:second')]
            : []);
        SaTokenContext::setRequest($request);

        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return 'admin';
        });

        try {
            $auth->checkBasic();
            $this->fail('重复 Authorization Header 必须被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('存在多个值', $e->getMessage());
        }
        $this->assertSame(0, $validatorCalls);
    }

    public function testCheckBasicThrowsOnMissingHeader(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn([]);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
    }

    public function testCheckDigestRejectsDuplicateAuthorizationHeaders(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Digest username="alice"', 'Digest username="mallory"']
            : []);
        SaTokenContext::setRequest($request);

        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setDigestValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return md5('alice:Sa-Token:password');
        });

        try {
            $auth->checkDigest();
            $this->fail('重复 Authorization Header 必须被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('存在多个值', $e->getMessage());
        }
        $this->assertSame(0, $validatorCalls);
    }

    public function testCheckBasicThrowsOnInvalidCredentials(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name): array {
            if ($name === 'Authorization') {
                return ['Basic ' . base64_encode('admin:wrong')];
            }
            return [];
        });
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(function (string $username, string $password): ?string {
            return null;
        });
        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
    }

    public function testCheckBasicTreatsFalseValidatorResultAsFailure(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn(['Basic ' . base64_encode('admin:wrong')]);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static fn (): bool => false);

        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
    }

    public function testCheckBasicDoesNotTreatTrueAsLoginId(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn(['Basic ' . base64_encode('admin:valid')]);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static fn (): bool => true);

        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
    }

    public function testBasicAuthenticationLocksAfterConfiguredFailures(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setAntiBruteMaxFailures(2)->setAntiBruteLockDuration(60));
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn(['Basic ' . base64_encode('admin:wrong')]);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static function () use (&$validatorCalls): ?string {
            $validatorCalls++;
            return null;
        });

        for ($attempt = 0; $attempt < 2; $attempt++) {
            try {
                $auth->checkBasic();
                $this->fail('错误的 Basic 凭据必须被拒绝');
            } catch (SaTokenException) {
            }
        }

        try {
            $auth->checkBasic();
            $this->fail('达到失败上限后，Basic 验证器不得继续运行');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('锁定', $e->getMessage());
        }

        $this->assertSame(2, $validatorCalls);
    }

    public function testDigestAuthenticationLocksAfterConfiguredFailures(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setAntiBruteMaxFailures(2)->setAntiBruteLockDuration(60));
        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setDigestValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return md5('admin:Test:password');
        });

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $nonce = 'issued-nonce-' . $attempt;
            $header = 'Digest username="admin", realm="Test", nonce="' . $nonce
                . '", uri="/test", qop=auth, nc=00000001, cnonce="xyz", response="invalid"';
            $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
            $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
            $request->method('getMethod')->willReturn('GET');
            $request->method('getRequestTarget')->willReturn('/test');
            $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
            SaTokenContext::setRequest($request);
            SaToken::getDao()->set('satoken:auth:digest:nonce:' . hash('sha256', $nonce), '1', 300);

            try {
                $auth->checkDigest('Test');
                $this->fail('无效的 Digest 凭据必须被拒绝');
            } catch (SaTokenException $e) {
                if ($attempt === 2) {
                    $this->assertStringContainsString('锁定', $e->getMessage());
                }
            }
        }

        $this->assertSame(2, $validatorCalls);
    }

    public function testCheckDigestTreatsFalseValidatorResultAsFailure(): void
    {
        $nonce = 'issued-nonce';
        $header = 'Digest username="admin", realm="Test", nonce="' . $nonce
            . '", uri="/test", qop=auth, nc=00000001, cnonce="xyz", response="invalid"';
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($header): array {
            return $name === 'Authorization' ? [$header] : [];
        });
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn('/test');
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);
        SaToken::getDao()->set('satoken:auth:digest:nonce:' . hash('sha256', $nonce), '1', 300);

        $auth = new SaHttpAuth();
        $auth->setDigestValidator(static fn (): bool => false);

        $this->expectException(SaTokenException::class);
        $auth->checkDigest('Test');
    }

    public function testCheckDigestRejectsEmptyHa1FromValidator(): void
    {
        $username = 'unknown-user';
        $nonce = 'issued-empty-ha1-nonce';
        $uri = '/test';
        $ha2 = md5('GET:' . $uri);
        $response = md5(':' . $nonce . ':00000001:xyz:auth:' . $ha2);
        $header = sprintf(
            'Digest username="%s", realm="Test", nonce="%s", uri="%s", qop=auth, nc=00000001, cnonce="xyz", response="%s"',
            $username,
            $nonce,
            $uri,
            $response
        );
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn($uri);
        SaTokenContext::setRequest($request);
        SaToken::getDao()->set('satoken:auth:digest:nonce:' . hash('sha256', $nonce), '1', 300);

        $auth = new SaHttpAuth();
        $auth->setDigestValidator(static fn (): string => '');

        $this->expectException(SaTokenException::class);
        $auth->checkDigest('Test');
    }

    public function testCheckDigestRejectsRealmMismatchAndUnsupportedQop(): void
    {
        foreach ([
            ['headerRealm' => 'Other', 'challengeRealm' => 'Test', 'qop' => 'auth'],
            ['headerRealm' => 'Test', 'challengeRealm' => 'Test', 'qop' => 'auth-int'],
        ] as $case) {
            $nonce = 'issued-invalid-digest-' . bin2hex(random_bytes(4));
            $uri = '/test';
            $username = 'admin';
            $ha1 = md5($username . ':' . $case['headerRealm'] . ':secret');
            $ha2 = md5('GET:' . $uri);
            $response = md5($ha1 . ':' . $nonce . ':00000001:xyz:' . $case['qop'] . ':' . $ha2);
            $header = sprintf(
                'Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=00000001, cnonce="xyz", response="%s"',
                $username,
                $case['headerRealm'],
                $nonce,
                $uri,
                $case['qop'],
                $response
            );
            $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
            $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
            $request->method('getMethod')->willReturn('GET');
            $request->method('getRequestTarget')->willReturn($uri);
            SaTokenContext::setRequest($request);
            SaToken::getDao()->set('satoken:auth:digest:nonce:' . hash('sha256', $nonce), '1', 300);

            $auth = new SaHttpAuth();
            $validatorCalls = 0;
            $auth->setDigestValidator(static function () use (&$validatorCalls, $username, $case): string {
                $validatorCalls++;
                return md5($username . ':' . $case['challengeRealm'] . ':secret');
            });
            try {
                $auth->checkDigest($case['challengeRealm']);
                self::fail('Realm mismatch and unsupported qop must be rejected');
            } catch (SaTokenException) {
                self::assertSame(0, $validatorCalls);
            }
            SaTokenContext::clear();
        }
    }

    public function testSendChallengeSetsHeader(): void
    {
        $auth = new SaHttpAuth();
        $auth->sendChallenge('TestRealm');
        $this->assertEquals('Basic realm="TestRealm"', $this->responseTracker->headers['WWW-Authenticate']);
    }

    public function testChallengeRealmEscapesQuotedStringCharacters(): void
    {
        $auth = new SaHttpAuth();
        $auth->sendChallenge('tenant"\\one');

        $this->assertSame('Basic realm="tenant\\"\\\\one"', $this->responseTracker->headers['WWW-Authenticate']);
    }

    public function testChallengeRealmRejectsHeaderControlCharacters(): void
    {
        $auth = new SaHttpAuth();

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('认证 realm 不能包含控制字符');
        $auth->sendDigestChallenge("safe\r\nSet-Cookie: attacker=1");
    }

    public function testGenerateNonceReturnsNonEmptyString(): void
    {
        $auth = new SaHttpAuth();
        $nonce = $auth->generateNonce();
        $this->assertEquals(32, strlen($nonce));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $nonce);
    }

    public function testParseDigestHeader(): void
    {
        $header = 'Digest username="admin", realm="Test", nonce="abc123", uri="/test", qop=auth, nc=00000001, cnonce="xyz789", response="resp123"';
        $auth = new SaHttpAuth();
        $result = $auth->parseDigestHeader($header);
        $this->assertEquals('admin', $result['username']);
        $this->assertEquals('Test', $result['realm']);
        $this->assertEquals('abc123', $result['nonce']);
        $this->assertEquals('/test', $result['uri']);
        $this->assertEquals('auth', $result['qop']);
        $this->assertEquals('00000001', $result['nc']);
        $this->assertEquals('xyz789', $result['cnonce']);
        $this->assertEquals('resp123', $result['response']);
    }

    public function testCheckDigestWithValidCredentials(): void
    {
        $username = 'admin';
        $realm = 'Test';
        $password = '123456';
        $nonce = 'abc123';
        $uri = '/test';
        $qop = 'auth';
        $nc = '00000001';
        $cnonce = 'xyz789';

        $ha1 = md5($username . ':' . $realm . ':' . $password);
        $ha2 = md5('GET:' . $uri);
        $response = md5($ha1 . ':' . $nonce . ':' . $nc . ':' . $cnonce . ':' . $qop . ':' . $ha2);

        $digestHeader = sprintf(
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"',
            $username,
            $realm,
            $nonce,
            $uri,
            $qop,
            $nc,
            $cnonce,
            $response
        );

        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($digestHeader): array {
            if ($name === 'Authorization') {
                return [$digestHeader];
            }
            return [];
        });
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn('/test');
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        // 模拟服务端此前已通过 sendDigestChallenge 签发该 nonce
        SaToken::getDao()->set('satoken:auth:digest:nonce:' . hash('sha256', $nonce), '1', 300);

        $auth = new SaHttpAuth();
        $auth->setDigestValidator(function (string $user) use ($ha1): ?string {
            if ($user === 'admin') {
                return $ha1;
            }
            return null;
        });
        $auth->checkDigest($realm);
        $this->assertTrue(true);

        // 同一 nonce 的重放必须被拒绝（nonce 一次性消费）
        try {
            $auth->checkDigest($realm);
            $this->fail('重放已消费的 Digest nonce 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('重放', $e->getMessage());
        }

        // 从未签发过的 nonce 也必须被拒绝
        $forgedHeader = str_replace('nonce="' . $nonce . '"', 'nonce="forged-nonce"', $digestHeader);
        $request2 = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request2->method('getHeader')->willReturnCallback(function (string $name) use ($forgedHeader): array {
            if ($name === 'Authorization') {
                return [$forgedHeader];
            }
            return [];
        });
        $request->method('getRequestTarget')->willReturn('/test');
        SaTokenContext::setRequest($request2);
        try {
            $auth->checkDigest($realm);
            $this->fail('未签发的 Digest nonce 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('重放', $e->getMessage());
        }
    }

    public function testCheckDigestRejectsAuthorizationForDifferentRequestTarget(): void
    {
        $username = 'admin';
        $realm = 'Test';
        $nonce = 'issued-nonce-path-binding';
        $signedUri = '/public';
        $ha1 = md5($username . ':' . $realm . ':123456');
        $ha2 = md5('GET:' . $signedUri);
        $response = md5($ha1 . ':' . $nonce . ':00000001:xyz:auth:' . $ha2);
        $header = sprintf(
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=auth, nc=00000001, cnonce="xyz", response="%s"',
            $username,
            $realm,
            $nonce,
            $signedUri,
            $response
        );

        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn('/admin');
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);
        SaToken::getDao()->set('satoken:auth:digest:nonce:' . hash('sha256', $nonce), '1', 300);

        $auth = new SaHttpAuth();
        $auth->setDigestValidator(static fn (string $user): ?string => $user === $username ? $ha1 : null);

        try {
            $auth->checkDigest($realm);
            $this->fail('针对其他 URI 签发的 Digest 响应不得认证当前请求');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('URI', $e->getMessage());
        }

        $this->assertNull(\SaToken\StpUtil::getLoginId());
        $this->assertNotNull(SaToken::getDao()->get('satoken:auth:digest:nonce:' . hash('sha256', $nonce)));
    }

    public function testCheckDigestThrowsOnMissingHeader(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn([]);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $this->expectException(SaTokenException::class);
        $auth->checkDigest();
    }
}
