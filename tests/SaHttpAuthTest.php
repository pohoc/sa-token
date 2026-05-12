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

    public function testCheckBasicThrowsOnMissingHeader(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn([]);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
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

    public function testSendChallengeSetsHeader(): void
    {
        $auth = new SaHttpAuth();
        $auth->sendChallenge('TestRealm');
        $this->assertEquals('Basic realm="TestRealm"', $this->responseTracker->headers['WWW-Authenticate']);
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
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setDigestValidator(function (string $user) use ($ha1): ?string {
            if ($user === 'admin') {
                return $ha1;
            }
            return null;
        });
        $auth->checkDigest($realm);
        $this->assertTrue(true);
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
