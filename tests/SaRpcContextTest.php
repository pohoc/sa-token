<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\Rpc\SaRpcContext;
use SaToken\Rpc\SaRpcInterceptor;
use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaRpcContextTest extends TestCase
{
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
            'isReadHeader'    => true,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        SaToken::setDao(new SaTokenDaoMemory());
        SaTokenContext::setContextId('default');
        SaTokenContext::clear();
        SaRpcContext::reset();
    }

    protected function tearDown(): void
    {
        SaTokenContext::setContextId('default');
        SaTokenContext::clear();
        SaToken::reset();
        SaRpcContext::reset();
    }

    /**
     * @param array<string, string> $headers
     */
    protected function mockRequestWithHeaders(array $headers): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($headers): array {
            return isset($headers[$name]) ? [$headers[$name]] : [];
        });
        return $request;
    }

    public function testAttachToHeaders(): void
    {
        $token = StpUtil::login(10001);

        $request = $this->mockRequestWithHeaders(['satoken' => $token]);
        SaTokenContext::setRequest($request);

        $headers = SaRpcContext::attachToHeaders([]);

        $this->assertArrayHasKey('X-Sa-Token', $headers);
        $this->assertEquals($token, $headers['X-Sa-Token']);
        $this->assertArrayHasKey('X-Sa-Login-Id', $headers);
        $this->assertEquals('10001', $headers['X-Sa-Login-Id']);
        $this->assertArrayHasKey('X-Sa-Login-Type', $headers);
        $this->assertEquals('login', $headers['X-Sa-Login-Type']);
    }

    public function testAttachToHeadersWithoutLogin(): void
    {
        $headers = SaRpcContext::attachToHeaders([]);

        $this->assertArrayNotHasKey('X-Sa-Token', $headers);
        $this->assertArrayNotHasKey('X-Sa-Login-Id', $headers);
        $this->assertArrayHasKey('X-Sa-Login-Type', $headers);
        $this->assertEquals('login', $headers['X-Sa-Login-Type']);
    }

    public function testExtractAndValidateWithValidToken(): void
    {
        $token = StpUtil::login(10001);

        $request = $this->mockRequestWithHeaders([
            'X-Sa-Token'      => $token,
            'X-Sa-Login-Id'   => '10001',
            'X-Sa-Login-Type' => 'login',
        ]);
        SaTokenContext::setRequest($request);

        SaRpcContext::extractAndValidate();
        $this->assertTrue(true);
    }

    public function testExtractAndValidateThrowsOnMissingToken(): void
    {
        $this->expectException(SaTokenException::class);
        SaRpcContext::extractAndValidate();
    }

    public function testExtractAndValidateThrowsOnInvalidToken(): void
    {
        $request = $this->mockRequestWithHeaders([
            'X-Sa-Token'      => 'invalid-token-value',
            'X-Sa-Login-Type' => 'login',
        ]);
        SaTokenContext::setRequest($request);

        $this->expectException(SaTokenException::class);
        SaRpcContext::extractAndValidate();
    }

    public function testIsRpcRequestReturnsTrue(): void
    {
        $request = $this->mockRequestWithHeaders(['X-Sa-Token' => 'some-token']);
        SaTokenContext::setRequest($request);

        $this->assertTrue(SaRpcContext::isRpcRequest());
    }

    public function testIsRpcRequestReturnsFalse(): void
    {
        $this->assertFalse(SaRpcContext::isRpcRequest());
    }

    public function testGetForwardedLoginId(): void
    {
        $request = $this->mockRequestWithHeaders([
            'X-Sa-Token'      => 'some-token',
            'X-Sa-Login-Id'   => '20001',
            'X-Sa-Login-Type' => 'login',
        ]);
        SaTokenContext::setRequest($request);

        $this->assertEquals('20001', SaRpcContext::getForwardedLoginId());
    }

    public function testCustomHeaderNames(): void
    {
        SaRpcContext::setTokenHeaderName('X-Custom-Token');
        $this->assertEquals('X-Custom-Token', SaRpcContext::getTokenHeaderName());

        $request = $this->mockRequestWithHeaders(['X-Custom-Token' => 'my-token']);
        SaTokenContext::setRequest($request);

        $this->assertTrue(SaRpcContext::isRpcRequest());
        $this->assertEquals('my-token', SaRpcContext::getForwardedToken());
    }

    public function testRpcInterceptorIncoming(): void
    {
        $token = StpUtil::login(10001);

        $request = $this->mockRequestWithHeaders([
            'X-Sa-Token'      => $token,
            'X-Sa-Login-Id'   => '10001',
            'X-Sa-Login-Type' => 'login',
        ]);
        SaTokenContext::setRequest($request);

        $interceptor = new SaRpcInterceptor();
        $interceptor->handleIncoming();

        $this->assertTrue(true);
    }

    public function testRpcInterceptorOutgoing(): void
    {
        $token = StpUtil::login(10001);

        $request = $this->mockRequestWithHeaders(['satoken' => $token]);
        SaTokenContext::setRequest($request);

        $interceptor = new SaRpcInterceptor();
        $headers = $interceptor->handleOutgoing([]);

        $this->assertArrayHasKey('X-Sa-Token', $headers);
        $this->assertEquals($token, $headers['X-Sa-Token']);
        $this->assertArrayHasKey('X-Sa-Login-Id', $headers);
        $this->assertArrayHasKey('X-Sa-Login-Type', $headers);
    }
}
