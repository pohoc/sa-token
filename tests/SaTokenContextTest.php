<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Util\SaTokenContext;

class SaTokenContextTest extends TestCase
{
    protected function tearDown(): void
    {
        SaTokenContext::setContextId('default');
        SaTokenContext::clear();
    }

    // ---- Context ID ----

    public function testSetAndGetContextId(): void
    {
        SaTokenContext::setContextId('test-coroutine-1');
        $this->assertEquals('test-coroutine-1', SaTokenContext::getContextId());
    }

    // ---- Request / Response ----

    public function testSetAndGetRequest(): void
    {
        $request = new \stdClass();
        $request->uri = '/api/test';
        SaTokenContext::setRequest($request);

        $this->assertSame($request, SaTokenContext::getRequest());
    }

    public function testGetRequestWhenNull(): void
    {
        $this->assertNull(SaTokenContext::getRequest());
    }

    public function testSetAndGetResponse(): void
    {
        $response = new \stdClass();
        SaTokenContext::setResponse($response);

        $this->assertSame($response, SaTokenContext::getResponse());
    }

    public function testGetResponseWhenNull(): void
    {
        $this->assertNull(SaTokenContext::getResponse());
    }

    // ---- Clear ----

    public function testClear(): void
    {
        SaTokenContext::setRequest(new \stdClass());
        SaTokenContext::setResponse(new \stdClass());
        SaTokenContext::clear();

        $this->assertNull(SaTokenContext::getRequest());
        $this->assertNull(SaTokenContext::getResponse());
    }

    // ---- Coroutine Isolation ----

    public function testContextIsolationByContextId(): void
    {
        SaTokenContext::setContextId('ctx-1');
        $req1 = new \stdClass();
        $req1->id = 1;
        SaTokenContext::setRequest($req1);

        SaTokenContext::setContextId('ctx-2');
        $req2 = new \stdClass();
        $req2->id = 2;
        SaTokenContext::setRequest($req2);

        // 当前上下文应为 ctx-2 的请求
        $req1 = SaTokenContext::getRequest();
        $this->assertEquals(2, is_object($req1) && property_exists($req1, 'id') ? $req1->id : null);

        SaTokenContext::setContextId('ctx-1');
        $req2 = SaTokenContext::getRequest();
        $this->assertEquals(1, is_object($req2) && property_exists($req2, 'id') ? $req2->id : null);
    }

    // ---- Header with PSR-7 ----

    public function testGetHeaderFromPsr7Request(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->with('satoken')->willReturn(['my-token-value']);
        SaTokenContext::setRequest($request);

        $this->assertEquals('my-token-value', SaTokenContext::getHeader('satoken'));
    }

    public function testGetHeaderWhenNoRequest(): void
    {
        $this->assertNull(SaTokenContext::getHeader('satoken'));
    }

    public function testGetHeaderFromPsr7EmptyHeader(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->with('satoken')->willReturn([]);
        SaTokenContext::setRequest($request);

        $this->assertNull(SaTokenContext::getHeader('satoken'));
    }

    // ---- Cookie with PSR-7 ----

    public function testGetCookieFromPsr7Request(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getCookieParams')->willReturn(['satoken' => 'cookie-token']);
        SaTokenContext::setRequest($request);

        $this->assertEquals('cookie-token', SaTokenContext::getCookie('satoken'));
    }

    public function testGetCookieWhenNoRequest(): void
    {
        $this->assertNull(SaTokenContext::getCookie('satoken'));
    }

    public function testGetCookieNotFound(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getCookieParams')->willReturn([]);
        SaTokenContext::setRequest($request);

        $this->assertNull(SaTokenContext::getCookie('nonexistent'));
    }

    // ---- Param with PSR-7 ----

    public function testGetParamFromQueryParams(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['token' => 'query-token']);
        $request->method('getParsedBody')->willReturn(null);
        SaTokenContext::setRequest($request);

        $this->assertEquals('query-token', SaTokenContext::getParam('token'));
    }

    public function testGetParamFromBody(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getParsedBody')->willReturn(['token' => 'body-token']);
        SaTokenContext::setRequest($request);

        $this->assertEquals('body-token', SaTokenContext::getParam('token'));
    }

    public function testGetParamWhenNoRequest(): void
    {
        $this->assertNull(SaTokenContext::getParam('token'));
    }

    // ---- Set Header on PSR-7 Response ----

    public function testSetHeaderOnPsr7Response(): void
    {
        $response = $this->createMock(\Psr\Http\Message\ResponseInterface::class);
        $newResponse = $this->createMock(\Psr\Http\Message\ResponseInterface::class);
        $response->method('withHeader')->with('satoken', 'Bearer xxx')->willReturn($newResponse);
        SaTokenContext::setResponse($response);

        SaTokenContext::setHeader('satoken', 'Bearer xxx');

        // 新响应应该被存回上下文
        $this->assertSame($newResponse, SaTokenContext::getResponse());
    }

    public function testSetHeaderWhenNoResponse(): void
    {
        // 不应抛异常
        SaTokenContext::setHeader('satoken', 'value');
        $this->assertNull(SaTokenContext::getResponse());
    }

    // ---- Set Cookie on PSR-7 Response ----

    public function testSetCookieOnPsr7Response(): void
    {
        $response = $this->createMock(\Psr\Http\Message\ResponseInterface::class);
        $newResponse = $this->createMock(\Psr\Http\Message\ResponseInterface::class);
        $response->method('withAddedHeader')->willReturn($newResponse);
        SaTokenContext::setResponse($response);

        SaTokenContext::setCookie('satoken', 'token-value', 3600, '/', '', false, false, 'Lax');

        $this->assertSame($newResponse, SaTokenContext::getResponse());
    }

    public function testSetCookieWhenNoResponse(): void
    {
        // 不应抛异常
        SaTokenContext::setCookie('satoken', 'value');
        $this->assertNull(SaTokenContext::getResponse());
    }
}
