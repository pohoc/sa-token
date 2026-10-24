<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Exception\SaTokenException;
use SaToken\Tests\Fixtures\SymfonyHeaderBagStub;
use SaToken\Util\SaTokenContext;

class SaTokenContextTest extends TestCase
{
    protected function tearDown(): void
    {
        SaTokenContext::setContextId('default');
        SaTokenContext::clear();
        SaTokenContext::setTrustedProxies([]);
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

    public function testGetClientIpFromFrameworkRequest(): void
    {
        SaTokenContext::setRequest(new class () {
            public function getClientIp(): string
            {
                return '198.51.100.24';
            }
        });

        $this->assertSame('198.51.100.24', SaTokenContext::getClientIp());
    }

    public function testGetClientIpFromPsr7ServerParams(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '203.0.113.10']);
        SaTokenContext::setRequest($request);

        $this->assertSame('203.0.113.10', SaTokenContext::getClientIp());
    }

    public function testGetClientIpCombinesRepeatedForwardedForHeaders(): void
    {
        SaTokenContext::setTrustedProxies(['198.51.100.1']);
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '198.51.100.1']);
        $request->method('getHeader')->willReturnCallback(static function (string $name): array {
            return strcasecmp($name, 'X-Forwarded-For') === 0
                ? ['192.0.2.123', '203.0.113.88']
                : [];
        });
        SaTokenContext::setRequest($request);

        $this->assertSame('203.0.113.88', SaTokenContext::getClientIp());
    }

    public function testSetAndGetResponse(): void
    {
        $response = new \stdClass();
        SaTokenContext::setResponse($response);

        $this->assertSame($response, SaTokenContext::getResponse());
    }

    public function testNewRequestClearsPreviousResponseAndDeferredHeaders(): void
    {
        SaTokenContext::setContextId('reused-request-context');

        SaTokenContext::setHeader('X-Pending-Previous-User', 'pending-token');
        SaTokenContext::setRequest(new \stdClass());
        $previousResponse = new TestResponseTracker();
        SaTokenContext::setResponse($previousResponse);
        $this->assertArrayNotHasKey('X-Pending-Previous-User', $previousResponse->headers);

        SaTokenContext::setHeader('X-Previous-User', 'previous-token');

        SaTokenContext::setRequest(new \stdClass());

        $this->assertNull(SaTokenContext::getResponse());
        $this->assertSame('previous-token', $previousResponse->headers['X-Previous-User']);

        SaTokenContext::setHeader('X-Current-User', 'current-token');
        $currentResponse = new TestResponseTracker();
        SaTokenContext::setResponse($currentResponse);

        $this->assertArrayNotHasKey('X-Previous-User', $currentResponse->headers);
        $this->assertSame('current-token', $currentResponse->headers['X-Current-User']);
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

    public function testContextIsolatedAcrossInterleavedFibers(): void
    {
        $fiberA = new \Fiber(static function (): mixed {
            SaTokenContext::setRequest('request-a');
            \Fiber::suspend();
            return SaTokenContext::getRequest();
        });
        $fiberB = new \Fiber(static function (): mixed {
            SaTokenContext::setRequest('request-b');
            \Fiber::suspend();
            return SaTokenContext::getRequest();
        });

        $fiberA->start();
        $fiberB->start();
        $fiberA->resume();
        $fiberB->resume();

        $this->assertSame('request-a', $fiberA->getReturn());
        $this->assertSame('request-b', $fiberB->getReturn());
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
        $response = $this->createMock(\Psr\Http\Message\ResponseInterface::class);
        $newResponse = $this->createMock(\Psr\Http\Message\ResponseInterface::class);

        SaTokenContext::setHeader('satoken', 'value');
        $this->assertNull(SaTokenContext::getResponse());

        $response->method('withHeader')->with('satoken', 'value')->willReturn($newResponse);
        SaTokenContext::setResponse($response);

        $this->assertSame($newResponse, SaTokenContext::getResponse());
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

    public function testNegativeCookieTimeoutExpiresCookieImmediately(): void
    {
        $response = $this->createMock(\Psr\Http\Message\ResponseInterface::class);
        $newResponse = $this->createMock(\Psr\Http\Message\ResponseInterface::class);
        $response->expects(self::once())
            ->method('withAddedHeader')
            ->with('Set-Cookie', self::callback(static function (string $cookie): bool {
                self::assertStringContainsString('satoken=', $cookie);
                self::assertStringContainsString('Expires=', $cookie);
                self::assertStringContainsString('Max-Age=0', $cookie);
                return true;
            }))
            ->willReturn($newResponse);
        SaTokenContext::setResponse($response);

        SaTokenContext::setCookie('satoken', '', -1, '/', '', true, true, 'Lax');

        self::assertSame($newResponse, SaTokenContext::getResponse());
    }

    public function testFrameworkCookieUsesMinutesAndNegativeTimeoutForDeletion(): void
    {
        $response = new class () {
            /** @var list<array{string, string, int, string, string, bool, bool}> */
            public array $cookies = [];

            public function cookie(string $name, string $value, int $minutes, string $path, string $domain, bool $secure, bool $httpOnly): void
            {
                $this->cookies[] = [$name, $value, $minutes, $path, $domain, $secure, $httpOnly];
            }
        };
        SaTokenContext::setResponse($response);

        SaTokenContext::setCookie('satoken', 'token-value', 3600, '/', '', true, true);
        SaTokenContext::setCookie('satoken', '', -1, '/', '', true, true);

        self::assertSame(60, $response->cookies[0][2]);
        self::assertSame(-1, $response->cookies[1][2]);
    }

    public function testSetCookieWhenNoResponse(): void
    {
        $response = $this->createMock(\Psr\Http\Message\ResponseInterface::class);
        $newResponse = $this->createMock(\Psr\Http\Message\ResponseInterface::class);

        SaTokenContext::setCookie('satoken', 'value');
        $this->assertNull(SaTokenContext::getResponse());

        $response->method('withAddedHeader')->with(
            'Set-Cookie',
            $this->stringContains('satoken=value')
        )->willReturn($newResponse);
        SaTokenContext::setResponse($response);

        $this->assertSame($newResponse, SaTokenContext::getResponse());
    }

    public function testSetCookieRejectsInjectedAttributes(): void
    {
        $invalidCookies = [
            ['satoken; Domain=attacker.example', 'value', '/', '', 'Lax'],
            ['satoken', 'value', '/; Secure', '', 'Lax'],
            ['satoken', 'value', '/', 'example.com; Domain=attacker.example', 'Lax'],
            ['satoken', 'value', '/', '', 'Lax; Secure'],
        ];
        $rejected = 0;

        foreach ($invalidCookies as [$name, $value, $path, $domain, $sameSite]) {
            try {
                SaTokenContext::setCookie($name, $value, 60, $path, $domain, true, true, $sameSite);
                self::fail('不安全的 Cookie 属性必须被拒绝');
            } catch (SaTokenException) {
                // Expected: caller-controlled Cookie attributes cannot inject directives.
                $rejected++;
            }
        }

        self::assertSame(count($invalidCookies), $rejected);
    }

    public function testSetHeaderOnSymfonyStyleResponse(): void
    {
        $headers = new SymfonyHeaderBagStub();

        $response = new \stdClass();
        $response->headers = $headers;
        SaTokenContext::setResponse($response);

        SaTokenContext::setHeader('satoken', 'Bearer symfony');

        $resolved = SaTokenContext::getResponse();
        $this->assertSame($response, $resolved);
        $this->assertSame('Bearer symfony', $headers->values['satoken'] ?? null);
    }

    public function testSetCookieOnSymfonyStyleResponse(): void
    {
        if (!class_exists(\Symfony\Component\HttpFoundation\Cookie::class)) {
            require_once __DIR__ . '/Fixtures/SymfonyHttpFoundationCookieStub.php';
        }

        $headers = new SymfonyHeaderBagStub();

        $response = new \stdClass();
        $response->headers = $headers;
        SaTokenContext::setResponse($response);

        SaTokenContext::setCookie('satoken', 'symfony-cookie', 3600, '/', 'example.com', true, true, 'None');

        $resolved = SaTokenContext::getResponse();
        $this->assertSame($response, $resolved);
        $this->assertCount(1, $headers->cookies);

        $cookie = $headers->cookies[0];
        $this->assertSame('satoken', $cookie->name ?? null);
        $this->assertSame('symfony-cookie', $cookie->value ?? null);
        $this->assertSame('None', $cookie->sameSite ?? null);
    }

    public function testLaravelStyleResponseUsesSymfonyCookieAttributesWhenAvailable(): void
    {
        if (!class_exists(\Symfony\Component\HttpFoundation\Cookie::class)) {
            require_once __DIR__ . '/Fixtures/SymfonyHttpFoundationCookieStub.php';
        }

        $headers = new SymfonyHeaderBagStub();
        $response = new class ($headers) {
            /** @var array<int, bool|int|string> */
            public array $cookieCalls = [];

            public function __construct(public SymfonyHeaderBagStub $headers)
            {
            }

            public function cookie(string $name, string $value, int $minutes, string $path, string $domain, bool $secure, bool $httpOnly): void
            {
                $this->cookieCalls = [$name, $value, $minutes, $path, $domain, $secure, $httpOnly];
            }
        };
        SaTokenContext::setResponse($response);

        SaTokenContext::setCookie('satoken', 'laravel-cookie', 3600, '/', 'example.com', true, true, 'Strict');

        $this->assertSame([], $response->cookieCalls, '应优先使用 Symfony Cookie，避免 Laravel 分钟参数与配置丢失');
        $this->assertCount(1, $headers->cookies);
        $cookie = $headers->cookies[0];
        $this->assertSame('Strict', $cookie->sameSite ?? null);
        $this->assertGreaterThanOrEqual(time() + 3599, (int) $cookie->expire);
        $this->assertLessThanOrEqual(time() + 3601, (int) $cookie->expire);
    }

    public function testThinkPhpStyleResponseReceivesCookieOptionsArray(): void
    {
        $cookieManager = new ThinkPhpCookieManagerStub();
        $response = new ThinkPhpResponseStub($cookieManager);
        SaTokenContext::setResponse($response);

        SaTokenContext::setCookie('satoken', 'think-cookie', 3600, '/auth', 'example.com', true, true, 'Strict');

        $this->assertSame([
            'satoken',
            'think-cookie',
            [
                'expire' => 3600,
                'path' => '/auth',
                'domain' => 'example.com',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict',
            ],
        ], $cookieManager->lastSet);
    }
}

class ThinkPhpCookieManagerStub
{
    /** @var array{0: string, 1: string, 2: array<string, bool|int|string>}|null */
    public ?array $lastSet = null;

    /** @param array<string, bool|int|string> $options */
    public function set(string $name, string $value, array $options): void
    {
        $this->lastSet = [$name, $value, $options];
    }
}

class ThinkPhpResponseStub
{
    public function __construct(private ThinkPhpCookieManagerStub $cookieManager)
    {
    }

    public function getCookie(): ThinkPhpCookieManagerStub
    {
        return $this->cookieManager;
    }

    /** @param array<string, bool|int|string> $options */
    public function cookie(string $name, string $value, array $options): void
    {
        $this->cookieManager->set($name, $value, $options);
    }
}
