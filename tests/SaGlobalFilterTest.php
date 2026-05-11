<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Middleware\SaGlobalFilter;
use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

class SaGlobalFilterTest extends TestCase
{
    protected object $responseTracker;

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

        $this->responseTracker = new class () {
            public array $headers = [];
            public ?int $statusCode = null;
            public function header(string $name, string $value): void
            {
                $this->headers[$name] = $value;
            }
            public function status(int $code): void
            {
                $this->statusCode = $code;
            }
        };
        SaTokenContext::setResponse($this->responseTracker);
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaTokenContext::clear();
    }

    public function testAddBeforeFilterIsExecuted(): void
    {
        $flag = false;
        $filter = new SaGlobalFilter();
        $filter->addBeforeFilter(function () use (&$flag): void {
            $flag = true;
        });
        $filter->execute();
        $this->assertTrue($flag);
    }

    public function testAddAfterFilterIsExecuted(): void
    {
        $flag = false;
        $filter = new SaGlobalFilter();
        $filter->addAfterFilter(function () use (&$flag): void {
            $flag = true;
        });
        $filter->execute();
        $this->assertTrue($flag);
    }

    public function testSecurityHeadersAreApplied(): void
    {
        $filter = new SaGlobalFilter();
        $filter->execute();
        $this->assertEquals('nosniff', $this->responseTracker->headers['X-Content-Type-Options']);
        $this->assertEquals('SAMEORIGIN', $this->responseTracker->headers['X-Frame-Options']);
        $this->assertEquals('1; mode=block', $this->responseTracker->headers['X-XSS-Protection']);
        $this->assertEquals('strict-origin-when-cross-origin', $this->responseTracker->headers['Referrer-Policy']);
    }

    public function testCorsHeadersAreApplied(): void
    {
        $filter = new SaGlobalFilter();
        $filter->setCors([
            'allowOrigin' => 'http://example.com',
            'allowMethods' => 'GET, POST, OPTIONS',
            'allowHeaders' => 'Content-Type, Authorization',
            'allowCredentials' => true,
            'maxAge' => 3600,
        ]);
        $filter->execute();
        $this->assertEquals('http://example.com', $this->responseTracker->headers['Access-Control-Allow-Origin']);
        $this->assertEquals('GET, POST, OPTIONS', $this->responseTracker->headers['Access-Control-Allow-Methods']);
        $this->assertEquals('Content-Type, Authorization', $this->responseTracker->headers['Access-Control-Allow-Headers']);
        $this->assertEquals('true', $this->responseTracker->headers['Access-Control-Allow-Credentials']);
        $this->assertEquals('3600', $this->responseTracker->headers['Access-Control-Max-Age']);
    }

    public function testIsCorsRequestReturnsTrueForOptionsWithOrigin(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name): array {
            if ($name === 'Origin') {
                return ['http://example.com'];
            }
            return [];
        });
        $request->method('getMethod')->willReturn('OPTIONS');
        SaTokenContext::setRequest($request);

        $filter = new SaGlobalFilter();
        $this->assertTrue($filter->isCorsRequest());
    }

    public function testIsCorsRequestReturnsFalseWithoutOrigin(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn([]);
        SaTokenContext::setRequest($request);

        $filter = new SaGlobalFilter();
        $this->assertFalse($filter->isCorsRequest());
    }

    public function testHandlePreflightSetsCorsHeaders(): void
    {
        $filter = new SaGlobalFilter();
        $filter->setCors([
            'allowOrigin' => 'http://example.com',
            'allowMethods' => 'GET, POST, OPTIONS',
        ]);
        $filter->handlePreflight();
        $this->assertEquals('http://example.com', $this->responseTracker->headers['Access-Control-Allow-Origin']);
        $this->assertEquals('GET, POST, OPTIONS', $this->responseTracker->headers['Access-Control-Allow-Methods']);
        $this->assertEquals(204, $this->responseTracker->statusCode);
    }
}
