<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SaToken\Auth\SaApiKey;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

class SaApiKeyTest extends TestCase
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
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        SaToken::setDao(new SaTokenDaoMemory());
        SaTokenContext::setContextId('default');
        SaTokenContext::clear();
    }

    protected function tearDown(): void
    {
        SaTokenContext::setContextId('default');
        SaTokenContext::clear();
        SaToken::reset();
    }

    protected function mockRequestWithHeaders(array $headers): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($headers): array {
            return isset($headers[$name]) ? [$headers[$name]] : [];
        });
        return $request;
    }

    public function testIsApiKeyRequestReturnsTrueWhenHeadersPresent(): void
    {
        $request = $this->mockRequestWithHeaders([
            'api-key' => 'my-key',
            'api-secret' => 'my-secret',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey();
        $this->assertTrue($api->isApiKeyRequest());
    }

    public function testIsApiKeyRequestReturnsFalseWhenHeadersMissing(): void
    {
        $api = new SaApiKey();
        $this->assertFalse($api->isApiKeyRequest());
    }

    public function testRegisterKeyAndValidate(): void
    {
        $request = $this->mockRequestWithHeaders([
            'api-key' => 'my-key',
            'api-secret' => 'my-secret',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey();
        $api->registerKey('my-key', 'my-secret', 10001);
        $api->checkApiKey();

        $this->assertTrue(SaToken::getDao()->exists('satoken:login:loginId:login:10001'));
    }

    public function testCheckApiKeyThrowsOnMissingHeaders(): void
    {
        $api = new SaApiKey();
        $this->expectException(SaTokenException::class);
        $api->checkApiKey();
    }

    public function testCheckApiKeyThrowsOnInvalidSecret(): void
    {
        $request = $this->mockRequestWithHeaders([
            'api-key' => 'my-key',
            'api-secret' => 'wrong-secret',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey();
        $api->registerKey('my-key', 'my-secret', 10001);
        $this->expectException(SaTokenException::class);
        $api->checkApiKey();
    }

    public function testCheckApiKeyWithCustomValidator(): void
    {
        $request = $this->mockRequestWithHeaders([
            'api-key' => 'my-key',
            'api-secret' => 'my-secret',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey();
        $api->setValidator(function (string $apiKey, string $apiSecret): mixed {
            if ($apiKey === 'my-key' && $apiSecret === 'my-secret') {
                return 20001;
            }
            return null;
        });
        $api->checkApiKey();

        $this->assertTrue(SaToken::getDao()->exists('satoken:login:loginId:login:20001'));
    }

    public function testCustomHeaderNames(): void
    {
        $request = $this->mockRequestWithHeaders([
            'x-api-key' => 'my-key',
            'x-api-secret' => 'my-secret',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey(['headerName' => 'x-api-key', 'secretHeaderName' => 'x-api-secret']);
        $this->assertTrue($api->isApiKeyRequest());
    }
}
