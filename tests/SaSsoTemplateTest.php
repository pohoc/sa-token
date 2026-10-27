<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Sso\SaSsoTemplate;

class SaSsoTemplateTest extends TestCase
{
    public function testUnknownCryptoTypeIsRejected(): void
    {
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $this->expectExceptionMessage('不支持的加密类型');

        new SaSsoTemplate('smm');
    }

    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig());
        SaToken::setDao(new SaTokenDaoMemory());
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testSignParamsWithIntlMode(): void
    {
        $template = new SaSsoTemplate('intl');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-key-placeholder-32-bytes-lo';

        $signed = $template->signParams($params, $clientSecret);

        $this->assertArrayHasKey('sign', $signed);
        $this->assertEquals(64, strlen($signed['sign']));
    }

    public function testSignParamsWithSmMode(): void
    {
        if (!class_exists(\CryptoSm\SM3\Sm3::class)) {
            $this->markTestSkipped('CryptoSm SM3 extension not available');
        }

        $template = new SaSsoTemplate('sm');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-sso-secret-with-at-least-32-bytes';

        $signed = $template->signParams($params, $clientSecret);

        $this->assertArrayHasKey('sign', $signed);
        $this->assertEquals(64, strlen($signed['sign']));
    }

    public function testVerifySignWithIntlMode(): void
    {
        $template = new SaSsoTemplate('intl');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-sso-secret-with-at-least-32-bytes';

        $signed = $template->signParams($params, $clientSecret);
        $result = $template->verifySign($signed, $clientSecret);

        $this->assertTrue($result);
    }

    public function testVerifySignWithSmMode(): void
    {
        if (!class_exists(\CryptoSm\SM3\Sm3::class)) {
            $this->markTestSkipped('CryptoSm SM3 extension not available');
        }

        $template = new SaSsoTemplate('sm');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-sso-secret-with-at-least-32-bytes';

        $signed = $template->signParams($params, $clientSecret);
        $result = $template->verifySign($signed, $clientSecret);

        $this->assertTrue($result);
    }

    public function testVerifySignWithTamperedDataReturnsFalse(): void
    {
        $template = new SaSsoTemplate('intl');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-sso-secret-with-at-least-32-bytes';

        $signed = $template->signParams($params, $clientSecret);
        $signed['appId'] = 'tampered-app';

        $result = $template->verifySign($signed, $clientSecret);

        $this->assertFalse($result);
    }

    public function testVerifySignRejectsUnsignedNonScalarParameters(): void
    {
        $template = new SaSsoTemplate('intl');
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-sso-secret-with-at-least-32-bytes';
        $signed = $template->signParams(['loginId' => 'user-1'], $clientSecret);
        $signed['extra'] = ['admin' => true];

        $this->assertFalse($template->verifySign($signed, $clientSecret));
    }

    public function testVerifySignRejectsTooManyParameters(): void
    {
        $template = new SaSsoTemplate('intl');
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-key-placeholder-32-bytes-lo';
        $signed = $template->signParams(['loginId' => 'user-1'], $clientSecret);
        for ($index = 0; $index < 128; $index++) {
            $signed['field' . $index] = 'x';
        }

        self::assertFalse($template->verifySign($signed, $clientSecret));
    }

    public function testVerifySignRejectsExcessiveTotalParameterBytes(): void
    {
        $template = new SaSsoTemplate('intl');
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-key-placeholder-32-bytes-lo';
        $signed = $template->signParams(['loginId' => 'user-1'], $clientSecret);
        $signed['payload'] = str_repeat('x', 65537);

        self::assertFalse($template->verifySign($signed, $clientSecret));
    }

    public function testSignParamsRejectsExcessiveTotalParameterBytes(): void
    {
        $template = new SaSsoTemplate('intl');
        $clientSecret = getenv('TEST_SSO_CLIENT_SECRET') ?: 'test-key-placeholder-32-bytes-lo';

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('总长度超过限制');
        $template->signParams(['payload' => str_repeat('x', 65537)], $clientSecret);
    }

    public function testHttpHelperRejectsNonHttpSchemes(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('Only HTTP and HTTPS URLs are allowed');
        (new SaSsoTemplate('intl'))->post('file://localhost/etc/passwd', ['ticket' => 'secret']);
    }

    public function testHttpHelperRejectsAmbiguousUrlsBeforeOpeningTransport(): void
    {
        $template = new class () extends SaSsoTemplate {
            protected function curlRequest(string $method, string $url, array $data = []): string|false
            {
                throw new \RuntimeException('Transport must not be opened for an invalid URL');
            }

            protected function fileGetContentsRequest(string $method, string $url, array $data = []): string|false
            {
                throw new \RuntimeException('Transport must not be opened for an invalid URL');
            }
        };

        foreach ([
            'https://user:password@example.test/check',
            'https://example.test/check#fragment',
            'https://example.test\\@attacker.test/check',
            "https://example.test/check\n",
        ] as $url) {
            try {
                $template->post($url, ['ticket' => 'secret']);
                self::fail('Ambiguous URL components must be rejected before transport');
            } catch (SaTokenException $exception) {
                self::assertStringContainsString('Only HTTP and HTTPS URLs are allowed', $exception->getMessage());
            }
        }
    }

    public function testHttpFailureExceptionRedactsCredentialsAndUrlPath(): void
    {
        try {
            (new SaSsoTemplate('intl'))->post(
                'http://user:password@127.0.0.1:1/check/sensitive-path-secret?ticket=secret&sign=signature#fragment',
                ['ticket' => 'secret']
            );
            self::fail('Unreachable local endpoint must fail');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('http://127.0.0.1:1', $exception->getMessage());
            self::assertStringNotContainsString('password', $exception->getMessage());
            self::assertStringNotContainsString('sensitive-path-secret', $exception->getMessage());
            self::assertStringNotContainsString('ticket=secret', $exception->getMessage());
            self::assertStringNotContainsString('signature', $exception->getMessage());
            self::assertStringNotContainsString('fragment', $exception->getMessage());
        }
    }

    public function testStreamFailureExceptionRedactsCredentialsAndUrlPath(): void
    {
        $template = new class () extends SaSsoTemplate {
            protected function doRequest(string $method, string $url, array $data = []): string|false
            {
                return $this->fileGetContentsRequest($method, $url, $data);
            }
        };

        try {
            $template->post(
                'http://user:password@127.0.0.1:1/check/sensitive-path-secret?ticket=secret&sign=signature#fragment',
                ['ticket' => 'secret']
            );
            self::fail('Unreachable local endpoint must fail');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('http://127.0.0.1:1', $exception->getMessage());
            self::assertStringNotContainsString('password', $exception->getMessage());
            self::assertStringNotContainsString('sensitive-path-secret', $exception->getMessage());
            self::assertStringNotContainsString('ticket=secret', $exception->getMessage());
            self::assertStringNotContainsString('signature', $exception->getMessage());
            self::assertStringNotContainsString('fragment', $exception->getMessage());
        }
    }

    public function testShortSecretCannotSignOrVerify(): void
    {
        $template = new SaSsoTemplate('intl');

        try {
            $template->signParams(['ticket' => 't'], 'weak');
            $this->fail('短 SSO 密钥不得生成 HMAC');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('至少需要 32 字节', $e->getMessage());
        }

        $this->assertFalse($template->verifySign(['sign' => str_repeat('0', 64)], 'weak'));
    }

    public function testCurlRequestRejectsOversizedResponse(): void
    {
        if (!function_exists('curl_init')) {
            self::markTestSkipped('Curl extension is not installed.');
        }

        $this->withOversizedResponse(function (string $url): void {
            try {
                (new SaSsoTemplate())->get($url);
                self::fail('Oversized cURL response must be rejected');
            } catch (SaTokenException $exception) {
                self::assertStringContainsString('1 MiB limit', $exception->getMessage());
            }
        });
    }

    public function testStreamRequestRejectsOversizedResponse(): void
    {
        $this->withOversizedResponse(function (string $url): void {
            $template = new class () extends SaSsoTemplate {
                public function requestWithStreams(string $url): string|false
                {
                    return $this->fileGetContentsRequest('GET', $url);
                }

                public function error(): ?string
                {
                    return $this->lastError;
                }
            };

            self::assertFalse($template->requestWithStreams($url));
            self::assertSame('SSO response exceeds the 1 MiB limit', $template->error());
        });
    }

    private function withOversizedResponse(callable $request): void
    {
        if (!function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl is required for the local HTTP response limit test.');
        }

        $server = @stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
        self::assertIsResource($server, "Unable to start local HTTP fixture: {$errorMessage} ({$errorCode})");
        $address = stream_socket_get_name($server, false);
        self::assertIsString($address);
        $port = (int) substr($address, strrpos($address, ':') + 1);

        $pid = pcntl_fork();
        if ($pid === -1) {
            fclose($server);
            self::fail('Unable to fork local HTTP fixture');
        }
        if ($pid === 0) {
            $client = @stream_socket_accept($server, 10);
            fclose($server);
            if ($client === false) {
                exit(2);
            }

            stream_set_timeout($client, 3);
            $requestHeaders = '';
            while (!str_contains($requestHeaders, "\r\n\r\n")) {
                $part = fread($client, 1024);
                if ($part === false || $part === '') {
                    break;
                }
                $requestHeaders .= $part;
            }
            fwrite($client, "HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\nConnection: close\r\n\r\n");
            $chunk = str_repeat('x', 8192);
            for ($i = 0; $i < 256; $i++) {
                if (@fwrite($client, $chunk) === false) {
                    break;
                }
            }
            fclose($client);
            exit(0);
        }

        fclose($server);
        $status = 0;
        try {
            $request("http://127.0.0.1:{$port}/oversized");
        } finally {
            pcntl_waitpid($pid, $status);
        }

        if (!is_int($status)) {
            throw new \RuntimeException('Local HTTP fixture returned an invalid process status');
        }
        self::assertTrue(pcntl_wifexited($status));
        self::assertSame(0, pcntl_wexitstatus($status));
    }
}
