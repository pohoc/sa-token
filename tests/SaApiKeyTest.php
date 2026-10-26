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
use SaToken\Security\SaAntiBruteUtil;
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

    /**
     * @param array<string, string> $headers
     */
    protected function mockRequestWithHeaders(array $headers): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($headers): array {
            return isset($headers[$name]) ? [$headers[$name]] : [];
        });
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.101']);
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

    public function testDuplicateCredentialHeadersAreRejected(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => match ($name) {
            'api-key' => ['first-key', 'second-key'],
            'api-secret' => ['secret'],
            default => [],
        });
        SaTokenContext::setRequest($request);

        $api = new SaApiKey();
        $this->assertFalse($api->isApiKeyRequest());
        $this->expectException(SaTokenException::class);
        $api->checkApiKey();
    }

    public function testProxyCombinedCredentialHeadersAreRejected(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'first-key, second-key',
            'api-secret' => 'first-secret, second-secret',
        ]));

        $validatorCalls = 0;
        $api = (new SaApiKey())->setValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return 'api-user';
        });

        self::assertFalse($api->isApiKeyRequest());
        try {
            $api->checkApiKey();
            self::fail('合并的 Key/Secret Header 必须被拒绝');
        } catch (SaTokenException $exception) {
            self::assertSame('API Key 或 Secret Header 存在多个值', $exception->getMessage());
        }
        self::assertSame(0, $validatorCalls);
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

        $this->assertTrue(SaToken::getDao()->exists(\SaToken\TokenManager::buildLoginIdKey('login', '10001')));
    }

    public function testApiKeyIdentityOverridesAnUnrelatedBearerTokenForCurrentRequest(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $logic = SaToken::getStpLogic();
        $unrelatedToken = $logic->login('bearer-account')->getAccessToken();
        $api = new SaApiKey();
        $api->registerKey('service-key', 'service-secret', 'api-key-account');

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'satoken' => $unrelatedToken,
            'api-key' => 'service-key',
            'api-secret' => 'service-secret',
        ]));

        $api->checkApiKey();

        self::assertSame('api-key-account', $logic->getLoginId());
        self::assertSame('bearer-account', $logic->getLoginIdByToken($unrelatedToken));

        // The next request reuses the API Key session, but still must not let
        // an unrelated incoming bearer override the validated API Key identity.
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'satoken' => $unrelatedToken,
            'api-key' => 'service-key',
            'api-secret' => 'service-secret',
        ]));
        $api->checkApiKey();
        self::assertSame('api-key-account', $logic->getLoginId());
    }

    public function testApiKeySessionReuseDoesNotEmitBearerWhenResponseWritingIsDisabled(): void
    {
        $api = new SaApiKey();
        $api->registerKey('response-policy-key', 'response-policy-secret', 'api-key-account');

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'response-policy-key',
            'api-secret' => 'response-policy-secret',
        ]));
        $api->checkApiKey();

        $pendingHeaders = new \ReflectionProperty(SaTokenContext::class, 'pendingHeadersMap');
        $headersByContext = $pendingHeaders->getValue();
        self::assertIsArray($headersByContext);
        $contextHeaders = $headersByContext[SaTokenContext::getContextId()] ?? [];
        self::assertIsArray($contextHeaders);
        self::assertSame([], $contextHeaders);

        // Reuse must obey the same response policy as the initial login. In
        // particular, an API-Key-only client must not receive a bearer token
        // that can be used on routes which accept Sa-Token credentials.
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'response-policy-key',
            'api-secret' => 'response-policy-secret',
        ]));
        $api->checkApiKey();

        $headersByContext = $pendingHeaders->getValue();
        self::assertIsArray($headersByContext);
        $contextHeaders = $headersByContext[SaTokenContext::getContextId()] ?? [];
        self::assertIsArray($contextHeaders);
        self::assertSame([], $contextHeaders);

        SaToken::getConfig()->setIsWriteHeader(true);
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'response-policy-key',
            'api-secret' => 'response-policy-secret',
        ]));
        $api->checkApiKey();
        $headersByContext = $pendingHeaders->getValue();
        self::assertIsArray($headersByContext);
        $contextHeaders = $headersByContext[SaTokenContext::getContextId()] ?? [];
        self::assertIsArray($contextHeaders);
        self::assertSame(
            ['name' => 'satoken', 'value' => self::readReusableToken('api-key-account')],
            $contextHeaders[0] ?? null
        );
    }

    private static function readReusableToken(string $loginId): string
    {
        $tokens = SaToken::getStpLogic()->getTokenManager()->getTokenListByLoginId($loginId, 'login');
        $token = $tokens[0]['tokenValue'] ?? null;
        self::assertIsString($token);
        return $token;
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

    public function testValidatorExceptionCountsAsFailedApiKeyAttemptAndIsRethrown(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'throwing-key',
            'api-secret' => 'wrong-secret',
        ]));
        $api = (new SaApiKey())->setValidator(static function (): never {
            throw new SaTokenException('credential rejected');
        });

        try {
            $api->checkApiKey();
            self::fail('validator rejection must not authenticate');
        } catch (SaTokenException $exception) {
            self::assertSame('credential rejected', $exception->getMessage());
        }

        self::assertSame(1, SaAntiBruteUtil::getFailCount('throwing-key', 'api-key'));
    }

    public function testInvalidSecretAttemptsAreRateLimitedByApiKeyAndSource(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setAntiBruteMaxFailures(2)->setAntiBruteLockDuration(60));
        $api = new SaApiKey();
        $api->registerKey('known-api-key', 'correct-secret', 10001);

        foreach ([1, 2] as $attempt) {
            SaTokenContext::setRequest($this->mockRequestWithHeaders([
                'api-key' => 'known-api-key',
                'api-secret' => 'wrong-secret-' . $attempt,
            ]));
            try {
                $api->checkApiKey();
                $this->fail('错误 API Secret 应被拒绝');
            } catch (SaTokenException $e) {
                $this->assertSame('API Key 验证失败', $e->getMessage());
            }
        }

        $this->assertSame(2, SaAntiBruteUtil::getFailCount('known-api-key', 'api-key'));
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'known-api-key',
            'api-secret' => 'correct-secret',
        ]));

        $this->expectExceptionMessage('账号已被锁定');
        $api->checkApiKey();
    }

    public function testSuccessfulApiKeyValidationClearsCurrentSourceFailures(): void
    {
        $api = new SaApiKey();
        $api->registerKey('known-api-key', 'correct-secret', 10001);

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'known-api-key',
            'api-secret' => 'wrong-secret',
        ]));
        try {
            $api->checkApiKey();
            $this->fail('错误 API Secret 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertSame('API Key 验证失败', $e->getMessage());
        }

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'known-api-key',
            'api-secret' => 'correct-secret',
        ]));
        $api->checkApiKey();

        $this->assertSame(0, SaAntiBruteUtil::getFailCount('known-api-key', 'api-key'));
    }

    public function testCheckApiKeyRejectsEmptySecretBeforeCallingValidator(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'my-key',
            'api-secret' => '',
        ]));

        $api = new SaApiKey();
        $api->setValidator(static function (): int {
            self::fail('空凭据不应传递给自定义校验器');
        });

        $this->expectException(SaTokenException::class);
        $api->checkApiKey();
    }

    public function testRegisterKeyRejectsEmptyCredentials(): void
    {
        $api = new SaApiKey();

        $this->expectException(SaTokenException::class);
        $api->registerKey('my-key', '   ', 10001);
    }

    public function testSetKeyRegistryRejectsEmptySecret(): void
    {
        $api = new SaApiKey();

        $this->expectException(SaTokenException::class);
        $api->setKeyRegistry(['my-key' => ['secret' => '', 'loginId' => 10001]]);
    }

    public function testSetKeyRegistryAcceptsNumericApiKey(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => '123',
            'api-secret' => 'numeric-key-secret',
        ]));

        $api = new SaApiKey();
        $api->setKeyRegistry(['123' => ['secret' => 'numeric-key-secret', 'loginId' => 10001]]);
        $api->checkApiKey();

        $this->assertTrue(SaToken::getDao()->exists(\SaToken\TokenManager::buildLoginIdKey('login', '10001')));
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

        $this->assertTrue(SaToken::getDao()->exists(\SaToken\TokenManager::buildLoginIdKey('login', '20001')));
    }

    public function testExpiredActivityTokenIsReplacedDuringApiKeyAuthentication(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setActivityTimeout(60));
        $api = new SaApiKey();
        $api->registerKey('activity-key', 'activity-secret', 10001);

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'activity-key',
            'api-secret' => 'activity-secret',
        ]));
        $api->checkApiKey();

        $logic = SaToken::getStpLogic();
        $tokens = $logic->getTokenManager()->getTokenListByLoginId(10001, 'login');
        $oldToken = $tokens[0]['tokenValue'];
        self::assertIsString($oldToken);
        self::assertSame('10001', $logic->getLoginIdByToken($oldToken));

        SaToken::getDao()->delete(\SaToken\TokenManager::LAST_ACTIVE_PREFIX . $oldToken);
        self::assertNull($logic->getLoginIdByToken($oldToken));

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'activity-key',
            'api-secret' => 'activity-secret',
        ]));
        $api->checkApiKey();

        $tokens = $logic->getTokenManager()->getTokenListByLoginId(10001, 'login');
        $newToken = $tokens[0]['tokenValue'];
        self::assertIsString($newToken);
        self::assertNotSame($oldToken, $newToken);
        self::assertSame('10001', $logic->getLoginIdByToken($newToken));
    }

    public function testCheckApiKeyTreatsFalseValidatorResultAsFailure(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'invalid-key',
            'api-secret' => 'invalid-secret',
        ]));
        $api = new SaApiKey();
        $api->setValidator(static fn (): bool => false);

        $this->expectException(SaTokenException::class);
        $api->checkApiKey();
    }

    public function testCheckApiKeyDoesNotTreatTrueAsLoginId(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'key',
            'api-secret' => 'secret',
        ]));
        $api = new SaApiKey();
        $api->setValidator(static fn (): bool => true);

        $this->expectException(SaTokenException::class);
        $api->checkApiKey();
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
