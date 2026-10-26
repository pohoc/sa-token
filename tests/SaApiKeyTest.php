<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SaToken\Auth\SaApiKey;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\DisableServiceException;
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
            'api-secret' => 'my-api-secret-value-at-least-32-bytes',
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

    public function testSetConfigRotatesSingletonApiKeyHeadersAndPreservesValidator(): void
    {
        $validatorCalls = 0;
        $api = SaToken::getApiKey()->setValidator(static function (string $key, string $secret) use (&$validatorCalls): string {
            $validatorCalls++;
            return $key === 'configured-key' && $secret === 'configured-api-secret-value-at-least-32-bytes'
                ? 'configured-api-user'
                : '';
        });

        SaToken::setConfig(new SaTokenConfig([
            'apiKeyHeader' => 'x-api-key-v2',
            'apiSecretHeader' => 'x-api-secret-v2',
        ]));

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'configured-key',
            'api-secret' => 'configured-api-secret-value-at-least-32-bytes',
        ]));
        $this->assertFalse($api->isApiKeyRequest());

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'x-api-key-v2' => 'configured-key',
            'x-api-secret-v2' => 'configured-api-secret-value-at-least-32-bytes',
        ]));
        $api->checkApiKey();

        $this->assertSame(1, $validatorCalls);
        $this->assertSame('configured-api-user', SaToken::getStpLogic()->getLoginId());
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
            'api-secret' => 'my-api-secret-value-at-least-32-bytes',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey();
        $api->registerKey('my-key', 'my-api-secret-value-at-least-32-bytes', 10001);
        $api->checkApiKey();

        $this->assertTrue(SaToken::getDao()->exists(\SaToken\TokenManager::buildLoginIdKey('login', '10001')));
    }

    public function testApiKeyIdentityOverridesAnUnrelatedBearerTokenForCurrentRequest(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $logic = SaToken::getStpLogic();
        $unrelatedToken = $logic->login('bearer-account')->getAccessToken();
        $api = new SaApiKey();
        $api->registerKey('service-key', 'service-api-secret-value-at-least-32-bytes', 'api-key-account');

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'satoken' => $unrelatedToken,
            'api-key' => 'service-key',
            'api-secret' => 'service-api-secret-value-at-least-32-bytes',
        ]));

        $api->checkApiKey();

        self::assertSame('api-key-account', $logic->getLoginId());
        self::assertSame('bearer-account', $logic->getLoginIdByToken($unrelatedToken));

        // The next request reuses the API Key session, but still must not let
        // an unrelated incoming bearer override the validated API Key identity.
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'satoken' => $unrelatedToken,
            'api-key' => 'service-key',
            'api-secret' => 'service-api-secret-value-at-least-32-bytes',
        ]));
        $api->checkApiKey();
        self::assertSame('api-key-account', $logic->getLoginId());
    }

    public function testDisabledAccountCannotReuseAnApiKeySession(): void
    {
        $logic = SaToken::getStpLogic();
        $api = new SaApiKey();
        $api->registerKey('disabled-api-key', 'disabled-api-secret-value-at-least-32-bytes', 'disabled-api-user');
        $headers = [
            'api-key' => 'disabled-api-key',
            'api-secret' => 'disabled-api-secret-value-at-least-32-bytes',
        ];

        SaTokenContext::setRequest($this->mockRequestWithHeaders($headers));
        $api->checkApiKey();
        $logic->disable('disabled-api-user', 'login', 1, 3600);

        SaTokenContext::setRequest($this->mockRequestWithHeaders($headers));
        try {
            $api->checkApiKey();
            self::fail('封禁账号不能通过复用的 API Key 会话继续认证');
        } catch (DisableServiceException) {
            self::assertTrue($logic->isDisable('disabled-api-user', 'login'));
        }
    }

    public function testApiKeyReuseCannotWinAfterDisableTakesOverTheAccountLock(): void
    {
        $loginId = 'api-key-disable-lock-race';
        $tokenManager = new class () extends \SaToken\TokenManager {
            public ?\Closure $afterTokenListRead = null;

            public function getTokenListByLoginId(mixed $loginId, string $loginType): array
            {
                $tokens = parent::getTokenListByLoginId($loginId, $loginType);
                if ($this->afterTokenListRead !== null) {
                    $callback = $this->afterTokenListRead;
                    $this->afterTokenListRead = null;
                    $callback($loginId);
                }

                return $tokens;
            }
        };
        $logic = SaToken::getStpLogic();
        $logic->setTokenManager($tokenManager);
        $api = new SaApiKey();
        $api->registerKey('race-api-key', 'race-api-secret-value-at-least-32-bytes', $loginId);
        $headers = [
            'api-key' => 'race-api-key',
            'api-secret' => 'race-api-secret-value-at-least-32-bytes',
        ];

        SaTokenContext::setRequest($this->mockRequestWithHeaders($headers));
        $api->checkApiKey();
        SaTokenContext::setTokenOverride('login', null);
        $tokenManager->afterTokenListRead = function () use ($loginId): void {
            SaToken::getDao()->delete(
                \SaToken\TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', $loginId)
            );
            SaTokenContext::setContextId('disable-admin');
            try {
                SaToken::getStpLogic()->disable($loginId, 'login', 1, 3600);
            } finally {
                SaTokenContext::setContextId('default');
            }
        };
        SaTokenContext::setRequest($this->mockRequestWithHeaders($headers));

        try {
            $api->checkApiKey();
            self::fail('账号封禁完成后，缓存 API Key 会话不能继续认证');
        } catch (DisableServiceException) {
            self::assertTrue($logic->isDisable($loginId, 'login'));
        }

        self::assertNull($logic->getLoginId());
    }

    public function testInvalidApiKeyCannotFallBackToAnUnrelatedBearerToken(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $logic = SaToken::getStpLogic();
        $bearerToken = $logic->login('bearer-account')->getAccessToken();
        $api = new SaApiKey();
        $api->registerKey('service-key', 'service-api-secret-value-at-least-32-bytes', 'api-key-account');
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'satoken' => $bearerToken,
            'api-key' => 'service-key',
            'api-secret' => 'wrong-api-secret-value-at-least-32-bytes',
        ]));

        try {
            $api->checkApiKey();
            self::fail('无效 API Key 必须拒绝认证');
        } catch (SaTokenException) {
            self::assertNull($logic->getLoginId(), 'API Key 认证失败后不得回退到请求携带的 bearer token');
        }
    }

    public function testApiKeySessionReuseDoesNotEmitBearerWhenResponseWritingIsDisabled(): void
    {
        $api = new SaApiKey();
        $api->registerKey('response-policy-key', 'response-policy-api-secret-at-least-32-bytes', 'api-key-account');

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'response-policy-key',
            'api-secret' => 'response-policy-api-secret-at-least-32-bytes',
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
            'api-secret' => 'response-policy-api-secret-at-least-32-bytes',
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
            'api-secret' => 'response-policy-api-secret-at-least-32-bytes',
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
            'api-secret' => 'wrong-api-secret-value-at-least-32-bytes',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey();
        $api->registerKey('my-key', 'my-api-secret-value-at-least-32-bytes', 10001);
        $this->expectException(SaTokenException::class);
        $api->checkApiKey();
    }

    public function testValidatorExceptionCountsAsFailedApiKeyAttemptAndIsRethrown(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'throwing-key',
            'api-secret' => 'wrong-api-secret-value-at-least-32-bytes',
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
        $api->registerKey('known-api-key', 'correct-api-secret-value-at-least-32-bytes', 10001);

        foreach ([1, 2] as $attempt) {
            SaTokenContext::setRequest($this->mockRequestWithHeaders([
                'api-key' => 'known-api-key',
                'api-secret' => 'wrong-api-secret-value-at-least-32-bytes-' . $attempt,
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
            'api-secret' => 'correct-api-secret-value-at-least-32-bytes',
        ]));

        $this->expectExceptionMessage('账号已被锁定');
        $api->checkApiKey();
    }

    public function testSuccessfulApiKeyValidationClearsCurrentSourceFailures(): void
    {
        $api = new SaApiKey();
        $api->registerKey('known-api-key', 'correct-api-secret-value-at-least-32-bytes', 10001);

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'known-api-key',
            'api-secret' => 'wrong-api-secret-value-at-least-32-bytes',
        ]));
        try {
            $api->checkApiKey();
            $this->fail('错误 API Secret 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertSame('API Key 验证失败', $e->getMessage());
        }

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'known-api-key',
            'api-secret' => 'correct-api-secret-value-at-least-32-bytes',
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

    public function testCheckApiKeyRejectsShortSecretBeforeCallingCustomValidator(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'my-key',
            'api-secret' => 'short-secret',
        ]));

        $api = new SaApiKey();
        $api->setValidator(static function (): never {
            self::fail('短 Secret 不得传递给自定义校验器');
        });

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('至少需要 32 字节');
        $api->checkApiKey();
    }

    public function testRegisterKeyRejectsEmptyCredentials(): void
    {
        $api = new SaApiKey();

        $this->expectException(SaTokenException::class);
        $api->registerKey('my-key', '   ', 10001);
    }

    public function testRegisterKeyRejectsShortSecret(): void
    {
        $api = new SaApiKey();

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('至少需要 32 字节');
        $api->registerKey('my-key', 'short-secret', 10001);
    }

    public function testSetKeyRegistryRejectsEmptySecret(): void
    {
        $api = new SaApiKey();

        $this->expectException(SaTokenException::class);
        $api->setKeyRegistry(['my-key' => ['secret' => '', 'loginId' => 10001]]);
    }

    public function testSetKeyRegistryRejectsShortSecret(): void
    {
        $api = new SaApiKey();

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('至少需要 32 字节');
        $api->setKeyRegistry(['my-key' => ['secret' => 'short-secret', 'loginId' => 10001]]);
    }

    public function testSetKeyRegistryAcceptsNumericApiKey(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => '123',
            'api-secret' => 'numeric-api-secret-value-at-least-32-bytes',
        ]));

        $api = new SaApiKey();
        $api->setKeyRegistry(['123' => ['secret' => 'numeric-api-secret-value-at-least-32-bytes', 'loginId' => 10001]]);
        $api->checkApiKey();

        $this->assertTrue(SaToken::getDao()->exists(\SaToken\TokenManager::buildLoginIdKey('login', '10001')));
    }

    public function testCheckApiKeyWithCustomValidator(): void
    {
        $request = $this->mockRequestWithHeaders([
            'api-key' => 'my-key',
            'api-secret' => 'my-api-secret-value-at-least-32-bytes',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey();
        $api->setValidator(function (string $apiKey, string $apiSecret): mixed {
            if ($apiKey === 'my-key' && $apiSecret === 'my-api-secret-value-at-least-32-bytes') {
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
        $api->registerKey('activity-key', 'activity-api-secret-value-at-least-32-bytes', 10001);

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'activity-key',
            'api-secret' => 'activity-api-secret-value-at-least-32-bytes',
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
            'api-secret' => 'activity-api-secret-value-at-least-32-bytes',
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
            'api-secret' => 'invalid-api-secret-value-at-least-32-bytes',
        ]));
        $api = new SaApiKey();
        $api->setValidator(static fn (): bool => false);

        $this->expectException(SaTokenException::class);
        $api->checkApiKey();
    }

    public function testFailedApiKeyAuthenticationBlocksBearerFallbackAcrossLoginTypes(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $adminLogic = SaToken::getStpLogic('admin');
        $adminToken = $adminLogic->login('admin-api-bearer')->getAccessToken();
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'invalid-api-key',
            'api-secret' => 'invalid-api-secret-value-at-least-32-bytes',
            'satoken' => $adminToken,
        ]));

        try {
            (new SaApiKey())->setValidator(static fn (): ?string => null)->checkApiKey();
            self::fail('无效 API Key 必须拒绝认证');
        } catch (SaTokenException) {
            self::assertNull($adminLogic->getLoginId(), '认证失败后任何 loginType 都不得回退到原生 bearer token');
        }
    }

    public function testCheckApiKeyDoesNotTreatTrueAsLoginId(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'api-key' => 'key',
            'api-secret' => 'api-secret-value-at-least-32-bytes',
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
            'x-api-secret' => 'my-api-secret-value-at-least-32-bytes',
        ]);
        SaTokenContext::setRequest($request);

        $api = new SaApiKey(['headerName' => 'x-api-key', 'secretHeaderName' => 'x-api-secret']);
        $this->assertTrue($api->isApiKeyRequest());
    }
}
