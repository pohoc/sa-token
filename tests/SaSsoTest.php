<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Sso\Mode\SsoModeCrossDomain;
use SaToken\Sso\Mode\SsoModeNoSdk;
use SaToken\Sso\Mode\SsoModeSameDomain;
use SaToken\Sso\SaSsoConfig;
use SaToken\Sso\SaSsoHandle;
use SaToken\Sso\SaSsoManager;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaSsoNoSdkTestHandle extends SaSsoHandle
{
    protected function checkTicket(string $ticket): ?string
    {
        return $ticket === 'valid-ticket' ? 'no-sdk-user' : null;
    }
}

/**
 * SSO 模块测试
 *
 * 覆盖：URL 构建、配置、SaSsoManager 入口、ticket 校验逻辑
 */
class SaSsoTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        SaToken::setDao(new SaTokenDaoMemory());
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    // ======== SaSsoConfig 测试 ========

    public function testSsoConfigDefaults(): void
    {
        $config = new SaSsoConfig();
        $this->assertEquals('', $config->getLoginUrl());
        $this->assertEquals('', $config->getAuthUrl());
        $this->assertEquals('', $config->getBackUrl());
        $this->assertEquals('', $config->getCheckTicketUrl());
        $this->assertEquals('', $config->getSloUrl());
        $this->assertEquals('same-domain', $config->getMode());
        $this->assertEquals('', $config->getClientId());
        $this->assertEquals('', $config->getClientSecret());
    }

    public function testSsoConfigFromArray(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'       => 'https://auth.example.com/login',
            'authUrl'        => 'https://auth.example.com/auth',
            'backUrl'        => 'https://app.example.com/sso/callback',
            'checkTicketUrl' => 'https://auth.example.com/checkTicket',
            'sloUrl'         => 'https://auth.example.com/slo',
            'mode'           => 'cross-domain',
            'clientId'       => 'app-1',
            'clientSecret'   => 'sso-test-secret-with-at-least-32-bytes',
        ]);

        $this->assertEquals('https://auth.example.com/login', $config->getLoginUrl());
        $this->assertEquals('https://auth.example.com/auth', $config->getAuthUrl());
        $this->assertEquals('https://app.example.com/sso/callback', $config->getBackUrl());
        $this->assertEquals('https://auth.example.com/checkTicket', $config->getCheckTicketUrl());
        $this->assertEquals('https://auth.example.com/slo', $config->getSloUrl());
        $this->assertEquals('cross-domain', $config->getMode());
        $this->assertEquals('app-1', $config->getClientId());
        $this->assertEquals('sso-test-secret-with-at-least-32-bytes', $config->getClientSecret());
    }

    // ======== buildLoginUrl 测试 ========

    public function testBuildLoginUrlWithRedirect(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildLoginUrl('https://app.example.com/dashboard');

        $this->assertStringContainsString('https://auth.example.com/login', $url);
        $this->assertStringContainsString('redirect=', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testShortSsoClientSecretIsRejected(): void
    {
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $this->expectExceptionMessage('SSO 客户端密钥长度不足');

        new SaSsoConfig(['clientSecret' => 'secret-1']);
    }

    public function testSsoTransientCookiesUseLaxForCrossSiteCallback(): void
    {
        SaTokenContext::clear();
        $handle = new SaSsoHandle(new SaSsoConfig([
            'loginUrl' => 'https://auth.example.com/login',
            'allowDomains' => ['app.example.com'],
            'clientSecret' => 'sso-cookie-test-secret-with-at-least-32-bytes',
        ]));
        $handle->buildLoginUrl('https://app.example.com/callback', 'https://app.example.com/page');

        $pendingCookies = new \ReflectionProperty(SaTokenContext::class, 'pendingCookiesMap');
        $cookiesByContext = $pendingCookies->getValue();
        self::assertIsArray($cookiesByContext);
        $cookies = $cookiesByContext[SaTokenContext::getContextId()] ?? [];
        self::assertIsArray($cookies);

        $this->assertCount(3, $cookies);
        foreach ($cookies as $cookie) {
            self::assertIsArray($cookie);
            $this->assertSame('Lax', $cookie['sameSite'] ?? null);
            $this->assertTrue(($cookie['secure'] ?? null) === true);
            $this->assertTrue(($cookie['httpOnly'] ?? null) === true);
        }
        SaTokenContext::clear();
    }

    public function testSsoStateCookieCannotBeInjectedBySiblingSubdomain(): void
    {
        SaTokenContext::clear();
        SaToken::setConfig(new SaTokenConfig([
            'cookieDomain' => '.example.com',
            'cookiePath' => '/app',
            'cookieSecure' => false,
            'cookieHttpOnly' => false,
        ]));
        $handle = new SaSsoHandle(new SaSsoConfig([
            'loginUrl' => 'https://auth.example.com/login',
            'allowDomains' => ['app.example.com'],
        ]));
        $handle->buildLoginUrl('https://app.example.com/callback');

        $pendingCookies = new \ReflectionProperty(SaTokenContext::class, 'pendingCookiesMap');
        $cookiesByContext = $pendingCookies->getValue();
        self::assertIsArray($cookiesByContext);
        $cookies = $cookiesByContext[SaTokenContext::getContextId()] ?? [];
        self::assertIsArray($cookies);
        $stateCookie = null;
        foreach ($cookies as $cookie) {
            if (is_array($cookie) && is_string($cookie['name'] ?? null) && str_ends_with($cookie['name'], '_state')) {
                $stateCookie = $cookie;
                break;
            }
        }

        $this->assertIsArray($stateCookie);
        $this->assertSame('__Host-sso_params_state', $stateCookie['name'] ?? null);
        $this->assertSame('', $stateCookie['domain']);
        $this->assertSame('/', $stateCookie['path']);
        $this->assertTrue($stateCookie['secure']);
        $this->assertTrue($stateCookie['httpOnly']);
        SaTokenContext::clear();
    }

    public function testPreLoginRedirectCookieRequiresValidHmac(): void
    {
        SaTokenContext::setRequest(new class () {
            public function cookie(string $name): ?string
            {
                return match ($name) {
                    'sso_params' => base64_encode('https://attacker.example.com/collect'),
                    default => null,
                };
            }
        });

        $handle = new SaSsoHandle(new SaSsoConfig([
            'allowDomains' => ['*.example.com'],
        ]));

        self::assertSame('', $handle->restorePreLoginUrl());
    }

    public function testPreLoginRedirectUsesGlobalSigningKeyWhenSsoSecretIsAbsent(): void
    {
        SaTokenContext::clear();
        SaToken::setConfig(new SaTokenConfig(['signKey' => 'global-signing-key-at-least-32-bytes']));
        $handle = new SaSsoHandle(new SaSsoConfig([
            'allowDomains' => ['app.example.com'],
        ]));

        $handle->savePreLoginUrl('https://app.example.com/profile');

        $pendingCookies = new \ReflectionProperty(SaTokenContext::class, 'pendingCookiesMap');
        $cookiesByContext = $pendingCookies->getValue();
        self::assertIsArray($cookiesByContext);
        $cookies = $cookiesByContext[SaTokenContext::getContextId()] ?? [];
        self::assertIsArray($cookies);
        $signatures = array_values(array_filter(
            $cookies,
            static fn (mixed $cookie): bool =>
            is_array($cookie) && ($cookie['name'] ?? null) === 'sso_params_sig'
        ));
        self::assertCount(1, $signatures);
        self::assertSame(hash_hmac('sha256', base64_encode('https://app.example.com/profile'), 'global-signing-key-at-least-32-bytes'), $signatures[0]['value']);
        SaTokenContext::clear();
    }

    public function testPreLoginRedirectIsNotPersistedWhenAvailableKeysAreWeak(): void
    {
        SaTokenContext::clear();
        SaToken::setConfig(new SaTokenConfig([
            'hmacKey' => 'also-weak',
        ]));
        $handle = new SaSsoHandle(new SaSsoConfig([
            'allowDomains' => ['app.example.com'],
        ]));

        $handle->savePreLoginUrl('https://app.example.com/profile');

        $pendingCookies = new \ReflectionProperty(SaTokenContext::class, 'pendingCookiesMap');
        $cookiesByContext = $pendingCookies->getValue();
        self::assertIsArray($cookiesByContext);
        $cookies = $cookiesByContext[SaTokenContext::getContextId()] ?? [];
        self::assertIsArray($cookies);
        self::assertCount(2, $cookies);
        foreach ($cookies as $cookie) {
            self::assertIsArray($cookie);
            self::assertSame('', $cookie['value'] ?? null);
        }
        SaTokenContext::clear();
    }

    public function testCrossDomainCallbackWithRedirectPassesState(): void
    {
        SaTokenContext::setRequest(new class () {
            public function cookie(string $name): ?string
            {
                return $name === '__Host-sso_params_state' ? 'expected-state' : null;
            }
        });

        $mode = new SsoModeCrossDomain(new SaSsoConfig());
        try {
            $mode->doLoginCallbackWithRedirect('ticket', 'expected-state');
            $this->fail('缺少 ticket 校验地址时必须失败');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('ticket 校验地址未配置', $e->getMessage());
        }
    }

    public function testNoSdkLoginByTicketPassesStateToCallbackValidation(): void
    {
        $state = 'no-sdk-state';
        SaTokenContext::setRequest(new class ($state) {
            public function __construct(private string $state)
            {
            }

            public function cookie(string $name): ?string
            {
                return $name === '__Host-sso_params_state' ? $this->state : null;
            }
        });

        $mode = new SsoModeNoSdk(new SaSsoNoSdkTestHandle(new SaSsoConfig()));
        $result = $mode->doLoginByTicket('valid-ticket', $state);

        self::assertSame('no-sdk-user', $result['loginId']);
        self::assertSame('', $result['redirect']);
    }

    public function testSsoStateCanOnlyBeConsumedOnceAcrossCallbackRequests(): void
    {
        $state = 'one-time-state';
        SaTokenContext::setRequest(new class ($state) {
            public function __construct(private string $state)
            {
            }

            public function cookie(string $name): ?string
            {
                return $name === '__Host-sso_params_state' ? $this->state : null;
            }
        });

        $handle = new SaSsoHandle(new SaSsoConfig());
        $handle->validateCallbackRequest(null, $state);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('state 已使用');
        $handle->validateCallbackRequest(null, $state);
    }

    public function testSameDomainSsoEnforcesTokenFingerprint(): void
    {
        SaToken::setConfig((new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'tokenFingerprint' => true,
            'signKey'         => 'sso-csrf-test-secret-32-bytes-long',
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ])));
        SaTokenContext::setRequest(new class () {
            public function getHeaderLine(string $name): string
            {
                return strtolower($name) === 'user-agent' ? 'original-browser' : '';
            }
        });

        $token = StpUtil::login('sso-user')->getAccessToken();
        $csrf = SsoModeSameDomain::buildCsrfValue($token);
        SaTokenContext::setRequest(new class ($token, $csrf) {
            public function __construct(private string $token, private string $csrf)
            {
            }

            public function getHeaderLine(string $name): string
            {
                return match (strtolower($name)) {
                    'user-agent' => 'different-browser',
                    'x-csrf-token' => $this->csrf,
                    default => '',
                };
            }

            public function cookie(string $name): ?string
            {
                return $name === 'satoken' ? $this->token : null;
            }
        });

        $mode = new SsoModeSameDomain(new SaSsoConfig());
        try {
            $mode->doLogin();
            $this->fail('同域 SSO 不得绕过 Token 指纹校验');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无效或已过期', $e->getMessage());
        }
    }

    public function testSameDomainSsoDoesNotSkipCsrfForAnAlreadyAuthenticatedCookie(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'signKey'         => 'sso-csrf-test-secret-32-bytes-long',
            'isReadHeader'    => false,
            'isReadCookie'    => true,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));

        $token = StpUtil::login('cookie-user')->getAccessToken();
        SaTokenContext::setRequest(new class ($token) {
            public function __construct(private string $token)
            {
            }

            public function cookie(string $name): ?string
            {
                return $name === 'satoken' ? $this->token : null;
            }

            public function getHeaderLine(string $name): string
            {
                return '';
            }
        });

        $mode = new SsoModeSameDomain(new SaSsoConfig());
        try {
            $mode->doLogin();
            $this->fail('有效共享 Cookie 也必须先通过 CSRF 校验');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('需要 CSRF 验证', $e->getMessage());
        }

        $pendingCookies = new \ReflectionProperty(SaTokenContext::class, 'pendingCookiesMap');
        $cookiesByContext = $pendingCookies->getValue();
        $this->assertIsArray($cookiesByContext);
        $cookies = $cookiesByContext[SaTokenContext::getContextId()] ?? [];
        $this->assertIsArray($cookies);
        $csrfCookie = null;
        foreach ($cookies as $cookie) {
            if (is_array($cookie) && ($cookie['name'] ?? null) === '__Host-sso_csrf_token') {
                $csrfCookie = $cookie;
                break;
            }
        }
        $this->assertIsArray($csrfCookie);
        $this->assertSame('', $csrfCookie['domain']);
        $this->assertSame('/', $csrfCookie['path']);
        $this->assertTrue($csrfCookie['secure']);
        $this->assertFalse($csrfCookie['httpOnly']);

        $csrf = SsoModeSameDomain::buildCsrfValue($token);
        SaTokenContext::setRequest(new class ($token, $csrf) {
            public function __construct(private string $token, private string $csrf)
            {
            }

            public function cookie(string $name): ?string
            {
                return $name === 'satoken' ? $this->token : null;
            }

            public function getHeaderLine(string $name): string
            {
                return strtolower($name) === 'x-csrf-token' ? $this->csrf : '';
            }
        });
        $this->assertSame('cookie-user', $mode->doLogin());
        SaTokenContext::clear();
    }

    public function testSameDomainSsoRejectsDuplicateTokenCookiesBeforeParsing(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName' => 'satoken',
            'timeout' => 86400,
            'activityTimeout' => -1,
            'signKey' => 'sso-csrf-test-secret-32-bytes-long',
            'isReadHeader' => false,
            'isReadCookie' => false,
            'isReadBody' => false,
        ]));
        $token = StpUtil::login('cookie-user')->getAccessToken();
        $csrf = SsoModeSameDomain::buildCsrfValue($token);
        SaTokenContext::setRequest(new class ($token, $csrf) {
            public function __construct(private string $token, private string $csrf)
            {
            }

            public function cookie(string $name): ?string
            {
                return $name === 'satoken' ? $this->token : null;
            }

            public function getHeaderLine(string $name): string
            {
                return match (strtolower($name)) {
                    'cookie' => 'satoken=attacker-token; satoken=' . $this->token,
                    'x-csrf-token' => $this->csrf,
                    default => '',
                };
            }
        });

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('存在多个同名 Token');
        (new SsoModeSameDomain(new SaSsoConfig()))->doLogin();
    }

    public function testSameDomainSsoRequiresSecretForCsrfBinding(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('CSRF 校验需要配置');
        SsoModeSameDomain::buildCsrfValue('known-token');
    }

    public function testBuildLoginUrlWithoutRedirect(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'backUrl'      => 'https://app.example.com/callback',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildLoginUrl();

        $this->assertStringContainsString('redirect=', $url);
        $this->assertStringContainsString(rawurlencode('https://app.example.com/callback'), $url);
    }

    public function testBuildLoginUrlWithExistingQueryParams(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login?theme=dark',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildLoginUrl('https://app.example.com/home');

        $this->assertStringContainsString('&', $url);
        $this->assertStringContainsString('theme=dark', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testBuildLoginUrlRejectsInsecureNonLocalRedirect(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('SSO 回调域名不在允许列表中');
        (new SaSsoHandle($config))->buildLoginUrl('http://app.example.com/callback');
    }

    public function testBuildLoginUrlRequiresAllowlistedPortForNonDefaultPort(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'allowDomains' => ['app.example.com'],
        ]);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('SSO 回调域名不在允许列表中');
        (new SaSsoHandle($config))->buildLoginUrl('https://app.example.com:8443/callback');
    }

    public function testBuildLoginUrlAllowsExplicitWildcardDomainPort(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'allowDomains' => ['*.example.com:8443'],
        ]);

        $url = (new SaSsoHandle($config))->buildLoginUrl('https://app.example.com:8443/callback');

        $this->assertStringContainsString(rawurlencode('https://app.example.com:8443/callback'), $url);
    }

    public function testBuildLoginUrlAcceptsExplicitDefaultPortForHostAllowlist(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'allowDomains' => ['app.example.com'],
        ]);

        $url = (new SaSsoHandle($config))->buildLoginUrl('https://app.example.com:443/callback');

        $this->assertStringContainsString(rawurlencode('https://app.example.com:443/callback'), $url);
    }

    public function testBuildLoginUrlRejectsInsecureLoginEndpoint(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'http://auth.example.com/login',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('loginUrl 必须使用 HTTPS');
        (new SaSsoHandle($config))->buildLoginUrl('https://app.example.com/callback');
    }

    public function testBuildLoginUrlRejectsNonHttpLocalEndpointScheme(): void
    {
        $config = new SaSsoConfig([
            'loginUrl' => 'javascript://localhost/login',
        ]);

        $this->expectException(SaTokenException::class);
        (new SaSsoHandle($config))->buildLoginUrl();
    }

    public function testBuildLoginUrlRejectsAmbiguousEndpointUrls(): void
    {
        $rejected = 0;
        foreach ([
            'https://user@auth.example.com/login',
            'https://auth.example.com/login#fragment',
            "https://auth.example.com/login\r\nX-Injected: yes",
            'https://localhost\\@evil.example/login',
        ] as $endpoint) {
            $config = new SaSsoConfig(['loginUrl' => $endpoint]);
            try {
                (new SaSsoHandle($config))->buildLoginUrl();
                self::fail('歧义或带非请求组件的 SSO 端点必须被拒绝');
            } catch (SaTokenException) {
                // HTTP clients must not reinterpret a URL accepted by PHP.
                $rejected++;
            }
        }
        self::assertSame(4, $rejected);
    }

    public function testBuildLoginUrlAllowsLocalHttpRedirect(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'http://localhost:8080/login',
            'clientId'     => 'local-app',
            'allowDomains' => ['localhost'],
        ]);

        $url = (new SaSsoHandle($config))->buildLoginUrl('http://localhost:8080/callback');

        $this->assertStringContainsString(rawurlencode('http://localhost:8080/callback'), $url);
    }

    public function testBuildLoginUrlWithoutClientId(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildLoginUrl('https://app.example.com/home');

        $this->assertStringNotContainsString('client_id', $url);
    }

    // ======== buildSloUrl 测试 ========

    public function testBuildSloUrlWithRedirect(): void
    {
        $config = new SaSsoConfig([
            'sloUrl'       => 'https://auth.example.com/slo',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildSloUrl('https://app.example.com/home');

        $this->assertStringContainsString('https://auth.example.com/slo', $url);
        $this->assertStringContainsString('redirect=', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testBuildSloUrlWithoutRedirect(): void
    {
        $config = new SaSsoConfig([
            'sloUrl'   => 'https://auth.example.com/slo',
            'clientId' => 'app-1',
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildSloUrl();

        $this->assertStringNotContainsString('redirect=', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testBuildSloUrlRejectsInsecureOrUnsupportedEndpoint(): void
    {
        foreach (['http://auth.example.com/slo', 'javascript://auth.example.com/slo'] as $sloUrl) {
            $handle = new SaSsoHandle(new SaSsoConfig(['sloUrl' => $sloUrl]));

            try {
                $handle->buildSloUrl();
                $this->fail('SSO 单点注销端点必须使用 HTTPS');
            } catch (SaTokenException $exception) {
                $this->assertStringContainsString('sloUrl', $exception->getMessage());
            }
        }
    }

    // ======== doLoginCallback 错误场景 ========

    public function testDoLoginCallbackWithEmptyTicket(): void
    {
        $config = new SaSsoConfig([
            'checkTicketUrl' => 'https://auth.example.com/checkTicket',
        ]);

        $handle = new SaSsoHandle($config);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('SSO ticket 不能为空');
        $handle->doLoginCallback('');
    }

    public function testDoLoginCallbackRejectsOversizedTicketBeforeCallingValidator(): void
    {
        $handle = new class (new SaSsoConfig(['checkState' => false])) extends SaSsoHandle {
            public bool $validatorCalled = false;

            protected function checkTicket(string $ticket): string
            {
                $this->validatorCalled = true;
                return 'unexpected-user';
            }
        };

        try {
            $handle->doLoginCallback(str_repeat('t', 4097));
            self::fail('超大 SSO ticket 必须在进入 ticket 校验器前拒绝');
        } catch (SaTokenException $exception) {
            self::assertSame('SSO ticket 长度不能超过 4096 字节', $exception->getMessage());
        }

        self::assertFalse($handle->validatorCalled);
    }

    public function testDoLoginCallbackBindsNewIdentityInsteadOfIncomingToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'isReadHeader'    => true,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));

        $oldToken = StpUtil::login('old-user')->getAccessToken();
        SaTokenContext::setRequest(new class ($oldToken) {
            public function __construct(private string $token)
            {
            }

            public function getHeaderLine(string $name): string
            {
                return $name === 'satoken' ? $this->token : '';
            }
        });

        $handle = new class (new SaSsoConfig(['checkState' => false])) extends SaSsoHandle {
            protected function checkTicket(string $ticket): string
            {
                return 'sso-user';
            }
        };

        $this->assertSame('sso-user', $handle->doLoginCallback('valid-ticket'));
        $this->assertSame('sso-user', StpUtil::getLoginId());
        $this->assertNotSame($oldToken, StpUtil::getTokenValue());
    }

    public function testFailedSsoCallbackClearsPreviouslyBoundRequestIdentity(): void
    {
        $oldToken = StpUtil::login('old-sso-callback-user')->getAccessToken();
        SaTokenContext::setTokenOverride('login', $oldToken);
        $handle = new class (new SaSsoConfig(['checkState' => false])) extends SaSsoHandle {
            protected function checkTicket(string $ticket): ?string
            {
                return null;
            }
        };

        try {
            $handle->doLoginCallback('invalid-ticket');
            self::fail('无效 SSO ticket 必须拒绝认证');
        } catch (SaTokenException) {
            self::assertNull(StpUtil::getLoginId(), '失败的 SSO 回调不得保留先前绑定的身份');
        }
    }

    public function testFailedCrossRedisSsoCallbackClearsPreviouslyBoundRequestIdentity(): void
    {
        $oldToken = StpUtil::login('old-cross-redis-sso-user')->getAccessToken();
        SaTokenContext::setTokenOverride('login', $oldToken);
        $manager = new SaSsoManager(new SaSsoConfig([
            'crossRedis' => true,
            'checkState' => false,
        ]));
        $handle = new class ($manager->getConfig()) extends SaSsoHandle {
            public function checkTicketCrossRedis(string $ticket): ?string
            {
                return null;
            }
        };
        (new \ReflectionProperty(SaSsoManager::class, 'handle'))->setValue($manager, $handle);

        self::assertNull($manager->doLoginCallback('invalid-ticket'));
        self::assertNull(StpUtil::getLoginId(), '失败的跨 Redis SSO 回调不得保留先前绑定的身份');
    }

    public function testCrossRedisManagerRejectsEmptyTicketBeforeRequest(): void
    {
        $manager = new SaSsoManager(new SaSsoConfig([
            'crossRedis' => true,
            'checkState' => false,
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('SSO ticket 不能为空');
        $manager->doLoginCallback('');
    }

    public function testCrossRedisManagerRejectsOversizedTicketBeforeOutboundRequest(): void
    {
        $manager = new SaSsoManager(new SaSsoConfig([
            'crossRedis' => true,
            'checkState' => false,
            'clientSecret' => str_repeat('s', 32),
        ]));

        try {
            $manager->doLoginCallback(str_repeat('t', 4097));
            self::fail('超大跨 Redis SSO ticket 必须在发起出站请求前拒绝');
        } catch (SaTokenException $exception) {
            self::assertSame('SSO ticket 长度不能超过 4096 字节', $exception->getMessage());
        }
    }

    public function testCrossRedisManagerBindsTicketIdentityInsteadOfIncomingToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'isReadHeader'    => true,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));

        $oldToken = StpUtil::login('old-user')->getAccessToken();
        SaTokenContext::setRequest(new class ($oldToken) {
            public function __construct(private string $token)
            {
            }

            public function getHeaderLine(string $name): string
            {
                return $name === 'satoken' ? $this->token : '';
            }
        });

        $manager = new SaSsoManager(new SaSsoConfig([
            'crossRedis' => true,
            'checkState' => false,
        ]));
        $handle = new class ($manager->getConfig()) extends SaSsoHandle {
            public function checkTicketCrossRedis(string $ticket): string
            {
                return 'sso-user';
            }
        };
        (new \ReflectionProperty(SaSsoManager::class, 'handle'))->setValue($manager, $handle);

        $this->assertSame('sso-user', $manager->doLoginCallback('valid-ticket'));
        $this->assertSame('sso-user', StpUtil::getLoginId());
        $this->assertNotSame($oldToken, StpUtil::getTokenValue());
    }

    public function testDoLoginCallbackWithMissingCheckTicketUrl(): void
    {
        $config = new SaSsoConfig();
        $handle = new SaSsoHandle($config);

        // 内部会抛出 checkTicketUrl 未配置异常
        try {
            $handle->doLoginCallback('some-ticket');
            $this->fail('Expected SaTokenException');
        } catch (SaTokenException $e) {
            // 网络请求可能失败，但校验地址未配置也会触发
            $this->assertTrue(true);
        }
    }

    // ======== getConfig ========

    public function testHandleGetConfig(): void
    {
        $config = new SaSsoConfig(['loginUrl' => 'https://auth.example.com/login']);
        $handle = new SaSsoHandle($config);
        $this->assertSame($config, $handle->getConfig());
    }

    // ======== SaSsoManager 测试 ========

    public function testManagerWithArrayConfig(): void
    {
        $manager = new SaSsoManager([
            'loginUrl' => 'https://auth.example.com/login',
            'mode'     => 'cross-domain',
        ]);

        $this->assertEquals('https://auth.example.com/login', $manager->getConfig()->getLoginUrl());
        $this->assertEquals('cross-domain', $manager->getConfig()->getMode());
        $this->assertNotNull($manager->getHandle());
    }

    public function testManagerWithConfigObject(): void
    {
        $config = new SaSsoConfig(['loginUrl' => 'https://auth.example.com/login']);
        $manager = new SaSsoManager($config);
        $this->assertSame($config, $manager->getConfig());
    }

    public function testManagerBuildLoginUrl(): void
    {
        $manager = new SaSsoManager([
            'loginUrl'     => 'https://auth.example.com/login',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $url = $manager->buildLoginUrl('https://app.example.com/home');
        $this->assertStringContainsString('https://auth.example.com/login', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testManagerBuildSloUrl(): void
    {
        $manager = new SaSsoManager([
            'sloUrl'   => 'https://auth.example.com/slo',
            'clientId' => 'app-1',
        ]);

        $url = $manager->buildSloUrl();
        $this->assertStringContainsString('https://auth.example.com/slo', $url);
    }
}
