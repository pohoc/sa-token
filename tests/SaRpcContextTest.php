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
use SaToken\TokenManager;
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
     * @param array<string, string|list<string>> $headers
     */
    protected function mockRequestWithHeaders(array $headers): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($headers): array {
            if (!isset($headers[$name])) {
                return [];
            }
            return is_array($headers[$name]) ? $headers[$name] : [$headers[$name]];
        });
        return $request;
    }

    public function testAttachToHeaders(): void
    {
        $loginResult = StpUtil::login(10001);
        $token = $loginResult->getAccessToken();

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
        $loginResult = StpUtil::login(10001);
        $token = $loginResult->getAccessToken();

        $request = $this->mockRequestWithHeaders([
            'X-Sa-Token'      => $token,
            'X-Sa-Login-Id'   => '10001',
            'X-Sa-Login-Type' => 'login',
        ]);
        SaTokenContext::setRequest($request);

        SaRpcContext::extractAndValidate();
        $this->assertTrue(true);
    }

    public function testExtractAndValidateRejectsIdleExpiredToken(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setActivityTimeout(60));
        $token = StpUtil::login(10002)->getAccessToken();
        SaToken::getDao()->set(TokenManager::LAST_ACTIVE_PREFIX . $token, (string) (time() - 120), 300);

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token'      => $token,
            'X-Sa-Login-Id'   => '10002',
            'X-Sa-Login-Type' => 'login',
        ]));

        $this->expectException(SaTokenException::class);
        SaRpcContext::extractAndValidate();
    }

    public function testExtractAndValidateRejectsFingerprintMismatch(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setTokenFingerprint(true));
        $token = StpUtil::login(10003)->getAccessToken();
        StpUtil::getStpLogic()->getTokenManager()->saveFingerprint($token, hash('sha256', 'different-device'), 300);

        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token'      => $token,
            'X-Sa-Login-Id'   => '10003',
            'X-Sa-Login-Type' => 'login',
        ]));

        $this->expectException(SaTokenException::class);
        SaRpcContext::extractAndValidate();
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

    public function testExtractAndValidateRejectsDuplicateCredentialHeaders(): void
    {
        $token = StpUtil::login(10007)->getAccessToken();
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token' => ['attacker-value', $token],
            'X-Sa-Login-Id' => '10007',
            'X-Sa-Login-Type' => 'login',
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('RPC 认证 Header 存在多个值');
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

    public function testIsRpcRequestReturnsFalseForDuplicateTokenHeaders(): void
    {
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token' => ['token-one', 'token-two'],
        ]));

        $this->assertFalse(SaRpcContext::isRpcRequest());
        $this->assertNull(SaRpcContext::getForwardedToken());
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
        $loginResult = StpUtil::login(10001);
        $token = $loginResult->getAccessToken();

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

    public function testRpcInterceptorEnforcesConfiguredLoginType(): void
    {
        $token = SaToken::getStpLogic('user')->login(10004)->getAccessToken();
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token'      => $token,
            'X-Sa-Login-Id'   => '10004',
            'X-Sa-Login-Type' => 'user',
        ]));

        $interceptor = (new SaRpcInterceptor())->setLoginType('admin');

        $this->expectException(SaTokenException::class);
        $interceptor->handleIncoming();
    }

    public function testRpcInterceptorUsesConfiguredLoginTypeWhenHeaderIsMissing(): void
    {
        $token = SaToken::getStpLogic('admin')->login(10005)->getAccessToken();
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token'    => $token,
            'X-Sa-Login-Id' => '10005',
        ]));

        (new SaRpcInterceptor())->setLoginType('admin')->handleIncoming();

        $this->assertTrue(true);
    }

    public function testRpcAutoLoginDoesNotSendLocallyIssuedCredentialsInResponse(): void
    {
        $token = StpUtil::login(10006)->getAccessToken();
        $conflictingToken = StpUtil::login(10007)->getAccessToken();
        SaTokenContext::clear();
        SaToken::getConfig()
            ->setIsWriteCookie(true)
            ->setIsWriteHeader(true)
            ->setRefreshToken(true);
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token' => $token,
            'satoken' => $conflictingToken,
        ]));

        (new SaRpcInterceptor())->setAutoLogin(true)->handleIncoming();

        $pendingCookies = new \ReflectionProperty(SaTokenContext::class, 'pendingCookiesMap');
        $pendingHeaders = new \ReflectionProperty(SaTokenContext::class, 'pendingHeadersMap');
        $contextId = SaTokenContext::getContextId();
        $cookiesByContext = $pendingCookies->getValue();
        $headersByContext = $pendingHeaders->getValue();
        self::assertIsArray($cookiesByContext);
        self::assertIsArray($headersByContext);
        self::assertSame([], $cookiesByContext[$contextId] ?? []);
        self::assertSame([], $headersByContext[$contextId] ?? []);
        self::assertSame('10006', StpUtil::getLoginId(), '下游身份必须与已验证的 RPC Token 一致');

        SaTokenContext::setRequest($this->mockRequestWithHeaders(['satoken' => $conflictingToken]));
        self::assertSame('10007', StpUtil::getLoginId(), '下一请求必须清除 RPC Token 覆盖');
    }

    public function testRpcAutoLoginRejectsInvalidForwardedTokenInsteadOfFallingBack(): void
    {
        $conflictingToken = StpUtil::login(10008)->getAccessToken();
        SaTokenContext::clear();
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token' => 'invalid-rpc-token',
            'satoken' => $conflictingToken,
        ]));

        $interceptor = (new SaRpcInterceptor())->setValidateToken(false)->setAutoLogin(true);
        try {
            $interceptor->handleIncoming();
            self::fail('autoLogin 必须拒绝无效的 RPC Token');
        } catch (SaTokenException $exception) {
            self::assertSame('RPC Token 无效', $exception->getMessage());
        }

        self::assertNull(SaToken::getStpLogic()->getLoginId());
    }

    public function testRpcAutoLoginValidatesForwardedIdentityWhenTokenValidationToggleIsOff(): void
    {
        $token = StpUtil::login(10009)->getAccessToken();
        SaTokenContext::clear();
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token'      => $token,
            'X-Sa-Login-Id'   => 'attacker-controlled-id',
            'X-Sa-Login-Type' => 'login',
        ]));

        $interceptor = (new SaRpcInterceptor())->setValidateToken(false)->setAutoLogin(true);
        try {
            $interceptor->handleIncoming();
            self::fail('autoLogin 必须将转发身份绑定到已验证的 Token');
        } catch (SaTokenException $exception) {
            self::assertSame('RPC Token 与转发身份信息不匹配', $exception->getMessage());
        }

        self::assertNull(StpUtil::getLoginId(), '身份不匹配时不得留下有效登录覆盖');
    }

    public function testRpcAutoLoginRejectsRepeatedForwardedIdentityHeadersWhenValidationToggleIsOff(): void
    {
        $token = StpUtil::login(10010)->getAccessToken();
        SaTokenContext::clear();
        SaTokenContext::setRequest($this->mockRequestWithHeaders([
            'X-Sa-Token'      => $token,
            'X-Sa-Login-Id'   => ['10010', 'attacker-controlled-id'],
            'X-Sa-Login-Type' => 'login',
        ]));

        $interceptor = (new SaRpcInterceptor())->setValidateToken(false)->setAutoLogin(true);
        try {
            $interceptor->handleIncoming();
            self::fail('autoLogin 必须拒绝重复身份 Header');
        } catch (SaTokenException $exception) {
            self::assertSame('RPC 认证 Header 存在多个值', $exception->getMessage());
        }

        self::assertNull(StpUtil::getLoginId(), '拒绝重复身份 Header 后不得留下登录覆盖');
    }

    public function testRpcInterceptorOutgoing(): void
    {
        $loginResult = StpUtil::login(10001);
        $token = $loginResult->getAccessToken();

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
