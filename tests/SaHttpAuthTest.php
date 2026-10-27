<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Auth\SaHttpAuth;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Security\SaAntiBruteUtil;
use SaToken\Util\SaTokenContext;

class SaHttpAuthTest extends TestCase
{
    protected TestResponseTracker $responseTracker;

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

        $this->responseTracker = new TestResponseTracker();
        SaTokenContext::setResponse($this->responseTracker);
    }

    public function testDigestParserRejectsDuplicateAndMalformedFields(): void
    {
        $auth = new SaHttpAuth();

        self::assertSame([], $auth->parseDigestHeader('Digest username="alice", Username="mallory"'));
        self::assertSame([], $auth->parseDigestHeader('Digest username="alice" junk, nonce="n"'));
        self::assertSame(['username' => 'alice', 'nonce' => 'n'], $auth->parseDigestHeader('Digest username="alice", nonce="n"'));
        self::assertSame(['realm' => 'tenant"\\one'], $auth->parseDigestHeader('Digest realm="tenant\\"\\\\one"'));
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaTokenContext::clear();
    }

    public function testCheckBasicWithValidCredentials(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name): array {
            if ($name === 'Authorization') {
                return ['Basic ' . base64_encode('admin:123456')];
            }
            return [];
        });
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(function (string $username, string $password): ?string {
            if ($username === 'admin' && $password === '123456') {
                return 'admin';
            }
            return null;
        });
        $auth->checkBasic();
        $this->assertTrue(true);
    }

    public function testBasicRejectsOversizedCredentialsBeforeValidator(): void
    {
        $validatorCalls = 0;
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Basic ' . base64_encode('admin:' . str_repeat('p', 4097))]
            : []);
        SaTokenContext::setRequest($request);

        try {
            (new SaHttpAuth())->setBasicValidator(static function () use (&$validatorCalls): string {
                $validatorCalls++;
                return 'admin';
            })->checkBasic();
            self::fail('超长 Basic 密码必须拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('Basic 密码长度无效', $exception->getMessage());
        }

        self::assertSame(0, $validatorCalls);
    }

    public function testDigestParserRejectsOversizedHeader(): void
    {
        self::assertSame([], (new SaHttpAuth())->parseDigestHeader('Digest username="' . str_repeat('u', 8192) . '"'));
    }

    public function testBasicIdentityOverridesAnUnrelatedBearerToken(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $logic = SaToken::getStpLogic();
        $unrelatedToken = $logic->login('bearer-account')->getAccessToken();
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => match ($name) {
            'Authorization' => ['Basic ' . base64_encode('basic-user:password')],
            'satoken' => [$unrelatedToken],
            default => [],
        });
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.120']);
        SaTokenContext::setRequest($request);

        (new SaHttpAuth())->setBasicValidator(static fn (): string => 'basic-user')->checkBasic();

        self::assertSame('basic-user', $logic->getLoginId());
        self::assertSame('bearer-account', $logic->getLoginIdByToken($unrelatedToken));
    }

    public function testFailedBasicAuthenticationCannotFallBackToAnUnrelatedBearerToken(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $logic = SaToken::getStpLogic();
        $bearerToken = $logic->login('bearer-account')->getAccessToken();
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => match ($name) {
            'Authorization' => ['Basic ' . base64_encode('attacker:wrong-password')],
            'satoken' => [$bearerToken],
            default => [],
        });
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.122']);
        SaTokenContext::setRequest($request);

        $auth = (new SaHttpAuth())->setBasicValidator(static fn (): ?string => null);
        try {
            $auth->checkBasic();
            self::fail('无效 Basic 凭据必须拒绝认证');
        } catch (SaTokenException) {
            self::assertNull($logic->getLoginId(), 'Basic 认证失败后不得回退到请求携带的 bearer token');
        }
    }

    public function testFailedBasicAuthenticationBlocksBearerFallbackAcrossLoginTypes(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $adminLogic = SaToken::getStpLogic('admin');
        $adminToken = $adminLogic->login('admin-bearer-account')->getAccessToken();
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => match ($name) {
            'Authorization' => ['Basic ' . base64_encode('attacker:wrong-password')],
            'satoken' => [$adminToken],
            default => [],
        });
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.123']);
        SaTokenContext::setRequest($request);

        try {
            (new SaHttpAuth())->setBasicValidator(static fn (): ?string => null)->checkBasic();
            self::fail('无效 Basic 凭据必须拒绝认证');
        } catch (SaTokenException) {
            self::assertNull($adminLogic->getLoginId(), '认证失败后任何 loginType 都不得回退到原生 bearer token');
        }
    }

    public function testFailedDigestAuthenticationCannotFallBackToAnUnrelatedBearerToken(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $logic = SaToken::getStpLogic();
        $bearerToken = $logic->login('bearer-account')->getAccessToken();
        $auth = new SaHttpAuth();
        $username = 'digest-user';
        $realm = 'Sa-Token';
        $uri = '/resource';
        $header = sprintf(
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=auth, nc=00000001, cnonce="client-nonce"',
            $username,
            $realm,
            $auth->generateNonce(),
            $uri,
            str_repeat('0', 32)
        );
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => match ($name) {
            'Authorization' => [$header],
            'satoken' => [$bearerToken],
            default => [],
        });
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn($uri);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.123']);
        SaTokenContext::setRequest($request);
        $auth->setDigestValidator(static fn (): string => md5($username . ':' . $realm . ':password'));

        try {
            $auth->checkDigest($realm);
            self::fail('无效 Digest 凭据必须拒绝认证');
        } catch (SaTokenException) {
            self::assertNull($logic->getLoginId(), 'Digest 认证失败后不得回退到请求携带的 bearer token');
        }
    }

    public function testDigestIdentityOverridesAnUnrelatedBearerToken(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setIsReadHeader(true));
        $logic = SaToken::getStpLogic();
        $unrelatedToken = $logic->login('bearer-account')->getAccessToken();
        $auth = new SaHttpAuth();
        $username = 'digest-user';
        $realm = 'Sa-Token';
        $nonce = $auth->generateNonce();
        $uri = '/resource';
        $nc = '00000001';
        $cnonce = 'client-nonce';
        $ha1 = md5($username . ':' . $realm . ':password');
        $ha2 = md5('GET:' . $uri);
        $responseHash = md5($ha1 . ':' . $nonce . ':' . $nc . ':' . $cnonce . ':auth:' . $ha2);
        $authorization = sprintf(
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=auth, nc=%s, cnonce="%s"',
            $username,
            $realm,
            $nonce,
            $uri,
            $responseHash,
            $nc,
            $cnonce
        );
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => match ($name) {
            'Authorization' => [$authorization],
            'satoken' => [$unrelatedToken],
            default => [],
        });
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.121']);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn($uri);
        SaTokenContext::setRequest($request);
        $auth->setDigestValidator(static fn (): string => $ha1);

        $auth->checkDigest($realm);

        self::assertSame($username, $logic->getLoginId());
        self::assertSame('bearer-account', $logic->getLoginIdByToken($unrelatedToken));
    }

    public function testBasicValidatorExceptionCountsAsFailureAndIsRethrown(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Basic ' . base64_encode('throwing-user:wrong')]
            : []);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.110']);
        SaTokenContext::setRequest($request);

        $auth = (new SaHttpAuth())->setBasicValidator(static function (): never {
            throw new SaTokenException('credential rejected');
        });
        try {
            $auth->checkBasic();
            self::fail('validator rejection must not authenticate');
        } catch (SaTokenException $exception) {
            self::assertSame('credential rejected', $exception->getMessage());
        }

        self::assertSame(1, \SaToken\Security\SaAntiBruteUtil::getFailCount('throwing-user'));
    }

    public function testDigestValidatorExceptionCountsAsFailureAndIsRethrown(): void
    {
        $auth = new SaHttpAuth();
        $nonce = $auth->generateNonce();
        $header = sprintf(
            'Digest username="throwing-digest-user", realm="Sa-Token", nonce="%s", uri="/resource", '
                . 'response="00000000000000000000000000000000", qop=auth, nc=00000001, cnonce="client-nonce"',
            $nonce
        );
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn('/resource');
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.111']);
        SaTokenContext::setRequest($request);
        $auth->setDigestValidator(static function (): never {
            throw new SaTokenException('credential lookup rejected');
        });

        try {
            $auth->checkDigest();
            self::fail('validator rejection must not authenticate');
        } catch (SaTokenException $exception) {
            self::assertSame('credential lookup rejected', $exception->getMessage());
        }

        self::assertSame(1, \SaToken\Security\SaAntiBruteUtil::getFailCount('throwing-digest-user'));
    }

    public function testCheckBasicRejectsDuplicateAuthorizationHeaders(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Basic ' . base64_encode('admin:first'), 'Basic ' . base64_encode('admin:second')]
            : []);
        SaTokenContext::setRequest($request);

        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return 'admin';
        });

        try {
            $auth->checkBasic();
            $this->fail('重复 Authorization Header 必须被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('存在多个值', $e->getMessage());
        }
        $this->assertSame(0, $validatorCalls);
    }

    public function testCheckBasicRejectsProxyCombinedAuthorizationHeader(): void
    {
        $combined = 'Basic ' . base64_encode('admin:first') . ', Bearer attacker-token';
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? [$combined]
            : []);
        SaTokenContext::setRequest($request);

        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return 'admin';
        });

        try {
            $auth->checkBasic();
            self::fail('合并的 Authorization Header 必须被拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('存在多个值', $exception->getMessage());
        }
        self::assertSame(0, $validatorCalls);
    }

    public function testCheckBasicAcceptsSingleAuthorizationSchemeValue(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Basic ' . base64_encode('admin:password')]
            : []);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.122']);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static fn (): string => 'admin');
        $auth->checkBasic();

        self::assertSame('admin', \SaToken\StpUtil::getLoginId());
    }

    public function testCheckBasicThrowsOnMissingHeader(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn([]);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
    }

    public function testCheckDigestRejectsDuplicateAuthorizationHeaders(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Digest username="alice"', 'Digest username="mallory"']
            : []);
        SaTokenContext::setRequest($request);

        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setDigestValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return md5('alice:Sa-Token:password');
        });

        try {
            $auth->checkDigest();
            $this->fail('重复 Authorization Header 必须被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('存在多个值', $e->getMessage());
        }
        $this->assertSame(0, $validatorCalls);
    }

    public function testCheckBasicThrowsOnInvalidCredentials(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name): array {
            if ($name === 'Authorization') {
                return ['Basic ' . base64_encode('admin:wrong')];
            }
            return [];
        });
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(function (string $username, string $password): ?string {
            return null;
        });
        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
    }

    public function testCheckBasicTreatsFalseValidatorResultAsFailure(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn(['Basic ' . base64_encode('admin:wrong')]);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static fn (): bool => false);

        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
    }

    public function testCheckBasicDoesNotTreatTrueAsLoginId(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn(['Basic ' . base64_encode('admin:valid')]);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static fn (): bool => true);

        $this->expectException(SaTokenException::class);
        $auth->checkBasic();
    }

    public function testBasicAuthenticationLocksAfterConfiguredFailures(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setAntiBruteMaxFailures(2)->setAntiBruteLockDuration(60));
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn(['Basic ' . base64_encode('admin:wrong')]);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setBasicValidator(static function () use (&$validatorCalls): ?string {
            $validatorCalls++;
            return null;
        });

        for ($attempt = 0; $attempt < 2; $attempt++) {
            try {
                $auth->checkBasic();
                $this->fail('错误的 Basic 凭据必须被拒绝');
            } catch (SaTokenException) {
            }
        }

        try {
            $auth->checkBasic();
            $this->fail('达到失败上限后，Basic 验证器不得继续运行');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('锁定', $e->getMessage());
        }

        $this->assertSame(2, $validatorCalls);
    }

    public function testBasicLoginFailureReleasesSourceConcurrencyReservation(): void
    {
        SaToken::setConfig(SaToken::getConfig()
            ->setAntiBruteMaxFailures(0)
            ->setAntiBruteIpMaxFailures(1)
            ->setAntiBruteLockDuration(60));
        SaToken::getStpLogic()->disable('blocked-account', 'login');

        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Basic ' . base64_encode('valid-user:valid-password')]
            : []);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth = (new SaHttpAuth())->setBasicValidator(static fn (): string => 'blocked-account');
        try {
            $auth->checkBasic();
            self::fail('被禁用账号不得建立 Basic 登录会话');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('封禁', $exception->getMessage());
        }

        $nextRequest = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $nextRequest->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization'
            ? ['Basic ' . base64_encode('other-user:password')]
            : []);
        $nextRequest->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($nextRequest);
        SaAntiBruteUtil::checkAndThrow('other-user');
        SaAntiBruteUtil::clearCurrentSourceFailures('other-user');
    }

    public function testDigestLoginFailureReleasesSourceConcurrencyReservation(): void
    {
        SaToken::setConfig(SaToken::getConfig()
            ->setAntiBruteMaxFailures(0)
            ->setAntiBruteIpMaxFailures(1)
            ->setAntiBruteLockDuration(60));
        SaToken::getStpLogic()->disable('blocked-account', 'login');

        $realm = 'Test';
        $username = 'blocked-account';
        $uri = '/resource';
        $nonce = (new SaHttpAuth())->generateNonce();
        $ha1 = md5($username . ':' . $realm . ':valid-password');
        $ha2 = md5('GET:' . $uri);
        $response = md5($ha1 . ':' . $nonce . ':00000001:client:auth:' . $ha2);
        $header = sprintf(
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=auth, nc=00000001, cnonce="client", response="%s"',
            $username,
            $realm,
            $nonce,
            $uri,
            $response
        );
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn($uri);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth = (new SaHttpAuth())->setDigestValidator(static fn (): string => $ha1);
        try {
            $auth->checkDigest($realm);
            self::fail('被禁用账号不得建立 Digest 登录会话');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('封禁', $exception->getMessage());
        }

        $nextRequest = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $nextRequest->method('getHeader')->willReturn([]);
        $nextRequest->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($nextRequest);
        SaAntiBruteUtil::checkAndThrow('other-user');
        SaAntiBruteUtil::clearCurrentSourceFailures('other-user');
    }

    public function testDigestAuthenticationLocksAfterConfiguredFailures(): void
    {
        SaToken::setConfig(SaToken::getConfig()->setAntiBruteMaxFailures(2)->setAntiBruteLockDuration(60));
        $validatorCalls = 0;
        $auth = new SaHttpAuth();
        $auth->setDigestValidator(static function () use (&$validatorCalls): string {
            $validatorCalls++;
            return md5('admin:Test:password');
        });

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $nonce = $auth->generateNonce();
            $header = 'Digest username="admin", realm="Test", nonce="' . $nonce
                . '", uri="/test", qop=auth, nc=00000001, cnonce="xyz", response="invalid"';
            $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
            $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
            $request->method('getMethod')->willReturn('GET');
            $request->method('getRequestTarget')->willReturn('/test');
            $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
            SaTokenContext::setRequest($request);

            try {
                $auth->checkDigest('Test');
                $this->fail('无效的 Digest 凭据必须被拒绝');
            } catch (SaTokenException $e) {
                if ($attempt === 2) {
                    $this->assertStringContainsString('锁定', $e->getMessage());
                }
            }
        }

        $this->assertSame(2, $validatorCalls);
    }

    public function testCheckDigestTreatsFalseValidatorResultAsFailure(): void
    {
        $auth = new SaHttpAuth();
        $nonce = $auth->generateNonce();
        $header = 'Digest username="admin", realm="Test", nonce="' . $nonce
            . '", uri="/test", qop=auth, nc=00000001, cnonce="xyz", response="invalid"';
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($header): array {
            return $name === 'Authorization' ? [$header] : [];
        });
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn('/test');
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth->setDigestValidator(static fn (): bool => false);

        $this->expectException(SaTokenException::class);
        $auth->checkDigest('Test');
    }

    public function testCheckDigestRejectsEmptyHa1FromValidator(): void
    {
        $username = 'unknown-user';
        $auth = new SaHttpAuth();
        $nonce = $auth->generateNonce();
        $uri = '/test';
        $ha2 = md5('GET:' . $uri);
        $response = md5(':' . $nonce . ':00000001:xyz:auth:' . $ha2);
        $header = sprintf(
            'Digest username="%s", realm="Test", nonce="%s", uri="%s", qop=auth, nc=00000001, cnonce="xyz", response="%s"',
            $username,
            $nonce,
            $uri,
            $response
        );
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn($uri);
        SaTokenContext::setRequest($request);

        $auth->setDigestValidator(static fn (): string => '');

        $this->expectException(SaTokenException::class);
        $auth->checkDigest('Test');
    }

    public function testCheckDigestRejectsRealmMismatchAndUnsupportedQop(): void
    {
        foreach ([
            ['headerRealm' => 'Other', 'challengeRealm' => 'Test', 'qop' => 'auth'],
            ['headerRealm' => 'Test', 'challengeRealm' => 'Test', 'qop' => 'auth-int'],
        ] as $case) {
            $auth = new SaHttpAuth();
            $nonce = $auth->generateNonce();
            $uri = '/test';
            $username = 'admin';
            $ha1 = md5($username . ':' . $case['headerRealm'] . ':secret');
            $ha2 = md5('GET:' . $uri);
            $response = md5($ha1 . ':' . $nonce . ':00000001:xyz:' . $case['qop'] . ':' . $ha2);
            $header = sprintf(
                'Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=00000001, cnonce="xyz", response="%s"',
                $username,
                $case['headerRealm'],
                $nonce,
                $uri,
                $case['qop'],
                $response
            );
            $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
            $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
            $request->method('getMethod')->willReturn('GET');
            $request->method('getRequestTarget')->willReturn($uri);
            SaTokenContext::setRequest($request);

            $validatorCalls = 0;
            $auth->setDigestValidator(static function () use (&$validatorCalls, $username, $case): string {
                $validatorCalls++;
                return md5($username . ':' . $case['challengeRealm'] . ':secret');
            });
            try {
                $auth->checkDigest($case['challengeRealm']);
                self::fail('Realm mismatch and unsupported qop must be rejected');
            } catch (SaTokenException) {
                self::assertSame(0, $validatorCalls);
            }
            SaTokenContext::clear();
        }
    }

    public function testSendChallengeSetsHeader(): void
    {
        $auth = new SaHttpAuth();
        $auth->sendChallenge('TestRealm');
        $this->assertEquals('Basic realm="TestRealm"', $this->responseTracker->headers['WWW-Authenticate']);
    }

    public function testRepeatedDigestChallengesDoNotAllocatePerNonceStorage(): void
    {
        $auth = new SaHttpAuth();
        $auth->sendDigestChallenge('TestRealm');
        $storageSizeAfterFirstChallenge = SaToken::getDao()->size();

        for ($attempt = 0; $attempt < 100; $attempt++) {
            $auth->sendDigestChallenge('TestRealm');
        }

        self::assertSame($storageSizeAfterFirstChallenge, SaToken::getDao()->size());
    }

    public function testChallengeRealmEscapesQuotedStringCharacters(): void
    {
        $auth = new SaHttpAuth();
        $auth->sendChallenge('tenant"\\one');

        $this->assertSame('Basic realm="tenant\\"\\\\one"', $this->responseTracker->headers['WWW-Authenticate']);
    }

    public function testChallengeRealmRejectsHeaderControlCharacters(): void
    {
        $auth = new SaHttpAuth();

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('认证 realm 不能包含控制字符');
        $auth->sendDigestChallenge("safe\r\nSet-Cookie: attacker=1");
    }

    public function testGenerateNonceReturnsNonEmptyString(): void
    {
        $auth = new SaHttpAuth();
        $nonce = $auth->generateNonce();
        $this->assertMatchesRegularExpression('/^[0-9]{10}:[0-9a-f]{32}:[0-9a-f]{64}$/', $nonce);
    }

    public function testParseDigestHeader(): void
    {
        $header = 'Digest username="admin", realm="Test", nonce="abc123", uri="/test", qop=auth, nc=00000001, cnonce="xyz789", response="resp123"';
        $auth = new SaHttpAuth();
        $result = $auth->parseDigestHeader($header);
        $this->assertEquals('admin', $result['username']);
        $this->assertEquals('Test', $result['realm']);
        $this->assertEquals('abc123', $result['nonce']);
        $this->assertEquals('/test', $result['uri']);
        $this->assertEquals('auth', $result['qop']);
        $this->assertEquals('00000001', $result['nc']);
        $this->assertEquals('xyz789', $result['cnonce']);
        $this->assertEquals('resp123', $result['response']);
    }

    public function testCheckDigestWithValidCredentials(): void
    {
        $username = 'admin';
        $realm = 'Test';
        $password = '123456';
        $auth = new SaHttpAuth();
        $nonce = $auth->generateNonce();
        $uri = '/test';
        $qop = 'auth';
        $nc = '00000001';
        $cnonce = 'xyz789';

        $ha1 = md5($username . ':' . $realm . ':' . $password);
        $ha2 = md5('GET:' . $uri);
        $response = md5($ha1 . ':' . $nonce . ':' . $nc . ':' . $cnonce . ':' . $qop . ':' . $ha2);

        $digestHeader = sprintf(
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"',
            $username,
            $realm,
            $nonce,
            $uri,
            $qop,
            $nc,
            $cnonce,
            $response
        );

        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($digestHeader): array {
            if ($name === 'Authorization') {
                return [$digestHeader];
            }
            return [];
        });
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn('/test');
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth->setDigestValidator(function (string $user) use ($ha1): ?string {
            if ($user === 'admin') {
                return $ha1;
            }
            return null;
        });
        $auth->checkDigest($realm);
        $this->assertTrue(true);

        // 同一 nonce 的重放必须被拒绝（nonce 一次性消费）
        try {
            $auth->checkDigest($realm);
            $this->fail('重放已消费的 Digest nonce 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('重放', $e->getMessage());
        }

        // 从未签发过的 nonce 也必须被拒绝
        $forgedHeader = str_replace('nonce="' . $nonce . '"', 'nonce="forged-nonce"', $digestHeader);
        $request2 = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request2->method('getHeader')->willReturnCallback(function (string $name) use ($forgedHeader): array {
            if ($name === 'Authorization') {
                return [$forgedHeader];
            }
            return [];
        });
        $request->method('getRequestTarget')->willReturn('/test');
        SaTokenContext::setRequest($request2);
        try {
            $auth->checkDigest($realm);
            $this->fail('未签发的 Digest nonce 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('重放', $e->getMessage());
        }
    }

    public function testCheckDigestRejectsAuthorizationForDifferentRequestTarget(): void
    {
        $username = 'admin';
        $realm = 'Test';
        $auth = new SaHttpAuth();
        $nonce = $auth->generateNonce();
        $signedUri = '/public';
        $ha1 = md5($username . ':' . $realm . ':123456');
        $ha2 = md5('GET:' . $signedUri);
        $response = md5($ha1 . ':' . $nonce . ':00000001:xyz:auth:' . $ha2);
        $header = sprintf(
            'Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=auth, nc=00000001, cnonce="xyz", response="%s"',
            $username,
            $realm,
            $nonce,
            $signedUri,
            $response
        );

        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturnCallback(static fn (string $name): array => $name === 'Authorization' ? [$header] : []);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getRequestTarget')->willReturn('/admin');
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '192.0.2.100']);
        SaTokenContext::setRequest($request);

        $auth->setDigestValidator(static fn (string $user): ?string => $user === $username ? $ha1 : null);

        try {
            $auth->checkDigest($realm);
            $this->fail('针对其他 URI 签发的 Digest 响应不得认证当前请求');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('URI', $e->getMessage());
        }

        $this->assertNull(\SaToken\StpUtil::getLoginId());
        self::assertNull(SaToken::getDao()->get('satoken:auth:digest:nonce:used:' . explode(':', $nonce)[1]));
    }

    public function testCheckDigestThrowsOnMissingHeader(): void
    {
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->willReturn([]);
        SaTokenContext::setRequest($request);

        $auth = new SaHttpAuth();
        $this->expectException(SaTokenException::class);
        $auth->checkDigest();
    }
}
