<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotSafeException;
use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\SaOAuth2Config;
use SaToken\OAuth2\SaOAuth2Handle;
use SaToken\SaToken;
use SaToken\Sso\SaSsoConfig;
use SaToken\Sso\SaSsoHandle;
use SaToken\Sso\SaSsoManager;
use SaToken\Sso\SaSsoTemplate;
use SaToken\StpLogic;
use SaToken\StpUtil;
use SaToken\TokenManager;
use SaToken\Util\SaTokenContext;

/**
 * 安全加固回归测试
 *
 * 覆盖本次审计修复的关键安全行为：
 * 会话终止（mixed JWT / 黑名单 × 权限层）、OAuth2 授权绑定、SSO state 强制等
 */
class SecurityRegressionTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'isReadHeader'    => true,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
            'jwtSecretKey'    => 'test-jwt-secret-key-32-bytes-long-ok!',
            'signKey'         => 'sensitive-verify-test-sign-key-32-bytes',
        ]));
        SaToken::setDao(new SaTokenDaoMemory());
        SaTokenContext::setRequest($this->makeRequestStub([]));
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaTokenContext::clear();
    }

    private function actAsToken(string $token): void
    {
        SaTokenContext::setRequest($this->makeRequestStub(['satoken' => $token]));
    }

    /**
     * 最小请求桩：SaTokenContext::getHeader 通过 getHeaderLine 读取请求头
     */
    /**
     * @param array<string, string> $headers
     * @param array<string, string> $params
     */
    private function makeRequestStub(array $headers, array $params = []): object
    {
        return new class ($headers) {
            /** @param array<string, string> $headers */
            public function __construct(private array $headers)
            {
            }

            public function getHeaderLine(string $name): string
            {
                $lower = strtolower($name);
                foreach ($this->headers as $k => $v) {
                    if (strtolower($k) === $lower) {
                        return is_string($v) ? $v : '';
                    }
                }
                return '';
            }

            public function getMethod(): string
            {
                return 'GET';
            }

            public function getClientIp(): string
            {
                return '192.0.2.102';
            }
        };
    }

    /** @param array<string, mixed> $payload */
    private function createSignedToken(string $secretKey, array $payload): string
    {
        $encode = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
        $header = $encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256'], JSON_THROW_ON_ERROR));
        $body = $encode(json_encode($payload, JSON_THROW_ON_ERROR));
        $signingInput = $header . '.' . $body;

        return $signingInput . '.' . $encode(hash_hmac('sha256', $signingInput, $secretKey, true));
    }

    /**
     * @param array<string> $permissions
     */
    private function permissionProvider(array $permissions): void
    {
        SaToken::setAction(new class ($permissions) implements \SaToken\Action\SaTokenActionInterface {
            /** @param array<string> $permissions */
            public function __construct(private array $permissions)
            {
            }

            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                /** @var array<string> $perms */
                $perms = $this->permissions;
                return $perms;
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });
    }

    public function testTokenInfoDoesNotExposeIdentityFromAnotherLoginType(): void
    {
        $adminLogic = new \SaToken\StpLogic('admin');
        $token = $adminLogic->login('sensitive-admin-id')->getAccessToken();
        $userLogic = new \SaToken\StpLogic('user');
        $this->actAsToken($token);

        $this->assertNull($userLogic->getLoginIdByToken($token));
        $this->assertNull($userLogic->getTokenInfo()->getLoginId());
        $this->assertSame('sensitive-admin-id', $adminLogic->getTokenInfo()->getLoginId());
    }

    public function testWrongLoginTypeCannotRevokeAnotherTypesToken(): void
    {
        $adminLogic = new \SaToken\StpLogic('admin');
        $userLogic = new \SaToken\StpLogic('user');

        $logoutToken = $adminLogic->login('admin-logout-user')->getAccessToken();
        $this->actAsToken($logoutToken);
        $userLogic->logout();
        $this->assertSame('admin-logout-user', $adminLogic->getLoginIdByToken($logoutToken));

        $kickoutToken = $adminLogic->login('admin-kickout-user')->getAccessToken();
        $userLogic->kickoutByTokenValue($kickoutToken);
        $this->assertSame('admin-kickout-user', $adminLogic->getLoginIdByToken($kickoutToken));

        $revokeToken = $adminLogic->login('admin-revoke-user')->getAccessToken();
        $this->assertFalse($userLogic->revokeToken($revokeToken));
        $this->assertSame('admin-revoke-user', $adminLogic->getLoginIdByToken($revokeToken));
    }

    public function testTokenSessionRequiresTokenOwnedByCurrentLoginType(): void
    {
        $adminLogic = new \SaToken\StpLogic('admin');
        $userLogic = new \SaToken\StpLogic('user');
        $token = $adminLogic->login('admin-session-user')->getAccessToken();
        $this->actAsToken($token);

        $adminSession = $adminLogic->getTokenSession();
        $this->assertNotNull($adminSession);
        $adminSession->set('private-data', 'admin-only');

        $this->assertNull($userLogic->getTokenSession(false));

        $unrecognizedToken = 'unrecognized-token-from-request';
        $this->actAsToken($unrecognizedToken);
        $this->assertNull($userLogic->getTokenSession());
        $this->assertNull(SaToken::getDao()->get(TokenManager::TOKEN_SESSION_PREFIX . $unrecognizedToken));
    }

    public function testWrongLoginTypeCannotSwitchAnotherTypesToken(): void
    {
        $adminLogic = new \SaToken\StpLogic('admin');
        $userLogic = new \SaToken\StpLogic('user');
        $token = $adminLogic->login('admin-switch-user')->getAccessToken();
        $this->actAsToken($token);

        try {
            $userLogic->switchTo('attacker-controlled-user');
            $this->fail('其他 loginType 不应能对该 Token 写入身份切换');
        } catch (NotLoginException) {
            $this->assertFalse($userLogic->isSwitch());
        }

        $this->assertSame('admin-switch-user', $adminLogic->getLoginIdByToken($token));
    }

    public function testWrongLoginTypeCannotRenewAnotherTypesToken(): void
    {
        $adminLogic = new \SaToken\StpLogic('admin');
        $userLogic = new \SaToken\StpLogic('user');
        $token = $adminLogic->login('admin-renew-user')->getAccessToken();
        $this->actAsToken($token);
        $originalTimeout = $adminLogic->getTokenTimeout();

        $userLogic->renewTimeout(172800);

        $this->assertLessThanOrEqual($originalTimeout, $adminLogic->getTokenTimeout());
    }

    public function testStaleRenewalCannotExtendTokenReissuedToAnotherAccount(): void
    {
        $token = 'reusable-renewal-token-value';
        $manager = new TokenManager();
        $manager->saveToken($token, 'old-owner', 'login', 'PC', 300);

        $logic = new class ('login', $manager) extends StpLogic {
            public bool $pauseAfterIdentityLookup = true;

            public function getLoginIdByToken(string $tokenValue): ?string
            {
                $loginId = parent::getLoginIdByToken($tokenValue);
                if ($this->pauseAfterIdentityLookup && $loginId !== null) {
                    $this->pauseAfterIdentityLookup = false;
                    \Fiber::suspend();
                }
                return $loginId;
            }
        };

        $fiber = new \Fiber(function () use ($logic, $token): void {
            SaTokenContext::setTokenOverride('login', $token);
            try {
                $logic->renewTimeout(7200);
            } finally {
                SaTokenContext::setTokenOverride('login', null);
            }
        });

        $fiber->start();
        $this->assertTrue($fiber->isSuspended());

        $manager->deleteToken($token, 'old-owner', 'login');
        $manager->saveToken($token, 'new-owner', 'login', 'PC', 300);
        $newOwnerTimeout = $manager->getTokenTimeout($token);

        $fiber->resume();

        $this->assertTrue($fiber->isTerminated());
        $this->assertSame('new-owner', $manager->getLoginIdByToken($token));
        $this->assertLessThanOrEqual($newOwnerTimeout, $manager->getTokenTimeout($token));
    }

    public function testLogoutAfterRefreshLockLeaseExpiresCannotReturnNewSession(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'refreshToken'         => true,
            'refreshTokenRotation' => true,
        ])));

        $manager = new class () extends TokenManager {
            public bool $pauseAfterGeneratingRefreshAccessToken = false;

            public function createTokenValue(mixed $loginId, string $loginType, string $prefix = ''): string
            {
                $token = parent::createTokenValue($loginId, $loginType, $prefix);
                if ($this->pauseAfterGeneratingRefreshAccessToken && $prefix === '') {
                    $this->pauseAfterGeneratingRefreshAccessToken = false;
                    \Fiber::suspend();
                }

                return $token;
            }
        };
        $logic = new StpLogic('login', $manager);
        $login = $logic->login('refresh-logout-race');
        $oldAccessToken = $login->getAccessToken();
        $refreshToken = (string) $login->getRefreshToken();
        $manager->pauseAfterGeneratingRefreshAccessToken = true;
        $refreshResult = null;
        $refreshError = null;

        $fiber = new \Fiber(function () use ($logic, $refreshToken, &$refreshResult, &$refreshError): void {
            try {
                $refreshResult = $logic->refreshToken($refreshToken);
            } catch (\Throwable $exception) {
                $refreshError = $exception;
            }
        });

        $fiber->start();
        self::assertTrue($fiber->isSuspended());

        // Model an expired distributed lock lease after refresh minted a
        // candidate token but before it can save that token as a session.
        $accountLockKey = TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', 'refresh-logout-race');
        SaToken::getDao()->delete($accountLockKey);
        $logic->logoutByLoginId('refresh-logout-race');
        $fiber->resume();

        self::assertTrue($fiber->isTerminated());
        self::assertNull($refreshResult, '刷新不能在账号登出完成后返回新的会话凭据');
        self::assertInstanceOf(SaTokenException::class, $refreshError);
        self::assertNull($logic->getLoginIdByToken($oldAccessToken));
        self::assertFalse($logic->isRefreshTokenValid($refreshToken));
        self::assertSame([], $manager->getTokenListByLoginId('refresh-logout-race', 'login'));
    }

    public function testRenewalExtendsLoginIdIndexWithTokenTimeout(): void
    {
        $manager = new TokenManager();
        $token = $manager->createTokenValue('renew-index-owner', 'login');
        $manager->saveToken($token, 'renew-index-owner', 'login', 'PC', 300);
        $this->actAsToken($token);

        (new StpLogic('login', $manager))->renewTimeout(7200);

        $this->assertGreaterThanOrEqual(
            $manager->getTokenTimeout($token),
            SaToken::getDao()->getTimeout(TokenManager::buildLoginIdKey('login', 'renew-index-owner'))
        );
    }

    public function testStatelessLoginCannotIssueJwtAfterAccountLogoutWinsExpiredLock(): void
    {
        $loginId = 'stateless-lock-expiry-user';
        SaToken::setConfig(SaToken::getConfig()
            ->setJwtStateless(true)
            ->setJwtSecretKey('test-jwt-secret-key-32-bytes-long-ok!'));

        $logic = new class ('login') extends StpLogic {
            public ?\Closure $afterDisableCheck = null;

            protected function checkDisableForLogin(mixed $loginId): void
            {
                parent::checkDisableForLogin($loginId);
                if ($this->afterDisableCheck !== null) {
                    $callback = $this->afterDisableCheck;
                    $this->afterDisableCheck = null;
                    $callback($loginId);
                }
            }
        };
        $logic->afterDisableCheck = function (mixed $checkedLoginId) use ($loginId): void {
            self::assertSame($loginId, $checkedLoginId);
            // Simulate the 30-second account-lock lease expiring while the old
            // login request is paused; another worker completes logout first.
            SaToken::getDao()->delete(
                TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', $loginId)
            );
            (new StpLogic('login', new TokenManager()))->logoutByLoginId($loginId);
        };

        try {
            $token = $logic->loginStateless($loginId);
            self::assertNull(
                $logic->getLoginIdByToken($token),
                '全账号注销完成后，暂停中的旧登录请求不能返回仍可用的 JWT'
            );
        } catch (SaTokenException $exception) {
            self::assertContains($exception->getMessage(), [
                '账号会话已撤销，拒绝签发无效登录凭证',
                '账号会话锁已失效，拒绝签发无状态登录凭证',
            ]);
        }
    }

    public function testStatelessRefreshCannotReturnJwtAfterAccountLogoutWinsExpiredLock(): void
    {
        $loginId = 'stateless-refresh-lock-expiry-user';
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'jwtStateless'         => true,
            'jwtSecretKey'         => 'test-jwt-secret-key-32-bytes-long-ok!',
            'refreshToken'         => true,
            'refreshTokenRotation' => true,
            'refreshTokenTimeout'  => 3600,
        ])));

        $dao = new class () extends SaTokenDaoMemory {
            public bool $pauseOnGenerationRead = false;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($this->pauseOnGenerationRead
                    && str_starts_with($key, TokenManager::JWT_GENERATION_PREFIX)) {
                    $this->pauseOnGenerationRead = false;
                    \Fiber::suspend();
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $logic = new StpLogic('login');
        $accessToken = $logic->loginStateless($loginId);
        $refreshToken = $logic->createRefreshToken($accessToken);
        $dao->pauseOnGenerationRead = true;
        $refreshResult = null;
        $refreshError = null;

        $fiber = new \Fiber(function () use ($logic, $refreshToken, &$refreshResult, &$refreshError): void {
            try {
                $refreshResult = $logic->refreshToken($refreshToken);
            } catch (\Throwable $exception) {
                $refreshError = $exception;
            }
        });

        $fiber->start();
        self::assertTrue($fiber->isSuspended());

        // The refresh worker has read generation 0 but has not signed its JWT.
        // Let a second worker take over an expired lease and complete logout.
        $lockKey = TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', $loginId);
        SaToken::getDao()->delete($lockKey);
        $logic->logoutByLoginId($loginId);
        $fiber->resume();

        self::assertTrue($fiber->isTerminated());
        self::assertNull($refreshResult, '账号登出完成后，刷新不能返回新的无状态凭据');
        self::assertInstanceOf(SaTokenException::class, $refreshError);
        self::assertNull($logic->getLoginIdByToken($accessToken));
        self::assertFalse($logic->isRefreshTokenValid($refreshToken));
    }

    public function testStatelessLoginHonorsDisabledResponseCredentialWriting(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isWriteHeader' => true,
        ])));
        $logic = new StpLogic('login');

        $privateToken = $logic->loginStateless(
            'private-stateless-login',
            (new \SaToken\SaLoginParameter())->setWriteResponseCredentials(false)
        );
        self::assertSame('private-stateless-login', $logic->getLoginIdByToken($privateToken));

        $pendingHeaders = new \ReflectionProperty(SaTokenContext::class, 'pendingHeadersMap');
        $headersByContext = $pendingHeaders->getValue();
        if (!is_array($headersByContext)) {
            self::fail('待写响应头状态必须是数组');
        }
        $contextHeaders = $headersByContext[SaTokenContext::getContextId()] ?? [];
        if (!is_array($contextHeaders)) {
            self::fail('当前请求上下文的响应头状态必须是数组');
        }
        foreach ($contextHeaders as $header) {
            if (is_array($header) && is_string($header['name'] ?? null)) {
                self::assertNotSame('satoken', strtolower($header['name']));
            }
        }

        $defaultToken = $logic->loginStateless('default-stateless-login');
        $headersByContext = $pendingHeaders->getValue();
        if (!is_array($headersByContext)) {
            self::fail('待写响应头状态必须是数组');
        }
        $contextHeaders = $headersByContext[SaTokenContext::getContextId()] ?? [];
        if (!is_array($contextHeaders)) {
            self::fail('当前请求上下文的响应头状态必须是数组');
        }
        self::assertContains(
            ['name' => 'satoken', 'value' => $defaultToken],
            $contextHeaders,
            '默认登录仍按配置向响应写入 JWT'
        );
    }

    public function testStatelessLoginCannotFinishAfterDisableTakesOverExpiredAccountLock(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ])));

        $dao = new class () extends SaTokenDaoMemory {
            public ?\Closure $afterDisableRead = null;

            public function get(string $key): ?string
            {
                $value = parent::get($key);
                if ($this->afterDisableRead !== null && str_starts_with($key, 'satoken:disable:')) {
                    $callback = $this->afterDisableRead;
                    $this->afterDisableRead = null;
                    $callback();
                }

                return $value;
            }
        };
        SaToken::setDao($dao);
        $logic = new StpLogic('login');
        $loginId = 'stateless-disable-lock-expiry';
        $dao->afterDisableRead = function () use ($dao, $loginId): void {
            // Simulate a paused login resuming after its account-lock lease
            // expired and an administrator completed a disable operation.
            $dao->delete(TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', $loginId));
            (new StpLogic('login', new TokenManager()))->disable($loginId, 'login', 1, 3600);
        };

        try {
            $logic->loginStateless($loginId);
            self::fail('账号封禁完成后，丢失账号锁的无状态登录不能签发 Token');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('锁', $exception->getMessage());
        }

        self::assertTrue($logic->isDisable($loginId, 'login'));
    }

    public function testStatefulLoginCannotFinishAfterDisableTakesOverExpiredAccountLock(): void
    {
        $loginId = 'stateful-disable-lock-expiry';
        $logic = new class ('login') extends StpLogic {
            public int $disableChecks = 0;

            public string $raceLoginId = '';

            protected function checkDisableForLogin(mixed $loginId): void
            {
                parent::checkDisableForLogin($loginId);
                ++$this->disableChecks;
                if ($this->disableChecks === 3) {
                    // Simulate the account-lock lease expiring while the
                    // request is paused, then let an administrator finish.
                    SaToken::getDao()->delete(
                        TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', $this->raceLoginId)
                    );
                    SaTokenContext::setContextId('disable-admin');
                    try {
                        (new StpLogic('login', new TokenManager()))->disable($loginId, 'login', 1, 3600);
                    } finally {
                        SaTokenContext::setContextId('default');
                    }
                }
            }
        };
        $logic->raceLoginId = $loginId;

        try {
            $logic->login($loginId);
            self::fail('账号封禁完成后，丢失账号锁的有状态登录不能签发 Token');
        } catch (SaTokenException $exception) {
            self::assertNotSame('', $exception->getMessage());
        }

        self::assertTrue($logic->isDisable($loginId, 'login'));
        self::assertSame([], (new TokenManager())->getTokenListByLoginId($loginId, 'login'));
    }

    // ======== C1: mixed JWT 模式下会话必须可终止 ========

    public function testMixedJwtModeLogoutInvalidatesToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtMode'      => 'mixed',
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));

        $result = StpUtil::login(20001);
        $token = $result->getAccessToken();

        $this->actAsToken($token);
        $this->assertTrue(StpUtil::getStpLogic()->isLogin());

        // logout 删除 Dao 记录后，Token 必须立即失效（不得回退 JWT 验签放行）
        StpUtil::logout();
        $this->assertFalse(StpUtil::getStpLogic()->isLogin());
    }

    public function testMixedJwtModeKickoutInvalidatesToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtMode'      => 'mixed',
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));

        $result = StpUtil::login(20002);
        $token = $result->getAccessToken();
        $this->actAsToken($token);

        StpUtil::kickoutByTokenValue($token);
        $this->assertFalse(StpUtil::getStpLogic()->isLogin());
    }

    public function testMixedJwtAccountLogoutRemainsRevokedAfterSwitchToStatelessMode(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtMode'      => 'mixed',
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));
        $logic = StpUtil::getStpLogic();
        $loginId = 'mixed-to-stateless-account-logout';
        $token = $logic->login($loginId)->getAccessToken();

        $logic->logoutByLoginId($loginId);
        self::assertNull($logic->getLoginIdByToken($token));

        SaToken::getConfig()->setJwtStateless(true);
        self::assertNull(
            $logic->getLoginIdByToken($token),
            '账号注销后的 mixed JWT 不得通过无状态遗留令牌兼容路径复活'
        );
    }

    public function testMixedJwtSingleLogoutRemainsRevokedAfterSwitchToStatelessMode(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtMode'      => 'mixed',
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));
        $logic = StpUtil::getStpLogic();
        $loginId = 'mixed-to-stateless-single-logout';
        $token = $logic->login($loginId)->getAccessToken();
        $this->actAsToken($token);

        $logic->logout();
        self::assertNull($logic->getLoginIdByToken($token));

        SaToken::getConfig()->setJwtStateless(true);
        self::assertNull(
            $logic->getLoginIdByToken($token),
            '单 token 注销后的 mixed JWT 不得通过无状态遗留令牌兼容路径复活'
        );
    }

    public function testMixedJwtModeForgedJwtWithoutDaoRecordIsRejected(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtMode'      => 'mixed',
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));

        // 合法 JWT（自签发、未在 Dao 建立会话记录）不得直接登录成功
        $jwt = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29999, 'login', 3600);
        $this->actAsToken($jwt);
        $this->assertFalse(StpUtil::getStpLogic()->isLogin());
    }

    public function testMixedJwtModeExpiredTokenCannotRevealItsRefreshToken(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtMode'       => 'mixed',
            'timeout'       => 1,
            'jwtSecretKey'  => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader'  => true,
        ]));

        $token = StpUtil::login(20003)->getAccessToken();
        $refreshToken = StpUtil::createRefreshToken($token, 60);
        $this->actAsToken($token);

        // DAO 续期不能把不可变的 JWT exp 延长。
        StpUtil::renewTimeout(60);
        sleep(2);

        $this->assertTrue(StpUtil::isRefreshTokenValid($refreshToken));
        $this->assertNull(StpUtil::getStpLogic()->getTokenManager()->getLoginIdByToken($token));
        $this->assertNull(StpUtil::getRefreshTokenByAccessToken($token));
    }

    public function testStatelessJwtRejectsTokenFromAnotherLoginType(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));

        $jwt = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29999, 'admin', 3600);
        $this->actAsToken($jwt);

        $this->assertFalse(StpUtil::getStpLogic()->isLogin());
        $this->assertNull(StpUtil::getLoginId());
        $this->assertNull(StpUtil::getStpLogic()->getLoginIdByToken($jwt));
    }

    public function testStatelessJwtProvidesIdentityOnlyForMatchingLoginType(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));

        $jwt = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29999, 'login', 3600);
        $this->actAsToken($jwt);

        $this->assertTrue(StpUtil::getStpLogic()->isLogin());
        $this->assertSame('29999', StpUtil::getLoginId());
        $this->assertSame('29999', StpUtil::getStpLogic()->getLoginIdByToken($jwt));
    }

    public function testStatelessJwtDoesNotInheritAnotherLoginTypesSessionClaims(): void
    {
        $userLogic = SaToken::getStpLogic('user');
        $session = $userLogic->getSessionByLoginId('admin:42');
        self::assertNotNull($session);
        $session->set('role', 'administrator');

        $jwt = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken('42', 'user:admin', 3600);

        $payload = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->parseToken($jwt);
        $this->assertArrayNotHasKey('role', $payload);
    }

    public function testLogoutRevokesStatelessJwt(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));
        $jwt = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29998, 'login', 3600);
        $this->actAsToken($jwt);

        $this->assertTrue(StpUtil::isLogin());
        StpUtil::logout();

        $this->assertTrue(StpUtil::isTokenRevoked($jwt));
        $this->assertFalse(StpUtil::isLogin());
    }

    public function testRevokedStatelessJwtCannotBeReissuedThroughSignatureEncodingAlias(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));

        $logic = SaToken::getStpLogic('login');
        $token = $logic->loginStateless('alias-user');
        [$header, $payload, $signature] = explode('.', $token);
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $lastIndex = strpos($alphabet, substr($signature, -1));
        self::assertIsInt($lastIndex);
        $alias = $header . '.' . $payload . '.'
            . substr($signature, 0, -1) . $alphabet[$lastIndex ^ 1];

        self::assertNotSame($token, $alias);
        self::assertTrue($logic->revokeToken($token));
        self::assertNull($logic->getLoginIdByToken($alias), '撤销 Token 后，等价签名编码不得继续认证');
    }

    public function testKickoutByTokenRevokesStatelessJwt(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));
        $jwt = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29997, 'login', 3600);
        $this->actAsToken($jwt);

        $this->assertTrue(StpUtil::isLogin());
        StpUtil::kickoutByTokenValue($jwt);

        $this->assertTrue(StpUtil::isTokenRevoked($jwt));
        $this->assertFalse(StpUtil::isLogin());
    }

    public function testLogoutByLoginIdRevokesAllStatelessJwts(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));
        $jwt1 = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29996, 'login', 3600);
        $jwt2 = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29996, 'login', 3600);

        StpUtil::logoutByLoginId(29996);

        foreach ([$jwt1, $jwt2] as $jwt) {
            $this->actAsToken($jwt);
            $this->assertFalse(StpUtil::isLogin());
        }
    }

    public function testStatelessJwtAtExactAccountRevocationWatermarkIsRevoked(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));

        $logic = SaToken::getStpLogic('login');
        $token = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createToken('watermark-equality-user', 'login', 3600);
        $claims = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->parseToken($token);
        if (!is_int($claims['iat'] ?? null) && !is_float($claims['iat'] ?? null)) {
            self::fail('JWT iat 必须是数值时间戳');
        }
        self::assertSame('watermark-equality-user', $logic->getLoginIdByToken($token));

        $watermarkKey = 'satoken:jwt:revoked-before:login:' . hash('sha256', 'watermark-equality-user');
        SaToken::getDao()->set($watermarkKey, sprintf('%.6F', (float) $claims['iat']));

        self::assertNull($logic->getLoginIdByToken($token), 'iat 与撤销水位相等时必须按已撤销处理');
    }

    public function testStatelessJwtMintedBeforeLogoutByClockAheadNodeIsRevoked(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));
        StpUtil::logoutByLoginId('clock-skew-user');

        // Simulate a token minted before logout on another node whose clock is
        // ahead. Its future iat must not let it survive the account revocation.
        $token = $this->createSignedToken('test-jwt-secret-key-32-bytes-long-ok!', [
            'sub' => 'clock-skew-user',
            'type' => 'login',
            'iat' => microtime(true) + 60,
            'jti' => bin2hex(random_bytes(16)),
            'exp' => time() + 3600,
            'satoken_gen' => 0,
        ]);

        $this->actAsToken($token);
        $this->assertNull(StpUtil::getStpLogic()->getLoginIdByToken($token));
    }

    public function testStatelessJwtIssuedAfterAccountLogoutRemainsValid(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));
        $jwt = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29995, 'login', 3600);

        // Start at a fresh wall-clock second so the post-logout token is
        // guaranteed to be issued in the same integer second as the cutoff.
        $nextSecond = ceil(microtime(true));
        while (microtime(true) < $nextSecond) {
            usleep(1000);
        }
        StpUtil::logoutByLoginId(29995);
        $newJwt = (new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]))->createStatelessToken(29995, 'login', 3600);
        $this->actAsToken($newJwt);

        $this->assertTrue(StpUtil::isLogin());
        $this->assertFalse(StpUtil::isTokenRevoked($newJwt));
    }

    // ======== C2: 吊销黑名单必须覆盖权限校验层 ========

    public function testRevokedTokenFailsPermissionChecks(): void
    {
        $this->permissionProvider(['admin']);

        $result = StpUtil::login(20003);
        $token = $result->getAccessToken();
        $this->actAsToken($token);

        $this->assertTrue(StpUtil::hasPermission('admin'));

        StpUtil::revokeToken($token);

        // 吊销后 getLoginId 返回 null → 权限校验不再放行
        $this->assertNull(StpUtil::getStpLogic()->getLoginId());
        $this->assertFalse(StpUtil::hasPermission('admin'));
    }

    public function testRevokedTokenCannotPassSafeCheck(): void
    {
        $token = StpUtil::login(20005)->getAccessToken();
        $this->actAsToken($token);
        StpUtil::openSafe(300, 'payment');
        $this->assertTrue(StpUtil::isSafe('payment'));

        StpUtil::revokeToken($token);

        $this->assertFalse(StpUtil::isSafe('payment'));
        $this->expectException(NotSafeException::class);
        StpUtil::checkSafe('payment');
    }

    public function testReissuedTokenDoesNotInheritPreviousSwitchOrSafeState(): void
    {
        SaToken::setAction(new class () implements \SaToken\Action\SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function generateTokenValue(mixed $loginId, string $loginType): string
            {
                return 'fixed-reusable-token-value';
            }
        });

        $oldToken = StpUtil::login(20006)->getAccessToken();
        $this->actAsToken($oldToken);
        StpUtil::getStpLogic()->switchTo(90001);
        StpUtil::openSafe(300, 'payment');
        StpUtil::logout();

        $newToken = StpUtil::login(20007)->getAccessToken();
        $this->assertSame($oldToken, $newToken);
        $this->actAsToken($newToken);

        $this->assertSame('20007', StpUtil::getLoginId());
        $this->assertFalse(StpUtil::isSafe('payment'));
    }

    public function testSwitchedIdentityCannotBypassActivityTimeoutInPermissionChecks(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'activityTimeout' => 60,
        ])));
        $this->permissionProvider(['danger']);

        $token = StpUtil::login(20010)->getAccessToken();
        $this->actAsToken($token);
        StpUtil::getStpLogic()->switchTo(90002);
        SaToken::getDao()->set(TokenManager::LAST_ACTIVE_PREFIX . $token, (string) (time() - 120), 300);

        $this->expectException(NotLoginException::class);
        StpUtil::checkPermission('danger');
    }

    public function testExpiredActivityMarkerCannotReviveAnIdleToken(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'activityTimeout' => 1,
        ])));

        $token = StpUtil::login(20012)->getAccessToken();
        $this->assertNotNull(SaToken::getDao()->get(TokenManager::LAST_ACTIVE_PREFIX . $token));
        $this->actAsToken($token);
        $this->assertTrue(StpUtil::isLogin());

        sleep(2);

        $this->assertFalse(StpUtil::isLogin(), '活动时间标记过期后，Token 不得因缺少标记而恢复有效');
    }

    public function testStatelessJwtEnforcesConfiguredActivityTimeout(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'activityTimeout' => 60,
            'jwtStateless'    => true,
            'jwtSecretKey'    => 'test-jwt-secret-key-32-bytes-long-ok!',
        ])));

        $logic = SaToken::getStpLogic('login');
        $token = $logic->loginStateless(20013);
        $this->assertNotNull(SaToken::getDao()->get(TokenManager::LAST_ACTIVE_PREFIX . $token));
        $this->actAsToken($token);
        $this->assertTrue(StpUtil::isLogin());

        SaToken::getDao()->set(TokenManager::LAST_ACTIVE_PREFIX . $token, (string) (time() - 120), 300);

        $this->assertFalse(StpUtil::isLogin(), '无状态 JWT 也必须遵守启用的活动超时配置');
    }

    public function testStatelessJwtEnforcesConfiguredFingerprintBinding(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'jwtStateless'     => true,
            'jwtSecretKey'     => 'test-jwt-secret-key-32-bytes-long-ok!',
            'tokenFingerprint' => true,
        ])));

        SaTokenContext::setRequest($this->makeRequestStub(['User-Agent' => 'Trusted-Agent/1.0']));
        $logic = SaToken::getStpLogic('login');
        $token = $logic->loginStateless(20014);
        $this->assertNotNull(SaToken::getDao()->get(TokenManager::FINGERPRINT_PREFIX . $token));

        SaTokenContext::setRequest($this->makeRequestStub([
            'satoken'    => $token,
            'User-Agent' => 'Different-Agent/1.0',
        ]));

        $this->assertFalse(StpUtil::isLogin(), '无状态 JWT 必须遵守启用的指纹绑定配置');
    }

    public function testRefreshTokenCannotBeUsedFromDifferentFingerprint(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'refreshToken'     => true,
            'tokenFingerprint' => true,
        ])));
        SaTokenContext::setRequest($this->makeRequestStub(['User-Agent' => 'Trusted-Refresh-Client/1.0']));

        $loginResult = StpUtil::login(20015);
        $refreshToken = $loginResult->getRefreshToken();
        $this->assertNotSame('', $refreshToken);

        SaTokenContext::setRequest($this->makeRequestStub(['User-Agent' => 'Untrusted-Refresh-Client/1.0']));
        try {
            StpUtil::refreshToken($refreshToken);
            self::fail('RefreshToken 不得绕过已启用的客户端指纹绑定');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('指纹', $exception->getMessage());
        }

        self::assertTrue(StpUtil::isRefreshTokenValid($refreshToken));
    }

    public function testFingerprintBoundStatelessRefreshSurvivesAccessTokenExpiry(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'timeout'          => 1,
            'jwtStateless'     => true,
            'jwtSecretKey'     => 'test-jwt-secret-key-32-bytes-long-ok!',
            'tokenFingerprint' => true,
        ])));
        SaTokenContext::setRequest($this->makeRequestStub(['User-Agent' => 'Trusted-Refresh-Client/1.0']));
        $logic = SaToken::getStpLogic('login');

        $accessToken = $logic->loginStateless(20016);
        $refreshToken = $logic->createRefreshToken($accessToken, 60);
        sleep(2);

        self::assertNull($logic->getLoginIdByToken($accessToken));
        $result = $logic->refreshToken($refreshToken);
        self::assertSame('20016', $logic->getLoginIdByToken($result->getAccessToken()));
    }

    public function testSwitchedIdentityCannotBypassFingerprintInPermissionChecks(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'tokenFingerprint' => true,
        ])));
        $this->permissionProvider(['danger']);

        $token = StpUtil::login(20011)->getAccessToken();
        $this->actAsToken($token);
        StpUtil::getStpLogic()->switchTo(90003);
        StpUtil::getStpLogic()->getTokenManager()->saveFingerprint($token, hash('sha256', 'different-device'), 300);

        $this->expectException(NotLoginException::class);
        StpUtil::checkPermission('danger');
    }

    public function testRevokedTokenValueCannotBeReissuedWhileBlacklisted(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), ['maxTryTimes' => 2])));
        SaToken::setAction(new class () implements \SaToken\Action\SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function generateTokenValue(mixed $loginId, string $loginType): string
            {
                return 'fixed-revoked-token-value';
            }
        });

        $token = StpUtil::login(20008)->getAccessToken();
        $this->actAsToken($token);
        StpUtil::revokeToken($token);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('Token 值冲突');
        StpUtil::login(20009);
    }

    public function testCustomTokenGeneratorKeepsAccessAndRefreshCredentialsDistinct(): void
    {
        SaToken::setConfig(SaToken::getConfig()
            ->setRefreshToken(true)
            ->setRefreshTokenTimeout(3600));
        SaToken::setAction(new class () implements \SaToken\Action\SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function generateTokenValue(mixed $loginId, string $loginType): string
            {
                return 'custom-generated-credential-value';
            }
        });

        $login = StpUtil::login('custom-refresh-user');
        $accessToken = $login->getAccessToken();
        $refreshToken = $login->getRefreshToken();

        self::assertNotSame($accessToken, $refreshToken);
        self::assertStringStartsWith('srt_', (string) $refreshToken);
        try {
            StpUtil::refreshToken((string) $accessToken);
            self::fail('An access token must not also be accepted as a refresh token');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('RefreshToken 无效', $exception->getMessage());
        }

        try {
            StpUtil::refreshToken((string) $refreshToken);
            self::fail('A constant custom generator must not rotate a bearer credential');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('拒绝复用旧凭据', $exception->getMessage());
        }
        self::assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($accessToken));
        self::assertTrue(StpUtil::isRefreshTokenValid((string) $refreshToken));
    }

    public function testRevokeTokenWithPermanentTimeoutStaysRevoked(): void
    {
        $result = StpUtil::login(20004, (new \SaToken\SaLoginParameter())->setTimeout(-1));
        $token = $result->getAccessToken();
        $this->actAsToken($token);

        StpUtil::revokeToken($token);

        // 永不过期 Token 的黑名单条目必须不过期（防止一天后复活）
        $blacklistKey = 'satoken:blacklist:' . $token;
        $this->assertSame(-1, SaToken::getDao()->getTimeout($blacklistKey));
    }

    public function testRevokingUnknownTokenDoesNotAllocateBlacklistEntry(): void
    {
        $token = 'attacker-controlled-random-token';

        $this->assertFalse(StpUtil::revokeToken($token));
        $this->assertSame(-2, SaToken::getDao()->getTimeout('satoken:blacklist:' . $token));
    }

    public function testFailedLoginDoesNotLeaveBearerWhenAccountIndexCasFails(): void
    {
        $dao = new class () extends SaTokenDaoMemory {
            public bool $failLoginIndexWrite = true;

            public function compareAndSet(string $key, ?string $expectedValue, ?string $newValue, ?int $timeout = null): bool
            {
                if ($this->failLoginIndexWrite && str_starts_with($key, TokenManager::LOGIN_ID_V2_PREFIX)) {
                    $this->failLoginIndexWrite = false;
                    return false;
                }
                return parent::compareAndSet($key, $expectedValue, $newValue, $timeout);
            }
        };
        SaToken::setDao($dao);

        try {
            StpUtil::login('failed-index-cas-user');
            self::fail('账号会话索引 CAS 失败后登录必须失败');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('账号会话列表已并发变更', $exception->getMessage());
        }
        self::assertFalse($dao->failLoginIndexWrite, '故障注入必须命中账号会话索引写入');
        self::assertSame([], $dao->searchKeys(TokenManager::TOKEN_PREFIX, '', 0, 100));
    }

    public function testEncryptedTokenRejectsPlaintextSubjectReplacement(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => 'test-encryption-key-at-least-32-bytes',
        ]));
        $token = StpUtil::login(29994)->getAccessToken();
        $tokenKey = TokenManager::TOKEN_PREFIX . $token;

        SaToken::getDao()->set($tokenKey, 'attacker-selected-login-id', 3600);

        $this->assertNull(StpUtil::getStpLogic()->getLoginIdByToken($token));
        $this->assertFalse(StpUtil::isLogin());
    }

    public function testRevokingStatelessJwtWithoutExpiryKeepsItRevokedPermanently(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]));
        $jwt = new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]);
        $token = $jwt->createStatelessToken(29999, 'login');

        $this->assertTrue(StpUtil::revokeToken($token));
        $this->assertSame(-1, SaToken::getDao()->getTimeout('satoken:blacklist:' . $token));
        $this->assertNull(StpUtil::getStpLogic()->getLoginIdByToken($token));
    }

    public function testRevokingInvalidStatelessJwtDoesNotAllocateBlacklistEntry(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtStateless' => true,
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ]));
        $token = 'not-a-valid-jwt';

        $this->assertFalse(StpUtil::revokeToken($token));
        $this->assertSame(-2, SaToken::getDao()->getTimeout('satoken:blacklist:' . $token));
    }

    // ======== OAuth2 授权绑定 ========

    public function testOAuth2RegistrationRequiresSecret(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config());

        // 非 authorization_code 授权模式必须有 secret
        try {
            $handle->registerClient(new SaOAuth2Client([
                'clientId'   => 'no-secret',
                'grantTypes' => ['client_credentials'],
            ]));
            $this->fail('非授权码模式的客户端必须有 clientSecret');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('clientSecret', $e->getMessage());
        }

        // 纯授权码模式的公开客户端（PKCE）允许无 secret
        $handle->registerClient(new SaOAuth2Client([
            'clientId'   => 'public-client',
            'grantTypes' => ['authorization_code'],
            'redirectUris' => ['https://app.example.com/cb'],
        ]));
        $this->assertNotNull($handle->getClient('public-client'));
    }

    public function testOAuth2PublicClientRequiresPkce(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config());
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'pkce-public',
            'grantTypes'   => ['authorization_code'],
            'redirectUris' => ['https://app.example.com/cb'],
        ]));

        // 无 secret 且无 PKCE 的授权码生成必须拒绝
        try {
            $handle->generateAuthorizationCode('pkce-public', 1, 'https://app.example.com/cb');
            $this->fail('公开客户端必须使用 PKCE');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('PKCE', $e->getMessage());
        }

        // 带 PKCE 的完整公开客户端流程
        $verifier = str_repeat('public-verifier-', 4);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $code = $handle->generateAuthorizationCode('pkce-public', 2, 'https://app.example.com/cb', '', $challenge, 'S256');

        try {
            $handle->exchangeTokenByCode($code->getCode(), 'pkce-public', '', 'https://app.example.com/cb');
            $this->fail('公开客户端换 token 必须提交 code_verifier');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('code_verifier', $e->getMessage());
        }
        // 缺少 verifier 的请求不能烧毁合法授权码
        $at = $handle->exchangeTokenByCode($code->getCode(), 'pkce-public', '', 'https://app.example.com/cb', $verifier);
        $this->assertNotEmpty($at->getAccessToken());
    }

    public function testOAuth2EmptyRedirectUriListRejectsAnyUri(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config());
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'client-no-uris',
            'clientSecret' => 'oauth-test-secret-with-at-least-32-bytes',
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未注册的回调地址');
        $handle->generateAuthorizationCode('client-no-uris', 1, 'https://attacker.com/cb');
    }

    public function testOAuth2ScopeExceedingClientRegistrationRejected(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes' => ['authorization_code', 'password', 'client_credentials'],
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'scoping',
            'clientSecret' => 'oauth-test-secret-with-at-least-32-bytes',
            'grantTypes'   => ['client_credentials'],
            'scopes'       => ['read'],
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未授予的 scope');
        $handle->tokenByClientCredentials('scoping', 'oauth-test-secret-with-at-least-32-bytes', 'admin');
    }

    public function testOAuth2GrantTypeNotAuthorizedForClientRejected(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes' => ['authorization_code', 'password', 'client_credentials'],
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'code-only',
            'clientSecret' => 'oauth-test-secret-with-at-least-32-bytes',
            'grantTypes'   => ['authorization_code'],
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('授权模式');
        $handle->tokenByClientCredentials('code-only', 'oauth-test-secret-with-at-least-32-bytes');
    }

    public function testOAuth2RefreshTokenReuseRevokesFamily(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes'          => ['authorization_code', 'refresh_token'],
            'refreshTokenTimeout' => 86400,
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'rt-client',
            'clientSecret' => 'oauth-test-secret-with-at-least-32-bytes',
            'grantTypes'   => ['authorization_code', 'refresh_token'],
            'redirectUris' => ['https://app.example.com/cb'],
        ]));

        $code = $handle->generateAuthorizationCode('rt-client', 30001, 'https://app.example.com/cb');
        $at = $handle->exchangeTokenByCode($code->getCode(), 'rt-client', 'oauth-test-secret-with-at-least-32-bytes', 'https://app.example.com/cb');
        $rt = $at->getRefreshToken();
        $this->assertNotNull($rt);

        // 正常刷新一次
        $at2 = $handle->refreshToken($rt, 'rt-client', 'oauth-test-secret-with-at-least-32-bytes');

        // 重用已消费的 RT：必须拒绝，且家族令牌被撤销
        try {
            $handle->refreshToken($rt, 'rt-client', 'oauth-test-secret-with-at-least-32-bytes');
            $this->fail('RT 重用应被检测并拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('撤销', $e->getMessage());
        }

        // 家族中的 AT 已被联动撤销
        $this->assertNull($handle->validateAccessToken($at2->getAccessToken()));
    }

    public function testOAuth2RefreshTokenReplayFromAnotherClientCannotRevokeFamily(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes'          => ['authorization_code', 'refresh_token'],
            'refreshTokenTimeout' => 86400,
        ]));
        $clientSecret = 'oauth-test-secret-with-at-least-32-bytes';
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'owner-client',
            'clientSecret' => $clientSecret,
            'grantTypes'   => ['authorization_code', 'refresh_token'],
            'redirectUris' => ['https://owner.example.com/cb'],
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'other-client',
            'clientSecret' => 'another-oauth-secret-with-at-least-32-bytes',
            'grantTypes'   => ['authorization_code', 'refresh_token'],
            'redirectUris' => ['https://other.example.com/cb'],
        ]));

        $code = $handle->generateAuthorizationCode('owner-client', 30002, 'https://owner.example.com/cb');
        $at = $handle->exchangeTokenByCode($code->getCode(), 'owner-client', $clientSecret, 'https://owner.example.com/cb');
        $refreshToken = $at->getRefreshToken();
        self::assertNotNull($refreshToken);
        $rotated = $handle->refreshToken($refreshToken, 'owner-client', $clientSecret);

        try {
            $handle->refreshToken($refreshToken, 'other-client', 'another-oauth-secret-with-at-least-32-bytes');
            self::fail('其他客户端不能通过重放令牌撤销令牌家族');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('客户端 ID 不匹配', $exception->getMessage());
        }

        self::assertNotNull($handle->validateAccessToken($rotated->getAccessToken()));

        try {
            $handle->refreshToken($refreshToken, 'owner-client', $clientSecret);
            self::fail('令牌所属客户端的重放仍应撤销令牌家族');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('撤销', $exception->getMessage());
        }
        self::assertNull($handle->validateAccessToken($rotated->getAccessToken()));
    }

    public function testOAuth2PkceRoundTrip(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes' => ['authorization_code'],
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'pkce-client',
            'clientSecret' => 'oauth-test-secret-with-at-least-32-bytes',
            'grantTypes'   => ['authorization_code'],
            'redirectUris' => ['https://app.example.com/cb'],
        ]));

        $verifier = str_repeat('pkce-verifier-', 4); // 56 chars, 43..128
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        // 错误绑定请求必须拒绝，但不能烧毁合法授权码
        $codeMissing = $handle->generateAuthorizationCode('pkce-client', 30002, 'https://app.example.com/cb', '', $challenge, 'S256');
        try {
            $handle->exchangeTokenByCode($codeMissing->getCode(), 'pkce-client', 'oauth-test-secret-with-at-least-32-bytes', 'https://app.example.com/cb');
            $this->fail('绑定 PKCE 的授权码必须要求 code_verifier');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('code_verifier', $e->getMessage());
        }
        $atMissing = $handle->exchangeTokenByCode($codeMissing->getCode(), 'pkce-client', 'oauth-test-secret-with-at-least-32-bytes', 'https://app.example.com/cb', $verifier);
        $this->assertNotEmpty($atMissing->getAccessToken(), '缺少 verifier 的尝试不得烧毁合法授权码');

        $codeWrong = $handle->generateAuthorizationCode('pkce-client', 30003, 'https://app.example.com/cb', '', $challenge, 'S256');
        try {
            $handle->exchangeTokenByCode($codeWrong->getCode(), 'pkce-client', 'oauth-test-secret-with-at-least-32-bytes', 'https://app.example.com/cb', str_repeat('w', 56));
            $this->fail('错误的 code_verifier 必须被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('code_verifier', $e->getMessage());
        }
        $atWrong = $handle->exchangeTokenByCode($codeWrong->getCode(), 'pkce-client', 'oauth-test-secret-with-at-least-32-bytes', 'https://app.example.com/cb', $verifier);
        $this->assertNotEmpty($atWrong->getAccessToken(), '错误 verifier 的尝试不得烧毁合法授权码');

        // 正确 verifier 成功
        $code = $handle->generateAuthorizationCode('pkce-client', 30004, 'https://app.example.com/cb', '', $challenge, 'S256');
        $at = $handle->exchangeTokenByCode($code->getCode(), 'pkce-client', 'oauth-test-secret-with-at-least-32-bytes', 'https://app.example.com/cb', $verifier);
        $this->assertNotEmpty($at->getAccessToken());
    }

    // ======== SSO state 强制校验 ========

    public function testSsoCallbackWithoutStateIsRejected(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig([
            'checkTicketUrl' => 'https://auth.example.com/checkTicket',
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('state');
        $handle->doLoginCallback('some-ticket');
    }

    public function testSsoCallbackWithWrongStateIsRejected(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig([
            'checkTicketUrl' => 'https://auth.example.com/checkTicket',
        ]));

        try {
            $handle->doLoginCallback('some-ticket', null, 'attacker-state');
            $this->fail('错误的 state 必须被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('CSRF', $e->getMessage());
        }
    }

    public function testSsoDomainValidationRejectsJavascriptScheme(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig([
            'allowDomains' => ['app.example.com'],
        ]));

        $ref = new \ReflectionMethod(SaSsoHandle::class, 'validateDomain');

        // javascript:// 伪协议 host 可以匹配白名单，但必须被 scheme 校验拒绝
        $this->assertFalse($ref->invoke($handle, 'javascript://app.example.com/%0aalert(1)'));
        $this->assertFalse($ref->invoke($handle, 'data://app.example.com/text/html,hi'));
        $this->assertFalse($ref->invoke($handle, 'ftp://app.example.com/file'));

        // 大小写与尾点归一化
        $this->assertTrue($ref->invoke($handle, 'https://APP.example.com'));
        $this->assertTrue($ref->invoke($handle, 'https://app.example.com.'));
        // 严格 host 匹配不受影响
        $this->assertFalse($ref->invoke($handle, 'https://evilexample.com'));
        $this->assertFalse($ref->invoke($handle, 'https://app.example.com.evil.com'));

        // PHP treats the backslash as user-info while browsers normalize it to a path
        // separator; accepting this string sends the eventual redirect to evil.example.com.
        $this->assertFalse($ref->invoke($handle, 'https://evil.example.com\\@app.example.com/callback'));
        $this->assertFalse($ref->invoke($handle, 'https://user@app.example.com/callback'));
    }

    public function testSsoWildcardDomainDoesNotIncludeApexDomain(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig([
            'allowDomains' => ['*.example.com'],
        ]));

        $ref = new \ReflectionMethod(SaSsoHandle::class, 'validateDomain');

        $this->assertTrue($ref->invoke($handle, 'https://app.example.com/callback'));
        $this->assertTrue($ref->invoke($handle, 'https://deep.app.example.com/callback'));
        $this->assertFalse($ref->invoke($handle, 'https://example.com/callback'));
        $this->assertFalse($ref->invoke($handle, 'https://notexample.com/callback'));
    }

    // ======== SaSign 强制防重放 ========

    public function testSaSignRejectsReplayWithinWindow(): void
    {
        $signer = new \SaToken\Sign\SaSign(['key' => 'sign-secret-32-bytes-long-at-least!']);

        $signed = $signer->signParams(['action' => 'transfer', 'amount' => '100']);
        $this->assertTrue($signer->verifySign($signed));

        // 时间窗口内的重放必须被拒绝（内置 nonce 存储）
        $this->assertFalse($signer->verifySign($signed));
    }

    public function testSaSignRejectsMissingTimestampOrNonce(): void
    {
        $signer = new \SaToken\Sign\SaSign(['key' => 'sign-secret-32-bytes-long-at-least!']);

        $signed = $signer->signParams(['action' => 'a']);
        $this->assertFalse($signer->verifySign(['action' => 'a', 'sign' => $signed['sign']]));
        $this->assertFalse($signer->verifySign(['action' => 'a', 'timestamp' => $signed['timestamp']]));
    }

    public function testSaSignMd5Rejected(): void
    {
        $this->expectException(SaTokenException::class);
        new \SaToken\Sign\SaSign(['key' => 'sign-secret-32-bytes-long-at-least!', 'signAlg' => 'md5']);
    }

    public function testSaSignEmptyValueParamsBoundToSignature(): void
    {
        $signer = new \SaToken\Sign\SaSign(['key' => 'sign-secret-32-bytes-long-at-least!']);

        $signed = $signer->signParams(['action' => 'a']);
        $this->assertTrue($signer->verifySign($signed));

        // 注入空值参数不得保持签名有效
        $injected = $signed;
        $injected['zzz'] = '';
        $this->assertFalse($signer->verifySign($injected));
    }

    // ======== DAO 原子操作 ========

    public function testDaoSetIfNotExistsIsAtomic(): void
    {
        $dao = new SaTokenDaoMemory();

        $this->assertTrue($dao->setIfNotExists('lock:k', 'a', 10));
        $this->assertFalse($dao->setIfNotExists('lock:k', 'b', 10));
        $this->assertSame('a', $dao->get('lock:k'));
    }

    public function testDaoIncrementIsAtomic(): void
    {
        $dao = new SaTokenDaoMemory();

        $this->assertSame(1, $dao->increment('cnt:k', 1, 60));
        $this->assertSame(2, $dao->increment('cnt:k', 1, 60));
        $this->assertSame(5, $dao->increment('cnt:k', 3, 60));
        $this->assertSame(0, $dao->increment('cnt:k', -10, 60));
    }

    // ======== 防爆破原子计数 ========

    public function testAntiBruteLocksAtExactThreshold(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'antiBruteMaxFailures'  => 5,
            'antiBruteLockDuration' => 600,
        ]));

        for ($i = 0; $i < 4; $i++) {
            \SaToken\Security\SaAntiBruteUtil::recordFailure('user-a');
        }
        $this->assertFalse(\SaToken\Security\SaAntiBruteUtil::isAccountLocked('user-a'));
        $this->assertSame(4, \SaToken\Security\SaAntiBruteUtil::getFailCount('user-a'));

        \SaToken\Security\SaAntiBruteUtil::recordFailure('user-a');
        $this->assertTrue(\SaToken\Security\SaAntiBruteUtil::isAccountLocked('user-a'));
        $this->assertSame(5, \SaToken\Security\SaAntiBruteUtil::getFailCount('user-a'));

        // 其他账号不受影响
        $this->assertFalse(\SaToken\Security\SaAntiBruteUtil::isAccountLocked('user-b'));

        \SaToken\Security\SaAntiBruteUtil::clearFailures('user-a');
        $this->assertFalse(\SaToken\Security\SaAntiBruteUtil::isAccountLocked('user-a'));
        $this->assertSame(0, \SaToken\Security\SaAntiBruteUtil::getFailCount('user-a'));
    }

    // ======== SLO 回调验签 ========

    public function testSloCallbackRequiresSignatureWhenSecretConfigured(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig([
            'clientSecret' => 'slo-test-secret-with-at-least-32-bytes',
        ]));

        try {
            $handle->doSloCallback(40001);
            $this->fail('配置了密钥时，无签名的 SLO 回调必须拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('签名', $e->getMessage());
        }

        try {
            $handle->doSloCallback(40001, ['loginId' => '40001', 'sign' => 'forged']);
            $this->fail('签名错误的 SLO 回调必须拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('签名', $e->getMessage());
        }

        // 正确签名（认证中心用 buildSloCallbackParams 生成）应通过
        StpUtil::login(40001);
        $params = $handle->buildSloCallbackParams(40001);
        $handle->doSloCallback(40001, $params);
        $this->assertFalse(StpUtil::isLogin());
    }

    public function testSloCallbackRejectsWhenNoSharedSecretIsConfigured(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig());
        $loginResult = StpUtil::login(40004);
        $this->actAsToken($loginResult->getAccessToken());

        try {
            $handle->doSloCallback(40004);
            $this->fail('未配置共享密钥时不得接受未经认证的注销回调');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('clientSecret', $e->getMessage());
        }

        $this->assertTrue(StpUtil::isLogin(), '拒绝未认证的 SLO 回调时必须保留现有会话');
    }

    public function testSloCallbackRequiresSignedLoginId(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig([
            'clientSecret' => 'slo-test-secret-with-at-least-32-bytes',
        ]));
        $loginResult = StpUtil::login(40002);
        $token = $loginResult->getAccessToken();
        $params = (new \SaToken\Sso\SaSsoTemplate())->signParams([
            'timestamp' => (string) time(),
        ], 'slo-test-secret-with-at-least-32-bytes');

        try {
            $handle->doSloCallback(40002, $params);
            $this->fail('SLO 回调必须在签名中绑定 loginId');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('loginId', $e->getMessage());
        }

        $this->assertTrue(
            StpUtil::getStpLogic()->getTokenManager()->isTokenValid($token),
            '缺少签名 loginId 时不得注销会话'
        );
    }

    public function testSloCallbackRequiresSignedNonce(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig([
            'clientSecret' => 'slo-test-secret-with-at-least-32-bytes',
        ]));
        $token = StpUtil::login(40006)->getAccessToken();
        $params = (new SaSsoTemplate())->signParams([
            'loginId' => '40006',
            'timestamp' => (string) time(),
        ], 'slo-test-secret-with-at-least-32-bytes');

        try {
            $handle->doSloCallback(40006, $params);
            $this->fail('签名数据必须包含一次性 nonce');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('nonce', $e->getMessage());
        }

        $this->assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($token));
    }

    public function testSloCallbackRejectsReplayAfterUserLogsInAgain(): void
    {
        $handle = new SaSsoHandle(new SaSsoConfig([
            'clientSecret' => 'slo-test-secret-with-at-least-32-bytes',
        ]));
        $params = $handle->buildSloCallbackParams(40005);
        $handle->doSloCallback(40005, $params);

        $newToken = StpUtil::login(40005)->getAccessToken();
        $this->actAsToken($newToken);

        try {
            $handle->doSloCallback(40005, $params);
            $this->fail('重放的 SLO 回调不能再次注销用户后来建立的会话');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('nonce', $e->getMessage());
        }

        $this->assertSame('40005', StpUtil::getLoginId());
        $this->assertTrue(StpUtil::getStpLogic()->getTokenManager()->isTokenValid($newToken));
    }

    public function testSsoCheckTicketResponseRequiresTicketBinding(): void
    {
        $secret = 'sso-test-secret-with-at-least-32-bytes';
        $template = new \SaToken\Sso\SaSsoTemplate();
        $response = $template->signParams([
            'loginId' => '40003',
            'timestamp' => (string) time(),
        ], $secret);

        $httpTemplate = new class ($response) extends \SaToken\Sso\SaSsoTemplate {
            /** @param array<string, string> $response */
            public function __construct(private array $response)
            {
                parent::__construct();
            }

            public function post(string $url, array $data = []): string
            {
                return (string) json_encode($this->response);
            }
        };

        $handle = new class (new SaSsoConfig([
            'checkTicketUrl' => 'https://auth.example.com/check-ticket',
            'clientSecret' => $secret,
        ]), $httpTemplate) extends SaSsoHandle {
            public function __construct(SaSsoConfig $config, \SaToken\Sso\SaSsoTemplate $template)
            {
                parent::__construct($config);
                $this->template = $template;
            }

            public function check(string $ticket): ?string
            {
                return $this->checkTicket($ticket);
            }
        };

        try {
            $handle->check('ticket-40003');
            $this->fail('已签名的 check-ticket 响应也必须绑定请求 ticket');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('ticket', $e->getMessage());
        }
    }

    public function testCrossRedisSsoRequiresClientSecretBeforeSendingTicket(): void
    {
        $template = new class () extends SaSsoTemplate {
            public bool $requested = false;

            public function post(string $url, array $data = []): string
            {
                $this->requested = true;
                return '{}';
            }
        };
        $handle = new class (new SaSsoConfig([
            'crossRedisCheckUrl' => 'https://auth.example.com/cross-check-ticket',
        ]), $template) extends SaSsoHandle {
            public function __construct(SaSsoConfig $config, SaSsoTemplate $template)
            {
                parent::__construct($config);
                $this->template = $template;
            }

            public function checkRemote(string $ticket): ?string
            {
                return $this->checkTicketCrossRedis($ticket);
            }
        };

        try {
            $handle->checkRemote('ticket-without-shared-secret');
            self::fail('跨 Redis SSO 必须在发出 ticket 前要求共享密钥');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('clientSecret', $exception->getMessage());
        }

        self::assertFalse($template->requested);
    }

    public function testCrossRedisSsoWithoutClientSecretCannotLogIn(): void
    {
        $manager = new SaSsoManager(new SaSsoConfig([
            'crossRedis' => true,
            'checkState' => false,
        ]));

        try {
            $manager->doLoginCallback('ticket-without-shared-secret');
            self::fail('无共享密钥的跨 Redis 响应不得建立登录会话');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('clientSecret', $exception->getMessage());
        }

        self::assertNull(StpUtil::getLoginId());
    }

    public function testSsoCheckTicketResponseCannotBeReplayedForTheSameTicket(): void
    {
        $secret = 'sso-test-secret-with-at-least-32-bytes';
        foreach ([false, true] as $crossRedis) {
            $template = new class ($secret) extends SaSsoTemplate {
                private ?string $cachedResponse = null;

                public function __construct(private string $secret)
                {
                    parent::__construct();
                }

                public function post(string $url, array $data = []): string
                {
                    if ($this->cachedResponse === null) {
                        $response = $this->signParams([
                            'loginId' => '40003',
                            'ticket' => $data['ticket'],
                            'request_nonce' => $data['nonce'],
                            'timestamp' => (string) time(),
                        ], $this->secret);
                        $this->cachedResponse = (string) json_encode($response);
                    }

                    return $this->cachedResponse;
                }
            };
            $handle = new class (new SaSsoConfig([
                'checkTicketUrl' => 'https://auth.example.com/check-ticket',
                'crossRedisCheckUrl' => 'https://auth.example.com/cross-check-ticket',
                'clientSecret' => $secret,
            ]), $template) extends SaSsoHandle {
                public function __construct(SaSsoConfig $config, SaSsoTemplate $template)
                {
                    parent::__construct($config);
                    $this->template = $template;
                }

                public function checkLocal(string $ticket): ?string
                {
                    return $this->checkTicket($ticket);
                }

                public function checkRemote(string $ticket): ?string
                {
                    return $this->checkTicketCrossRedis($ticket);
                }
            };

            $this->assertSame(
                '40003',
                $crossRedis ? $handle->checkRemote('ticket-40003') : $handle->checkLocal('ticket-40003')
            );
            try {
                $crossRedis ? $handle->checkRemote('ticket-40003') : $handle->checkLocal('ticket-40003');
                $this->fail('已签名的 check-ticket 响应不能在另一个请求中重放');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('nonce', $e->getMessage());
            }
        }
    }

    public function testSsoCheckTicketRejectsEmptyLoginIdInLocalAndCrossRedisResponses(): void
    {
        $secret = 'sso-test-secret-with-at-least-32-bytes';
        foreach ([false, true] as $crossRedis) {
            $template = new class ($secret) extends SaSsoTemplate {
                public function __construct(private string $secret)
                {
                    parent::__construct();
                }

                public function post(string $url, array $data = []): string
                {
                    return (string) json_encode($this->signParams([
                        'loginId' => '',
                        'ticket' => $data['ticket'],
                        'request_nonce' => $data['nonce'],
                        'timestamp' => (string) time(),
                    ], $this->secret));
                }
            };
            $handle = new class (new SaSsoConfig([
                'checkTicketUrl' => 'https://auth.example.com/check-ticket',
                'crossRedisCheckUrl' => 'https://auth.example.com/cross-check-ticket',
                'clientSecret' => $secret,
            ]), $template) extends SaSsoHandle {
                public function __construct(SaSsoConfig $config, SaSsoTemplate $template)
                {
                    parent::__construct($config);
                    $this->template = $template;
                }

                public function checkLocal(string $ticket): ?string
                {
                    return $this->checkTicket($ticket);
                }

                public function checkRemote(string $ticket): ?string
                {
                    return $this->checkTicketCrossRedis($ticket);
                }
            };

            $loginId = $crossRedis
                ? $handle->checkRemote('ticket-empty-login-id')
                : $handle->checkLocal('ticket-empty-login-id');

            self::assertNull($loginId, 'An empty SSO subject must never count as a validated ticket identity');
        }
    }

    // ======== 第二轮加固回归 ========

    public function testTokenIsBoundToItsLoginType(): void
    {
        // 多账号体系：member 体系的 token 不得在 user 体系（及 RPC 透传）中冒用
        $memberLogic = SaToken::getStpLogic('member');
        $result = $memberLogic->login(50001);
        $token = $result->getAccessToken();

        $this->assertNotNull($memberLogic->getLoginIdByToken($token));

        $userLogic = SaToken::getStpLogic('user');
        $this->assertNull($userLogic->getLoginIdByToken($token));
    }

    public function testOAuth2FamilyRevocationSpansGenerations(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes'          => ['authorization_code', 'refresh_token'],
            'refreshTokenTimeout' => 86400,
            'isNewRefreshToken'   => true,
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'gen-client',
            'clientSecret' => 'oauth-test-secret-with-at-least-32-bytes',
            'grantTypes'   => ['authorization_code', 'refresh_token'],
            'redirectUris' => ['https://app.example.com/cb'],
        ]));

        $code = $handle->generateAuthorizationCode('gen-client', 60001, 'https://app.example.com/cb');
        $at1 = $handle->exchangeTokenByCode($code->getCode(), 'gen-client', 'oauth-test-secret-with-at-least-32-bytes', 'https://app.example.com/cb');
        $rt1 = $at1->getRefreshToken();
        $this->assertNotNull($rt1);

        // 第二代
        $at2 = $handle->refreshToken($rt1, 'gen-client', 'oauth-test-secret-with-at-least-32-bytes');
        $rt2 = $at2->getRefreshToken();
        $this->assertNotNull($rt2);

        // 第三代
        $at3 = $handle->refreshToken($rt2, 'gen-client', 'oauth-test-secret-with-at-least-32-bytes');
        $rt3 = $at3->getRefreshToken();
        $this->assertNotNull($rt3);

        // 重放第一代 RT：跨代撤销整条链
        try {
            $handle->refreshToken($rt1, 'gen-client', 'oauth-test-secret-with-at-least-32-bytes');
            $this->fail('第一代 RT 重放应被检测');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('撤销', $e->getMessage());
        }

        // 第三代 AT 已被联动撤销（若最新代存在 RT 则其同样被删）
        $this->assertNull($handle->validateAccessToken($at3->getAccessToken()));
        $this->assertNull($handle->validateAccessToken($at2->getAccessToken()));
        try {
            $handle->refreshToken($rt3, 'gen-client', 'oauth-test-secret-with-at-least-32-bytes');
            $this->fail('家族撤销后第三代 RT 也应失效');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无效的刷新令牌', $e->getMessage());
        }
    }

    public function testSsoCheckTicketResponseFreshnessAndBinding(): void
    {
        $template = new \SaToken\Sso\SaSsoTemplate();
        $secret = 'sso-test-secret-with-at-least-32-bytes';

        // 时效内通过
        $fresh = $template->signParams(['loginId' => '1', 'ticket' => 't1', 'timestamp' => (string) time()], $secret);
        $this->assertTrue($template->verifySign($fresh, $secret, 300));

        // 过期（把 timestamp 改为 10 分钟前并重签 -> 模拟旧响应直接改时间戳不重签则签名失败；此处直接构造过期签名）
        $stale = $template->signParams(['loginId' => '1', 'ticket' => 't1', 'timestamp' => (string) (time() - 3600)], $secret);
        $this->assertFalse($template->verifySign($stale, $secret, 300));

        $missingTimestamp = $template->signParams(['loginId' => '1', 'ticket' => 't1'], $secret);
        $this->assertFalse($template->verifySign($missingTimestamp, $secret, 300));

        $invalidTimestamp = $template->signParams(['loginId' => '1', 'ticket' => 't1', 'timestamp' => 'now'], $secret);
        $this->assertFalse($template->verifySign($invalidTimestamp, $secret, 300));
    }

    public function testSaSessionKeepsOriginalTtlOnUpdate(): void
    {
        $loginResult = StpUtil::login(50002);
        $this->actAsToken($loginResult->getAccessToken());
        $session = StpUtil::getSession();
        $session->set('k1', 'v1');

        $dao = SaToken::getDao();
        $sessionKey = 'satoken:session:login:50002';
        $ttlBefore = $dao->getTimeout($sessionKey);
        $this->assertGreaterThan(0, $ttlBefore);

        // 读取再修改：不得把会话变成永不过期
        $again = StpUtil::getSession();
        $again->set('k2', 'v2');

        $ttlAfter = $dao->getTimeout($sessionKey);
        $this->assertGreaterThan(0, $ttlAfter, '会话更新后 TTL 不应变为永不过期');
    }

    public function testSaSignBindsMethodAndPath(): void
    {
        $signer = new \SaToken\Sign\SaSign(['key' => 'sign-secret-32-bytes-long-at-least!']);

        $signed = $signer->signParams(['a' => '1'], 'POST', '/api/transfer');
        $this->assertTrue($signer->verifySign($signed, 'POST', '/api/transfer'));

        // 相同参数重放到其他端点：拒绝
        $this->assertFalse($signer->verifySign($signed, 'POST', '/api/other'));
        $this->assertFalse($signer->verifySign($signed, 'GET', '/api/transfer'));
    }

    public function testCustomTokenGeneratorGuards(): void
    {
        // 低熵自定义 token 必须被拒绝
        SaToken::setAction(new class () implements \SaToken\Action\SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function generateTokenValue(mixed $loginId, string $loginType): string
            {
                return substr(md5(is_scalar($loginId) ? (string) $loginId : ''), 0, 8);
            }
        });

        try {
            StpUtil::login(50003);
            $this->fail('低熵自定义 token 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('熵不足', $e->getMessage());
        }

        SaToken::setAction(null);
    }

    public function testLoginRejectsEmptyLoginId(): void
    {
        try {
            StpUtil::login('');
            $this->fail('空 loginId 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('loginId', $e->getMessage());
        }

        try {
            StpUtil::login(null);
            $this->fail('null loginId 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('loginId', $e->getMessage());
        }

        foreach ([false, true] as $booleanLoginId) {
            try {
                StpUtil::login($booleanLoginId);
                $this->fail('布尔 loginId 应被拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('loginId', $e->getMessage());
            }
        }

        // 数字 0 是合法标量 ID，不得与 false 混为同一身份。
        $this->assertNotEmpty(StpUtil::login(0)->getAccessToken());

        foreach ([false, true, [], new \stdClass()] as $invalidStatelessLoginId) {
            try {
                SaToken::getStpLogic('login')->loginStateless($invalidStatelessLoginId);
                $this->fail('无状态登录必须拒绝无效 loginId');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('loginId', $e->getMessage());
            }
        }
    }

    public function testAnnotationInheritsClassLevelAttributes(): void
    {
        // 父类标注 #[SaCheckLogin]，子类未标注——继承式鉴权必须生效；
        // 未登录上下文调用子类方法应抛 NotLoginException
        $ref = new \ReflectionMethod(\SaToken\Annotation\SaAnnotationProcessor::class, 'process');

        $child = new class () extends AnnotatedBaseController {
        };

        SaTokenContext::setRequest($this->makeRequestStub([]));

        try {
            $ref->invoke(null, get_class($child), 'someAction');
            $this->fail('父类类级注解应被子类继承并生效');
        } catch (NotLoginException) {
            $this->addToAssertionCount(1);
        }

        // 对照：登录后同一调用不再抛异常
        $loginResult = StpUtil::login(50004);
        $this->actAsToken($loginResult->getAccessToken());
        $ref->invoke(null, get_class($child), 'someAction');
        $this->addToAssertionCount(1);
    }

    // ======== 第三轮加固回归 ========

    public function testSessionConcurrentUpdatesDoNotLoseData(): void
    {
        $loginResult = StpUtil::login(60001);
        $this->actAsToken($loginResult->getAccessToken());

        // 模拟两个"进程"各自持有会话实例并交错写入
        $sessionA = StpUtil::getSession();
        $sessionB = StpUtil::getSession();
        $this->assertNotSame($sessionA, $sessionB);

        // A/B 都先加载到旧快照（此时存储里还没有对方的键）
        $sessionA->get('k1');
        $sessionB->get('k2');

        $sessionA->set('k1', 'from-a');
        $sessionB->set('k2', 'from-b');

        // 锁内重读保证双方写入都保留（旧实现后写者会覆盖前者）
        $final = StpUtil::getSession();
        $this->assertSame('from-a', $final->get('k1'));
        $this->assertSame('from-b', $final->get('k2'));
    }

    public function testSessionRejectsTamperedDataInsteadOfSilentReset(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenEncrypt' => true,
            'aesKey'       => str_repeat('x', 32),
        ]));

        $loginResult = StpUtil::login(60002);
        $this->actAsToken($loginResult->getAccessToken());

        $session = StpUtil::getSession();
        $session->set('secret', 'value');

        // 篡改存储密文（构造合法密文格式但 MAC 不匹配的数据；
        // 完全非 base64 的串会被当作存量明文直通，属于既有兼容语义）
        $sessionKey = 'satoken:session:login:60002';
        $tampered = base64_encode(random_bytes(96));
        SaToken::getDao()->set($sessionKey, $tampered, 300);

        try {
            $session->set('another', 'x');
            $this->fail('密文被篡改后写入应被拒绝（防止掩盖完整性破坏）');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('完整性', $e->getMessage());
        }

        // 原始（被篡改的）记录仍在——没有被空数据静默覆盖
        $this->assertSame($tampered, SaToken::getDao()->get($sessionKey));
    }

    public function testListenerExceptionDoesNotAbortLogin(): void
    {
        $event = SaToken::getEvent();
        $event->addListener(new class () implements \SaToken\Listener\SaTokenListenerInterface {
            public function onLogin(string $loginType, mixed $loginId, string $tokenValue, mixed $parameter): void
            {
                throw new \RuntimeException('listener boom');
            }

            public function onLogout(string $loginType, mixed $loginId, string $tokenValue): void
            {
            }

            public function onKickout(string $loginType, mixed $loginId, string $tokenValue): void
            {
            }

            public function onReplaced(string $loginType, mixed $loginId, string $tokenValue): void
            {
            }

            public function onBlock(string $loginType, mixed $loginId, string $service, int $level, int $timeout): void
            {
            }

            public function onSwitch(string $loginType, mixed $loginId, mixed $switchToId, string $tokenValue): void
            {
            }

            public function onSwitchBack(string $loginType, mixed $loginId, string $tokenValue): void
            {
            }
        });

        $result = StpUtil::login(60003);
        $this->assertNotEmpty($result->getAccessToken());

        $errors = $event->getListenerErrors();
        $this->assertNotEmpty($errors, '监听器异常应被捕获记录');
        $this->assertInstanceOf(\RuntimeException::class, $errors[0]);
    }

    public function testGetStpLogicRejectsIllegalLoginType(): void
    {
        try {
            SaToken::getStpLogic("evil\0type");
            $this->fail('非法 loginType 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('loginType', $e->getMessage());
        }

        // 超长类型（RPC 头可控时的注册表膨胀向量）
        try {
            SaToken::getStpLogic(str_repeat('a', 64));
            $this->fail('超长 loginType 应被拒绝');
        } catch (SaTokenException) {
            $this->addToAssertionCount(1);
        }

        // 合法类型不受影响
        $this->assertInstanceOf(\SaToken\StpLogic::class, SaToken::getStpLogic('member-app_v2'));
    }

    public function testMaxTryTimesRetriesOnTokenConflict(): void
    {
        // 生成器先返回已被占用的 token，再返回唯一 token —— 应通过重试自愈
        SaToken::setAction(new class () implements \SaToken\Action\SaTokenActionInterface {
            public int $calls = 0;

            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function generateTokenValue(mixed $loginId, string $loginType): string
            {
                $this->calls++;
                return $this->calls === 1 ? 'occupied-token-value-16' : 'fresh-token-' . bin2hex(random_bytes(16));
            }
        });

        // 预占第一个 token
        SaToken::getDao()->set('satoken:login:token:occupied-token-value-16', 'other-user', 300);

        $result = StpUtil::login(60004);
        $this->assertStringStartsWith('fresh-token-', $result->getAccessToken());

        SaToken::setAction(null);
    }

    public function testFixedCustomTokenThrowsAfterRetries(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'maxTryTimes' => 3,
        ])));
        SaToken::setAction(new class () implements \SaToken\Action\SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }

            public function generateTokenValue(mixed $loginId, string $loginType): string
            {
                return 'fixed-conflicting-token';
            }
        });

        SaToken::getDao()->set('satoken:login:token:fixed-conflicting-token', 'other-user', 300);

        try {
            StpUtil::login(60005);
            $this->fail('固定冲突 token 重试耗尽后应抛异常');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('Token 值冲突', $e->getMessage());
        }

        SaToken::setAction(null);
    }

    /**
     * @return array<string, mixed>
     */
    private function baseConfig(): array
    {
        return [
            'tokenName'    => 'satoken',
            'timeout'      => 86400,
            'isReadHeader' => true,
        ];
    }

    // ======== 第四轮加固回归 ========

    public function testSameDomainSsoCsrfIsTokenBound(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'signKey' => 'csrf-binding-secret-32-bytes-long-ok!',
            'isWriteCookie' => false,
        ])));
        SaToken::setDao(new SaTokenDaoMemory());

        $loginResult = StpUtil::login(61001);
        $validToken = $loginResult->getAccessToken();
        \SaToken\Util\SaTokenContext::clear();

        $mode = new \SaToken\Sso\Mode\SsoModeSameDomain(new \SaToken\Sso\SaSsoConfig());

        $makeRequest = fn (string $cookieToken, string $csrfHeader = '', string $csrfParam = '') => new class ($cookieToken, $csrfHeader, $csrfParam) implements \Psr\Http\Message\ServerRequestInterface {
            use PsrRequestStubTrait;
            public function __construct(private string $t, private string $h, private string $p)
            {
            }
            /** @return array<string, string> */
            public function getCookieParams(): array
            {
                return ['satoken' => $this->t];
            }
            /** @return array<string> */
            public function getHeader($name): array
            {
                return strtolower((string) $name) === 'x-csrf-token' && $this->h !== '' ? [$this->h] : [];
            }
            /** @return array<string, string> */
            public function getQueryParams(): array
            {
                return $this->p !== '' ? ['_csrf' => $this->p] : [];
            }
        };

        // A) 即使共享 Cookie 有效，也不能因普通认证已识别 Token 而跳过 CSRF。
        \SaToken\Util\SaTokenContext::setRequest($makeRequest($validToken));
        try {
            $mode->doLogin();
            $this->fail('有效共享 Cookie 也必须先通过 CSRF 校验');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('需要 CSRF 验证', $e->getMessage());
        }
        \SaToken\Util\SaTokenContext::clear();

        // B) Cookie 中 Token 已失效 + 无 CSRF 头：要求 CSRF
        \SaToken\Util\SaTokenContext::setRequest($makeRequest('dead-token-value-012345'));
        try {
            $mode->doLogin();
            $this->fail('缺少 CSRF 头应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('CSRF', $e->getMessage());
        }

        // C) 错误 CSRF 头：拒绝
        \SaToken\Util\SaTokenContext::setRequest($makeRequest('dead-token-value-012345', 'wrong-csrf'));
        try {
            $mode->doLogin();
            $this->fail('错误的 CSRF 应被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('CSRF', $e->getMessage());
        }

        // D) CSRF 与 Token 确定性绑定：同 Token 重算一致、异 Token 不同
        $expected = \SaToken\Sso\Mode\SsoModeSameDomain::buildCsrfValue('dead-token-value-012345');
        $this->assertSame($expected, \SaToken\Sso\Mode\SsoModeSameDomain::buildCsrfValue('dead-token-value-012345'));
        $this->assertNotSame($expected, \SaToken\Sso\Mode\SsoModeSameDomain::buildCsrfValue('other-token'));

        // E) 正确 CSRF 但 Token 已失效：明确的重登录信号（而非笼统"需要 CSRF"）
        \SaToken\Util\SaTokenContext::setRequest($makeRequest('dead-token-value-012345', $expected));
        try {
            $mode->doLogin();
            $this->fail('失效 Token 应提示重新登录');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('重新登录', $e->getMessage());
        }

        // F) GET 参数携带 CSRF 不再被接受（防 Referer/日志泄露票据）
        \SaToken\Util\SaTokenContext::setRequest($makeRequest('dead-token-value-012345', '', $expected));
        try {
            $mode->doLogin();
            $this->fail('GET 参数携带 CSRF 不应被接受');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('CSRF', $e->getMessage());
        }
    }

    public function testOAuth2PasswordGrantBruteForceLockout(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes' => ['password'],
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'pwd-client',
            'clientSecret' => 'oauth-test-secret-with-at-least-32-bytes',
            'grantTypes'   => ['password'],
        ]));
        $handle->setUserCredentialsValidator(fn (string $u, string $p): ?int => null);

        for ($i = 0; $i < 5; $i++) {
            try {
                $handle->tokenByPassword('pwd-client', 'oauth-test-secret-with-at-least-32-bytes', 'victim', 'wrong');
                $this->fail('错误凭据应被拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('用户名或密码错误', $e->getMessage());
            }
        }

        // 达到锁定阈值后，即使密码正确也被锁定拦截（不再暴露验证端点给爆破）
        $handle->setUserCredentialsValidator(fn (string $u, string $p): int => 70001);
        try {
            $handle->tokenByPassword('pwd-client', 'oauth-test-secret-with-at-least-32-bytes', 'victim', 'right-password');
            $this->fail('爆破达到阈值后应锁定该用户名');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('锁定', $e->getMessage());
        }
    }

    public function testLogoutIsSerializedWithAccountLock(): void
    {
        $loginResult = StpUtil::login(61002);
        $this->actAsToken($loginResult->getAccessToken());

        // 模拟另一进程持有同账号登录锁
        $otherManager = new \SaToken\TokenManager();
        $otherManager->acquireLock('login:login:' . hash('sha256', '61002'), 5);

        try {
            StpUtil::logout();
            $this->fail('他方持锁时注销应被拒绝而非竞态覆盖');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('处理中', $e->getMessage());
        } finally {
            $otherManager->releaseLock('login:login:' . hash('sha256', '61002'));
        }

        // 释放锁后注销正常
        StpUtil::logout();
        $this->assertFalse(StpUtil::isLogin());
    }

    // ======== 第五轮加固回归 ========

    public function testHeaderAndCookieValuesAreCrLfSanitized(): void
    {
        // 响应头注入（HTTP 响应拆分）防线：CR/LF/NUL 在写入入口被剥离
        \SaToken\Util\SaTokenContext::setHeader('X-Test', "good\r\nInjected: evil");
        \SaToken\Util\SaTokenContext::setCookie('c', "val\r\nSet-Cookie: x=y", 60);

        $response = \SaToken\Util\SaTokenContext::getResponse();
        if ($response instanceof \Psr\Http\Message\ResponseInterface) {
            $this->assertSame('goodInjected: evil', $response->getHeaderLine('X-Test'));
            $setCookie = $response->getHeaderLine('Set-Cookie');
            $this->assertStringNotContainsString("\n", $setCookie);
            $this->assertStringNotContainsString("\r", $setCookie);
        } else {
            // 非 PSR-7 环境：pending 值已被净化（无公开读取器，用反射断言）
            $ref = new \ReflectionProperty(\SaToken\Util\SaTokenContext::class, 'pendingHeadersMap');
            /** @var array<string, array<int, array{name: string, value: string}>> $pending */
            $pending = $ref->getValue();
            $ctx = \SaToken\Util\SaTokenContext::getContextId();
            $found = false;
            foreach ($pending[$ctx] ?? [] as $h) {
                if ($h['name'] === 'X-Test') {
                    $found = true;
                    $this->assertSame('goodInjected: evil', $h['value']);
                }
            }
            $this->assertTrue($found, 'X-Test 应存在于待写响应头中');
        }
    }

    public function testOtpSendIsRateLimited(): void
    {
        $sent = [];
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'signKey' => 'sensitive-verify-test-sign-key-32-bytes',
            'sensitiveVerifyCallback' => function (string $scene, string $code, mixed $loginId) use (&$sent): void {
                $sent[] = $code;
            },
        ])));

        \SaToken\Security\SaSensitiveVerify::setSendInterval(60);
        \SaToken\Security\SaSensitiveVerify::sendCode('sms-bomb', 62001);
        $this->assertCount(1, $sent);

        try {
            \SaToken\Security\SaSensitiveVerify::sendCode('sms-bomb', 62001);
            $this->fail('60 秒内重复发送应被频控拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('频繁', $e->getMessage());
        }
        $this->assertCount(1, $sent, '被频控的发送不得触发通知回调');

        // 其他 loginId 不受影响
        \SaToken\Security\SaSensitiveVerify::sendCode('sms-bomb', 62002);
        $this->assertCount(2, $sent);

        // 频控窗口清零后可再发
        SaToken::getDao()->delete(\SaToken\Security\SaSensitiveVerify::getKey('sms-bomb', 62001) . ':sent');
        \SaToken\Security\SaSensitiveVerify::sendCode('sms-bomb', 62001);
        $this->assertCount(3, $sent);
    }

    public function testStpLogicOtpSendDoesNotExposeCodeToCaller(): void
    {
        $sent = null;
        SaToken::getConfig()->setSensitiveVerifyCallback(
            static function (string $scene, string $code, mixed $loginId) use (&$sent): void {
                $sent = $code;
            }
        );
        $token = StpUtil::login(62003)->getAccessToken();
        $this->actAsToken($token);

        StpUtil::getStpLogic()->sendOtpCode('profile-update');

        self::assertSame('void', (string) (new \ReflectionMethod(\SaToken\StpLogic::class, 'sendOtpCode'))->getReturnType());
        self::assertIsString($sent);
        self::assertMatchesRegularExpression('/^\d{6}$/', $sent);
    }

    public function testOauth2IdTokenEchoesNonceAndHasJti(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $rsaKey);
        $rsaPrivateKey = '';
        self::assertTrue(openssl_pkey_export($rsaKey, $rsaPrivateKey));
        if (!is_string($rsaPrivateKey)) {
            self::fail('RSA private key export did not return a string.');
        }
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes' => ['authorization_code'],
            'openIdMode' => true,
            'issuer'     => 'https://issuer.example.com',
        ]));
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'rsaPrivateKey' => $rsaPrivateKey,
        ])));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'oidc-nonce',
            'clientSecret' => 'oauth-test-secret-with-at-least-32-bytes',
            'grantTypes'   => ['authorization_code'],
            'redirectUris' => ['https://app.example.com/cb'],
            'scopes'       => ['openid'],
        ]));

        $code = $handle->generateAuthorizationCode('oidc-nonce', 62003, 'https://app.example.com/cb', 'openid', '', '', 'nonce-abc-123');
        $at = $handle->exchangeTokenByCode($code->getCode(), 'oidc-nonce', 'oauth-test-secret-with-at-least-32-bytes', 'https://app.example.com/cb');

        $this->assertNotEmpty($at->getIdToken());
        $parts = explode('.', $at->getIdToken());
        $padded = $parts[1] . str_repeat('=', (4 - strlen($parts[1]) % 4) % 4);
        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);
        $this->assertIsString($decoded);
        $payload = json_decode($decoded, true);
        $this->assertIsArray($payload);
        $this->assertSame('nonce-abc-123', $payload['nonce'] ?? null, '授权请求的 nonce 必须回显进 id_token');
        $this->assertNotEmpty($payload['jti'] ?? null, 'id_token 应包含 jti 唯一标识');
    }

    public function testGetSessionByLoginIdRejectsBadIds(): void
    {
        $logic = SaToken::getStpLogic('login');

        foreach ([null, '', [], false, true, new \stdClass()] as $bad) {
            try {
                $logic->getSessionByLoginId($bad);
                $this->fail('非法 loginId 应被拒绝: ' . gettype($bad));
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('loginId', $e->getMessage());
            }
        }

        // 合法 loginId 正常创建
        $session = $logic->getSessionByLoginId(62004);
        $this->assertNotNull($session);
        $zeroSession = $logic->getSessionByLoginId(0);
        $this->assertSame('satoken:session:login:0', $zeroSession?->getId());
    }

    public function testApiKeySurfacesLockContentionAfterRetries(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'isWriteHeader' => true,
        ])));
        $loginResult = StpUtil::login(62005);
        $apiKeyAuth = new \SaToken\Auth\SaApiKey();
        $apiKeyAuth->registerKey('k-test-1', 'security-regression-api-secret-value-32b', 62005);

        $request = new class ('k-test-1', 'security-regression-api-secret-value-32b') implements \Psr\Http\Message\ServerRequestInterface {
            use PsrRequestStubTrait;
            public function __construct(private string $k, private string $s)
            {
            }
            public function getHeader($name): array
            {
                return match (strtolower((string) $name)) {
                    'api-key' => [$this->k],
                    'api-secret' => [$this->s],
                    default => [],
                };
            }
            public function getHeaderLine($name): string
            {
                $h = $this->getHeader($name);
                return $h !== [] ? (string) $h[0] : '';
            }
            /** @return array<string, string> */
            public function getCookieParams(): array
            {
                return [];
            }
        };
        \SaToken\Util\SaTokenContext::setRequest($request);

        // 模拟他方持有 62005 的账号锁（冷启动竞争的极端形态）：
        // 重试耗尽后应把锁竞争异常抛给调用方，而不是静默吞掉
        $otherManager = new \SaToken\TokenManager();
        $otherManager->acquireLock('login:login:' . hash('sha256', '62005'), 5);
        try {
            $apiKeyAuth->checkApiKey();
            $this->fail('锁竞争耗尽重试后应抛出异常');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('处理中', $e->getMessage());
        } finally {
            $otherManager->releaseLock('login:login:' . hash('sha256', '62005'));
        }

        // 释放锁后：可复用已有会话——复用与 login 语义一致，token 写入响应头
        $recorder = new \SaToken\Tests\RecordingResponse();
        \SaToken\Util\SaTokenContext::setResponse($recorder);
        $apiKeyAuth->checkApiKey();

        // PSR-7 不可变：最终 response 存于 context 的 responseMap 中
        $ref = new \ReflectionProperty(\SaToken\Util\SaTokenContext::class, 'responseMap');
        /** @var array<string, mixed> $responseMap */
        $responseMap = $ref->getValue();
        $finalResponse = $responseMap[\SaToken\Util\SaTokenContext::getContextId()] ?? null;
        $this->assertInstanceOf(\SaToken\Tests\RecordingResponse::class, $finalResponse);
        $this->assertNotEmpty($finalResponse->getHeaderLine('satoken'), '复用会话应把有效 token 写入响应头');
    }
}

/**
 * 供 PSR-7 桩复用的默认实现（仅覆盖本测试需要的方法）
 */
trait PsrRequestStubTrait
{
    public function getProtocolVersion(): string
    {
        return '1.1';
    }

    public function withProtocolVersion($version): \Psr\Http\Message\RequestInterface
    {
        return $this;
    }

    /** @return array<string, array<string>> */
    public function getHeaders(): array
    {
        return [];
    }

    public function hasHeader($name): bool
    {
        return false;
    }

    public function getHeader($name): array
    {
        return [];
    }

    public function getHeaderLine($name): string
    {
        return '';
    }

    public function withHeader($name, $value): static
    {
        return $this;
    }

    public function withAddedHeader($name, $value): static
    {
        return $this;
    }

    public function withoutHeader($name): static
    {
        return $this;
    }

    public function withBody(\Psr\Http\Message\StreamInterface $body): static
    {
        return $this;
    }

    public function getBody(): \Psr\Http\Message\StreamInterface
    {
        throw new \RuntimeException('not needed');
    }

    public function withMethod($method): static
    {
        return $this;
    }

    public function withUri(\Psr\Http\Message\UriInterface $uri, $preserveHost = false): static
    {
        return $this;
    }

    public function getRequestTarget(): string
    {
        return '/';
    }

    public function withRequestTarget($requestTarget): static
    {
        return $this;
    }

    /** @param array<string, string> $query */
    public function withQueryParams(array $query): static
    {
        return $this;
    }

    /**
     * @return array<string, mixed>|object|null
     */
    public function getParsedBody()
    {
        return null;
    }

    /** @param array<string, mixed>|object|resource|null $data */
    public function withParsedBody($data): static
    {
        return $this;
    }

    /** @return array<int, mixed> */
    public function getUploadedFiles(): array
    {
        return [];
    }

    /** @param array<int, mixed> $uploadedFiles */
    public function withUploadedFiles(array $uploadedFiles): static
    {
        return $this;
    }

    /** @param array<string, string> $cookies */
    public function withCookieParams(array $cookies): static
    {
        return $this;
    }

    /** @return array<string, mixed> */
    public function getServerParams(): array
    {
        return ['REMOTE_ADDR' => '192.0.2.102'];
    }

    /** @return array<string, string> */
    public function getQueryParams(): array
    {
        return [];
    }

    public function getAttribute($name, $default = null): mixed
    {
        return $default;
    }

    public function getMethod(): string
    {
        return 'GET';
    }

    public function getUri(): \Psr\Http\Message\UriInterface
    {
        return new \SaToken\Tests\MinimalUri();
    }

    /** @return array<string, mixed> */
    public function getAttributes(): array
    {
        return [];
    }

    public function withAttribute($name, $value): static
    {
        return $this;
    }

    public function withoutAttribute($name): static
    {
        return $this;
    }
}

/**
 * 类级 #[SaCheckLogin] 的基类控制器（用于继承注解测试）
 */
#[\SaToken\Annotation\SaCheckLogin]
abstract class AnnotatedBaseController
{
    public function someAction(): void
    {
    }
}

/**
 * 最小 Uri 实现（PSR-7 桩用）
 */
class MinimalUri implements \Psr\Http\Message\UriInterface
{
    public function getScheme(): string
    {
        return 'https';
    }

    public function getAuthority(): string
    {
        return '';
    }

    public function getUserInfo(): string
    {
        return '';
    }

    public function getHost(): string
    {
        return 'localhost';
    }

    public function getPort(): ?int
    {
        return null;
    }

    public function getPath(): string
    {
        return '/';
    }

    public function getQuery(): string
    {
        return '';
    }

    public function getFragment(): string
    {
        return '';
    }

    public function withScheme($scheme): static
    {
        return $this;
    }

    public function withUserInfo($user, $password = null): static
    {
        return $this;
    }

    public function withHost($host): static
    {
        return $this;
    }

    public function withPort($port): static
    {
        return $this;
    }

    public function withPath($path): static
    {
        return $this;
    }

    public function withQuery($query): static
    {
        return $this;
    }

    public function withFragment($fragment): static
    {
        return $this;
    }

    public function __toString(): string
    {
        return 'https://localhost/';
    }
}

/**
 * 记录响应头的 Response 桩（PSR-7）
 */
class RecordingResponse implements \Psr\Http\Message\ResponseInterface
{
    /** @var array<string, list<string>> */
    public array $headers = [];

    public function getProtocolVersion(): string
    {
        return '1.1';
    }

    public function withProtocolVersion($version): static
    {
        return $this;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function hasHeader($name): bool
    {
        return isset($this->headers[(string) $name]);
    }

    public function getHeader($name): array
    {
        return $this->headers[(string) $name] ?? [];
    }

    public function getHeaderLine($name): string
    {
        return implode(', ', $this->getHeader($name));
    }

    public function withHeader($name, $value): static
    {
        $c = new static();
        /** @var array<string, list<string>> $headers */
        $headers = $this->headers;
        $c->headers = $headers;
        $c->headers[(string) $name] = is_array($value) ? array_values(array_map('strval', $value)) : [(string) $value];
        return $c;
    }

    public function withAddedHeader($name, $value): static
    {
        $c = new static();
        /** @var array<string, list<string>> $headers */
        $headers = $this->headers;
        $c->headers = $headers;
        foreach ((array) $value as $v) {
            $c->headers[(string) $name][] = (string) $v;
        }
        return $c;
    }

    public function withoutHeader($name): static
    {
        $c = new static();
        /** @var array<string, list<string>> $headers */
        $headers = $this->headers;
        $c->headers = $headers;
        unset($c->headers[(string) $name]);
        return $c;
    }

    public function getBody(): \Psr\Http\Message\StreamInterface
    {
        throw new \RuntimeException('not needed');
    }

    public function withBody(\Psr\Http\Message\StreamInterface $body): static
    {
        return $this;
    }

    public function getStatusCode(): int
    {
        return 200;
    }

    public function withStatus($code, $reasonPhrase = ''): static
    {
        return $this;
    }

    public function getReasonPhrase(): string
    {
        return '';
    }
}
