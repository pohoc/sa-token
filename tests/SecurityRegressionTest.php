<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\SaOAuth2Config;
use SaToken\OAuth2\SaOAuth2Handle;
use SaToken\SaToken;
use SaToken\Sso\SaSsoConfig;
use SaToken\Sso\SaSsoHandle;
use SaToken\StpUtil;
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
        ]));
        SaToken::setDao(new SaTokenDaoMemory());
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
        };
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

    public function testMixedJwtModeForgedJwtWithoutDaoRecordIsRejected(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'jwtMode'      => 'mixed',
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
            'isReadHeader' => true,
        ]));

        // 合法 JWT（自签发、未在 Dao 建立会话记录）不得直接登录成功
        $jwt = new \SaToken\Plugin\SaTokenJwt([
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ])->createStatelessToken(29999, 'login', 3600);
        $this->actAsToken($jwt);
        $this->assertFalse(StpUtil::getStpLogic()->isLogin());
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
        // 失败尝试烧掉授权码（防暴力猜解 verifier）
        try {
            $handle->exchangeTokenByCode($code->getCode(), 'pkce-public', '', 'https://app.example.com/cb', $verifier);
            $this->fail('校验失败过的授权码应已被消费');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无效的授权码', $e->getMessage());
        }

        $code2 = $handle->generateAuthorizationCode('pkce-public', 3, 'https://app.example.com/cb', '', $challenge, 'S256');
        $at = $handle->exchangeTokenByCode($code2->getCode(), 'pkce-public', '', 'https://app.example.com/cb', $verifier);
        $this->assertNotEmpty($at->getAccessToken());
    }

    public function testOAuth2EmptyRedirectUriListRejectsAnyUri(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config());
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'client-no-uris',
            'clientSecret' => 'secret-with-proper-length',
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
            'clientSecret' => 'secret-with-proper-length',
            'grantTypes'   => ['client_credentials'],
            'scopes'       => ['read'],
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('未授予的 scope');
        $handle->tokenByClientCredentials('scoping', 'secret-with-proper-length', 'admin');
    }

    public function testOAuth2GrantTypeNotAuthorizedForClientRejected(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes' => ['authorization_code', 'password', 'client_credentials'],
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'code-only',
            'clientSecret' => 'secret-with-proper-length',
            'grantTypes'   => ['authorization_code'],
        ]));

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('授权模式');
        $handle->tokenByClientCredentials('code-only', 'secret-with-proper-length');
    }

    public function testOAuth2RefreshTokenReuseRevokesFamily(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes'          => ['authorization_code', 'refresh_token'],
            'refreshTokenTimeout' => 86400,
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'rt-client',
            'clientSecret' => 'secret-with-proper-length',
            'grantTypes'   => ['authorization_code', 'refresh_token'],
            'redirectUris' => ['https://app.example.com/cb'],
        ]));

        $code = $handle->generateAuthorizationCode('rt-client', 30001, 'https://app.example.com/cb');
        $at = $handle->exchangeTokenByCode($code->getCode(), 'rt-client', 'secret-with-proper-length', 'https://app.example.com/cb');
        $rt = $at->getRefreshToken();
        $this->assertNotNull($rt);

        // 正常刷新一次
        $at2 = $handle->refreshToken($rt, 'rt-client', 'secret-with-proper-length');

        // 重用已消费的 RT：必须拒绝，且家族令牌被撤销
        try {
            $handle->refreshToken($rt, 'rt-client', 'secret-with-proper-length');
            $this->fail('RT 重用应被检测并拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('撤销', $e->getMessage());
        }

        // 家族中的 AT 已被联动撤销
        $this->assertNull($handle->validateAccessToken($at2->getAccessToken()));
    }

    public function testOAuth2PkceRoundTrip(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes' => ['authorization_code'],
        ]));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'pkce-client',
            'clientSecret' => 'secret-with-proper-length',
            'grantTypes'   => ['authorization_code'],
            'redirectUris' => ['https://app.example.com/cb'],
        ]));

        $verifier = str_repeat('pkce-verifier-', 4); // 56 chars, 43..128
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        // 防止暴力猜解 verifier：任何校验失败都会烧掉该授权码
        $codeMissing = $handle->generateAuthorizationCode('pkce-client', 30002, 'https://app.example.com/cb', '', $challenge, 'S256');
        try {
            $handle->exchangeTokenByCode($codeMissing->getCode(), 'pkce-client', 'secret-with-proper-length', 'https://app.example.com/cb');
            $this->fail('绑定 PKCE 的授权码必须要求 code_verifier');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('code_verifier', $e->getMessage());
        }
        try {
            $handle->exchangeTokenByCode($codeMissing->getCode(), 'pkce-client', 'secret-with-proper-length', 'https://app.example.com/cb', $verifier);
            $this->fail('校验失败过的授权码应已被消费');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无效的授权码', $e->getMessage());
        }

        $codeWrong = $handle->generateAuthorizationCode('pkce-client', 30003, 'https://app.example.com/cb', '', $challenge, 'S256');
        try {
            $handle->exchangeTokenByCode($codeWrong->getCode(), 'pkce-client', 'secret-with-proper-length', 'https://app.example.com/cb', str_repeat('w', 56));
            $this->fail('错误的 code_verifier 必须被拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('code_verifier', $e->getMessage());
        }

        // 正确 verifier 成功
        $code = $handle->generateAuthorizationCode('pkce-client', 30004, 'https://app.example.com/cb', '', $challenge, 'S256');
        $at = $handle->exchangeTokenByCode($code->getCode(), 'pkce-client', 'secret-with-proper-length', 'https://app.example.com/cb', $verifier);
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
        $ref->setAccessible(true);

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
            'clientSecret' => 'slo-shared-secret',
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
            'clientSecret' => 'secret-with-proper-length',
            'grantTypes'   => ['authorization_code', 'refresh_token'],
            'redirectUris' => ['https://app.example.com/cb'],
        ]));

        $code = $handle->generateAuthorizationCode('gen-client', 60001, 'https://app.example.com/cb');
        $at1 = $handle->exchangeTokenByCode($code->getCode(), 'gen-client', 'secret-with-proper-length', 'https://app.example.com/cb');
        $rt1 = $at1->getRefreshToken();
        $this->assertNotNull($rt1);

        // 第二代
        $at2 = $handle->refreshToken($rt1, 'gen-client', 'secret-with-proper-length');
        $rt2 = $at2->getRefreshToken();
        $this->assertNotNull($rt2);

        // 第三代
        $at3 = $handle->refreshToken($rt2, 'gen-client', 'secret-with-proper-length');
        $rt3 = $at3->getRefreshToken();
        $this->assertNotNull($rt3);

        // 重放第一代 RT：跨代撤销整条链
        try {
            $handle->refreshToken($rt1, 'gen-client', 'secret-with-proper-length');
            $this->fail('第一代 RT 重放应被检测');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('撤销', $e->getMessage());
        }

        // 第三代 AT 已被联动撤销（若最新代存在 RT 则其同样被删）
        $this->assertNull($handle->validateAccessToken($at3->getAccessToken()));
        $this->assertNull($handle->validateAccessToken($at2->getAccessToken()));
        try {
            $handle->refreshToken($rt3, 'gen-client', 'secret-with-proper-length');
            $this->fail('家族撤销后第三代 RT 也应失效');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('无效的刷新令牌', $e->getMessage());
        }
    }

    public function testSsoCheckTicketResponseFreshnessAndBinding(): void
    {
        $template = new \SaToken\Sso\SaSsoTemplate();
        $secret = 'sso-shared-secret';

        // 时效内通过
        $fresh = $template->signParams(['loginId' => '1', 'ticket' => 't1', 'timestamp' => (string) time()], $secret);
        $this->assertTrue($template->verifySign($fresh, $secret, 300));

        // 过期（把 timestamp 改为 10 分钟前并重签 -> 模拟旧响应直接改时间戳不重签则签名失败；此处直接构造过期签名）
        $stale = $template->signParams(['loginId' => '1', 'ticket' => 't1', 'timestamp' => (string) (time() - 3600)], $secret);
        $this->assertFalse($template->verifySign($stale, $secret, 300));
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
    }

    public function testAnnotationInheritsClassLevelAttributes(): void
    {
        // 父类标注 #[SaCheckLogin]，子类未标注——继承式鉴权必须生效；
        // 未登录上下文调用子类方法应抛 NotLoginException
        $ref = new \ReflectionMethod(\SaToken\Annotation\SaAnnotationProcessor::class, 'process');
        $ref->setAccessible(true);

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

        // A) 共享 Cookie 有效：isLogin 短路直接返回（同域模式主路径）
        \SaToken\Util\SaTokenContext::setRequest($makeRequest($validToken));
        $shortCircuitLoginId = $mode->doLogin();
        $this->assertTrue(is_scalar($shortCircuitLoginId));
        $this->assertSame('61001', (string) $shortCircuitLoginId);
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
            'clientSecret' => 'secret-with-proper-length',
            'grantTypes'   => ['password'],
        ]));
        $handle->setUserCredentialsValidator(fn (string $u, string $p): ?int => null);

        for ($i = 0; $i < 5; $i++) {
            try {
                $handle->tokenByPassword('pwd-client', 'secret-with-proper-length', 'victim', 'wrong');
                $this->fail('错误凭据应被拒绝');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('用户名或密码错误', $e->getMessage());
            }
        }

        // 达到锁定阈值后，即使密码正确也被锁定拦截（不再暴露验证端点给爆破）
        $handle->setUserCredentialsValidator(fn (string $u, string $p): int => 70001);
        try {
            $handle->tokenByPassword('pwd-client', 'secret-with-proper-length', 'victim', 'right-password');
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
            $ref->setAccessible(true);
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
            'sensitiveVerifyCallback' => function (string $scene, string $code, mixed $loginId) use (&$sent): void {
                $sent[] = $code;
            },
        ])));

        \SaToken\Security\SaSensitiveVerify::setSendInterval(60);
        $code1 = \SaToken\Security\SaSensitiveVerify::sendCode('sms-bomb', 62001);
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

    public function testOauth2IdTokenEchoesNonceAndHasJti(): void
    {
        $handle = new SaOAuth2Handle(new SaOAuth2Config([
            'grantTypes' => ['authorization_code'],
            'openIdMode' => true,
            'issuer'     => 'https://issuer.example.com',
        ]));
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'jwtSecretKey' => 'test-jwt-secret-key-32-bytes-long-ok!',
        ])));
        $handle->registerClient(new SaOAuth2Client([
            'clientId'     => 'oidc-nonce',
            'clientSecret' => 'secret-with-proper-length',
            'grantTypes'   => ['authorization_code'],
            'redirectUris' => ['https://app.example.com/cb'],
            'scopes'       => ['openid'],
        ]));

        $code = $handle->generateAuthorizationCode('oidc-nonce', 62003, 'https://app.example.com/cb', 'openid', '', '', 'nonce-abc-123');
        $at = $handle->exchangeTokenByCode($code->getCode(), 'oidc-nonce', 'secret-with-proper-length', 'https://app.example.com/cb');

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

        foreach ([null, '', [], new \stdClass()] as $bad) {
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
    }

    public function testApiKeySurfacesLockContentionAfterRetries(): void
    {
        SaToken::setConfig(new SaTokenConfig(array_merge($this->baseConfig(), [
            'isWriteHeader' => true,
        ])));
        $loginResult = StpUtil::login(62005);
        $apiKeyAuth = new \SaToken\Auth\SaApiKey();
        $apiKeyAuth->registerKey('k-test-1', 's-test-1', 62005);

        $request = new class ('k-test-1', 's-test-1') implements \Psr\Http\Message\ServerRequestInterface {
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
        $ref->setAccessible(true);
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

    public function getParsedBody(): null
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
        return [];
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
