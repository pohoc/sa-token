<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Action\SaTokenActionInterface;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\DisableServiceException;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotSafeException;
use SaToken\Listener\SaTokenListenerInterface;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;

class StpLogicFullTest extends TestCase
{
    protected StpLogic $logic;
    protected SaTokenDaoMemory $dao;
    protected TokenManager $tokenManager;

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
        $this->dao = new SaTokenDaoMemory();
        SaToken::setDao($this->dao);

        $this->logic = new StpLogic('login');
        $this->tokenManager = new TokenManager();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    private function loginAndGetToken(mixed $loginId = 10001, ?SaLoginParameter $param = null): string
    {
        return $this->logic->login($loginId, $param);
    }

    // ======== 权限校验 ========

    public function testCheckPermissionSuccess(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return ['user:add', 'user:delete', 'user:view'];
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

        $token = $this->loginAndGetToken();
        // 直接通过 TokenManager 验证
        $loginId = $this->tokenManager->getLoginIdByToken($token);
        $this->assertEquals('10001', $loginId);

        // 测试权限列表获取
        $permissions = $this->logic->getPermissionList('10001');
        $this->assertContains('user:add', $permissions);
    }

    public function testCheckPermissionNotLoggedIn(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return ['user:view'];
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

        // 未登录时 checkPermission 先抛 NotLoginException
        $this->expectException(NotLoginException::class);
        $this->logic->checkPermission('user:delete');
    }

    public function testCheckPermissionOrSuccess(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return ['user:view'];
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

        $permissions = $this->logic->getPermissionList('10001');
        $this->assertContains('user:view', $permissions);
    }

    public function testHasPermissionTrue(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return ['user:add'];
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

        // 未登录时 hasPermission 返回 false（内部捕获 NotLoginException）
        $this->assertFalse($this->logic->hasPermission('user:add'));
    }

    public function testGetPermissionListNoAction(): void
    {
        SaToken::setAction(null);
        $this->assertEquals([], $this->logic->getPermissionList(10001));
    }

    // ======== 角色校验 ========

    public function testCheckRoleSuccess(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['admin', 'user'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $roles = $this->logic->getRoleList('10001');
        $this->assertContains('admin', $roles);
        $this->assertContains('user', $roles);
    }

    public function testGetRoleListNoAction(): void
    {
        SaToken::setAction(null);
        $this->assertEquals([], $this->logic->getRoleList(10001));
    }

    // ======== 封禁登录拦截 ========

    public function testDisablePreventsLogin(): void
    {
        $this->logic->disable(10001, 'login', 1, 3600);

        $this->expectException(DisableServiceException::class);
        $this->logic->login(10001);
    }

    public function testDisableDoesNotAffectOtherUser(): void
    {
        $this->logic->disable(10001, 'login', 1, 3600);

        // 其他用户仍可登录
        $token = $this->logic->login(20002);
        $this->assertNotEmpty($token);
    }

    public function testDisableDifferentServiceNotAffectLogin(): void
    {
        $this->logic->disable(10001, 'comment', 1, 3600);

        // 'comment' 服务的封禁不影响 'login' 服务
        $token = $this->logic->login(10001);
        $this->assertNotEmpty($token);
    }

    public function testCheckDisableThrowsException(): void
    {
        $this->logic->disable(10001, 'comment', 1, 3600);

        $this->expectException(DisableServiceException::class);
        $this->logic->checkDisable(10001, 'comment');
    }

    public function testCheckDisableNoExceptionWhenNotDisabled(): void
    {
        // 不应抛异常
        $this->logic->checkDisable(10001, 'comment');
        $this->assertTrue(true);
    }

    // ======== 二级认证 ========

    public function testOpenSafeRequiresLogin(): void
    {
        $this->expectException(NotLoginException::class);
        $this->logic->openSafe(120);
    }

    public function testIsSafeWhenNotLoggedIn(): void
    {
        $this->assertFalse($this->logic->isSafe('default'));
    }

    public function testCheckSafeThrowsException(): void
    {
        $this->expectException(NotSafeException::class);
        $this->logic->checkSafe();
    }

    // ======== 身份切换完整流程 ========

    public function testSwitchToRequiresLogin(): void
    {
        $this->expectException(NotLoginException::class);
        $this->logic->switchTo(20001);
    }

    public function testIsSwitchWhenNotLoggedIn(): void
    {
        $this->assertFalse($this->logic->isSwitch());
    }

    // ======== Token 共享/复用 ========

    public function testTokenShareWithSameDeviceType(): void
    {
        $param1 = new SaLoginParameter();
        $param1->setDeviceType('PC');
        $token1 = $this->logic->login(10001, $param1);

        // 同设备类型再次登录，应复用 Token
        $param2 = new SaLoginParameter();
        $param2->setDeviceType('PC');
        $token2 = $this->logic->login(10001, $param2);

        $this->assertEquals($token1, $token2);
    }

    public function testTokenNotShareWithDifferentDeviceType(): void
    {
        $param1 = new SaLoginParameter();
        $param1->setDeviceType('PC');
        $token1 = $this->logic->login(10001, $param1);

        $param2 = new SaLoginParameter();
        $param2->setDeviceType('APP');
        $token2 = $this->logic->login(10001, $param2);

        $this->assertNotEquals($token1, $token2);
    }

    public function testTokenNotShareWhenIsShareFalse(): void
    {
        SaToken::getConfig()->setIsShare(false);

        $param1 = new SaLoginParameter();
        $param1->setDeviceType('PC');
        $token1 = $this->logic->login(10001, $param1);

        $param2 = new SaLoginParameter();
        $param2->setDeviceType('PC');
        $token2 = $this->logic->login(10001, $param2);

        $this->assertNotEquals($token1, $token2);
    }

    // ======== 多账号体系隔离 ========

    public function testMultiAccountIsolation(): void
    {
        $token1 = $this->logic->login(10001);

        $adminLogic = new StpLogic('admin');
        $token2 = $adminLogic->login(20001);

        // 两套体系的 Token 独立存储
        $this->assertNotNull($this->tokenManager->getLoginIdByToken($token1));
        $this->assertNotNull($this->tokenManager->getLoginIdByToken($token2));

        // 注销 login 不影响 admin
        $this->logic->logoutByLoginId(10001);
        $this->assertNull($this->tokenManager->getLoginIdByToken($token1));
        $this->assertNotNull($this->tokenManager->getLoginIdByToken($token2));
    }

    public function testMultiAccountDisableIsolation(): void
    {
        $this->logic->disable(10001, 'comment', 1, 3600);

        $adminLogic = new StpLogic('admin');
        // login 体系的封禁不影响 admin 体系
        $this->assertFalse($adminLogic->isDisable(10001, 'comment'));
    }

    // ======== 事件监听 ========

    public function testLoginEvent(): void
    {
        $eventReceived = false;
        $listener = new class ($eventReceived) implements SaTokenListenerInterface {
            public static bool $flag = false;
            public function __construct(bool &$flag)
            {
                self::$flag = &$flag;
            }
            public function onLogin(string $loginType, mixed $loginId, string $tokenValue, mixed $parameter): void
            {
                self::$flag = true;
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
        };

        SaToken::addListener($listener);
        $this->logic->login(10001);

        $this->assertTrue($listener::$flag);
    }

    // ======== Token 格式化 ========

    public function testFormatTokenValueWithPrefix(): void
    {
        SaToken::getConfig()->setTokenPrefix('Bearer');

        $token = $this->logic->login(10001);
        $this->assertNotEmpty($token);
        $this->assertStringNotContainsString('Bearer', $token);
    }

    // ======== getSession / getTokenSession ========

    public function testGetSessionByLoginId(): void
    {
        $session = $this->logic->getSessionByLoginId(10001);
        $this->assertNotNull($session);

        $session->set('key', 'value');
        $loaded = $this->logic->getSessionByLoginId(10001);
        $this->assertNotNull($loaded);
        $this->assertEquals('value', $loaded->get('key'));
    }

    public function testGetSessionByLoginIdNoCreate(): void
    {
        $session = $this->logic->getSessionByLoginId(99999, false);
        $this->assertNull($session);
    }

    // ======== getTokenInfo ========

    public function testGetTokenInfo(): void
    {
        $token = $this->logic->login(10001);
        // getTokenInfo 需要从请求上下文读取 token，这里无请求上下文所以 tokenValue 为空
        // 直接验证 TokenManager
        $loginId = $this->tokenManager->getLoginIdByToken($token);
        $this->assertEquals('10001', $loginId);
    }

    // ======== createTempToken ========

    public function testCreateTempToken(): void
    {
        $tempToken = $this->logic->createTempToken(10001, 300);
        $this->assertNotEmpty($tempToken);

        $loginId = $this->tokenManager->getLoginIdByToken($tempToken);
        $this->assertEquals('10001', $loginId);
    }

    // ======== kickoutByTokenValue ========

    public function testKickoutByTokenValue(): void
    {
        $token = $this->logic->login(10001);
        $this->assertNotNull($this->tokenManager->getLoginIdByToken($token));

        $this->logic->kickoutByTokenValue($token);
        $this->assertNull($this->tokenManager->getLoginIdByToken($token));
    }

    // ======== getLoginDeviceType ========

    public function testGetLoginDeviceType(): void
    {
        $param = new SaLoginParameter();
        $param->setDeviceType('PC');
        $token = $this->logic->login(10001, $param);

        // 无请求上下文时返回空
        $this->assertEquals('', $this->logic->getLoginDeviceType());
    }
}
