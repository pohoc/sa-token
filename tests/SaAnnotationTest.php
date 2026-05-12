<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Action\SaTokenActionInterface;
use SaToken\Annotation\SaAnnotationProcessor;
use SaToken\Annotation\SaCheckDisable;
use SaToken\Annotation\SaCheckLogin;
use SaToken\Annotation\SaCheckPermission;
use SaToken\Annotation\SaCheckRole;
use SaToken\Annotation\SaCheckSafe;
use SaToken\Annotation\SaIgnore;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\DisableServiceException;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotPermissionException;
use SaToken\Exception\NotRoleException;
use SaToken\Exception\NotSafeException;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\Util\SaTokenContext;

#[SaCheckLogin]
class SaAnnotationTestLoginController
{
    public function doSomething(): string
    {
        return 'done';
    }

    #[SaIgnore]
    public function publicAction(): string
    {
        return 'public';
    }
}

#[SaCheckLogin]
class SaAnnotationTestClassLevelController
{
    public function list(): string
    {
        return 'list';
    }

    public function detail(): string
    {
        return 'detail';
    }
}

class SaAnnotationTestPermissionAndController
{
    #[SaCheckPermission('user:add,user:delete', mode: 'AND')]
    public function manage(): string
    {
        return 'managed';
    }
}

class SaAnnotationTestPermissionOrController
{
    #[SaCheckPermission('user:add,user:delete', mode: 'OR')]
    public function manage(): string
    {
        return 'managed';
    }
}

class SaAnnotationTestRoleController
{
    #[SaCheckRole('admin,super', mode: 'AND')]
    public function adminPanel(): string
    {
        return 'admin';
    }
}

class SaAnnotationTestRoleOrController
{
    #[SaCheckRole('admin,super', mode: 'OR')]
    public function adminPanel(): string
    {
        return 'admin';
    }
}

class SaAnnotationTestSafeController
{
    #[SaCheckSafe('payment')]
    public function pay(): string
    {
        return 'paid';
    }
}

class SaAnnotationTestDisableController
{
    #[SaCheckDisable('comment')]
    public function comment(): string
    {
        return 'commented';
    }
}

#[SaCheckLogin(loginType: 'admin')]
class SaAnnotationTestCustomLoginTypeController
{
    public function dashboard(): string
    {
        return 'dashboard';
    }
}

#[SaIgnore]
class SaAnnotationTestIgnoreClassController
{
    public function anything(): string
    {
        return 'anything';
    }
}

class SaAnnotationTestMixedController
{
    #[SaCheckLogin]
    #[SaCheckPermission('user:view')]
    public function view(): string
    {
        return 'view';
    }
}

class SaAnnotationTest extends TestCase
{
    protected StpLogic $logic;

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

        $this->logic = new StpLogic('login');
    }

    protected function tearDown(): void
    {
        SaTokenContext::clear();
        SaToken::reset();
    }

    private function loginAndGetToken(mixed $loginId = 10001, string $loginType = 'login'): string
    {
        $stpLogic = SaToken::getStpLogic($loginType);
        $token = $stpLogic->login($loginId);
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->with('satoken')->willReturn([$token]);
        SaTokenContext::setRequest($request);
        return $token;
    }

    /**
     * @param array<string> $permissions
     * @param array<string> $roles
     */
    private function setActionWithPermissions(array $permissions = [], array $roles = []): void
    {
        SaToken::setAction(new class ($permissions, $roles) implements SaTokenActionInterface {
            /** @var array<string> */
            private array $permissions;
            /** @var array<string> */
            private array $roles;

            /**
             * @param array<string> $permissions
             * @param array<string> $roles
             */
            public function __construct(array $permissions, array $roles)
            {
                $this->permissions = $permissions;
                $this->roles = $roles;
            }

            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return $this->permissions;
            }

            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return $this->roles;
            }

            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });
    }

    public function testSaCheckLoginAttributeThrowsWhenNotLoggedIn(): void
    {
        $this->expectException(NotLoginException::class);
        SaAnnotationProcessor::process(SaAnnotationTestLoginController::class, 'doSomething');
    }

    public function testSaCheckLoginAttributePassesWhenLoggedIn(): void
    {
        $this->loginAndGetToken();
        SaAnnotationProcessor::process(SaAnnotationTestLoginController::class, 'doSomething');
        $this->assertTrue(true);
    }

    public function testSaCheckPermissionAndModePasses(): void
    {
        $this->setActionWithPermissions(['user:add', 'user:delete', 'user:view']);
        $this->loginAndGetToken();
        SaAnnotationProcessor::process(SaAnnotationTestPermissionAndController::class, 'manage');
        $this->assertTrue(true);
    }

    public function testSaCheckPermissionAndModeFails(): void
    {
        $this->setActionWithPermissions(['user:add']);
        $this->loginAndGetToken();
        $this->expectException(NotPermissionException::class);
        SaAnnotationProcessor::process(SaAnnotationTestPermissionAndController::class, 'manage');
    }

    public function testSaCheckPermissionOrModePasses(): void
    {
        $this->setActionWithPermissions(['user:add']);
        $this->loginAndGetToken();
        SaAnnotationProcessor::process(SaAnnotationTestPermissionOrController::class, 'manage');
        $this->assertTrue(true);
    }

    public function testSaCheckPermissionOrModeFails(): void
    {
        $this->setActionWithPermissions(['user:view']);
        $this->loginAndGetToken();
        $this->expectException(NotPermissionException::class);
        SaAnnotationProcessor::process(SaAnnotationTestPermissionOrController::class, 'manage');
    }

    public function testSaCheckRoleAttributeAndModePasses(): void
    {
        $this->setActionWithPermissions([], ['admin', 'super', 'user']);
        $this->loginAndGetToken();
        SaAnnotationProcessor::process(SaAnnotationTestRoleController::class, 'adminPanel');
        $this->assertTrue(true);
    }

    public function testSaCheckRoleAttributeAndModeFails(): void
    {
        $this->setActionWithPermissions([], ['admin']);
        $this->loginAndGetToken();
        $this->expectException(NotRoleException::class);
        SaAnnotationProcessor::process(SaAnnotationTestRoleController::class, 'adminPanel');
    }

    public function testSaCheckRoleAttributeOrModePasses(): void
    {
        $this->setActionWithPermissions([], ['admin']);
        $this->loginAndGetToken();
        SaAnnotationProcessor::process(SaAnnotationTestRoleOrController::class, 'adminPanel');
        $this->assertTrue(true);
    }

    public function testSaCheckRoleAttributeOrModeFails(): void
    {
        $this->setActionWithPermissions([], ['user']);
        $this->loginAndGetToken();
        $this->expectException(NotRoleException::class);
        SaAnnotationProcessor::process(SaAnnotationTestRoleOrController::class, 'adminPanel');
    }

    public function testSaCheckSafeAttributeThrowsWhenNotInSafeWindow(): void
    {
        $this->loginAndGetToken();
        $this->expectException(NotSafeException::class);
        SaAnnotationProcessor::process(SaAnnotationTestSafeController::class, 'pay');
    }

    public function testSaCheckSafeAttributePassesWhenInSafeWindow(): void
    {
        $this->loginAndGetToken();
        $this->logic->openSafe(300, 'payment');
        SaAnnotationProcessor::process(SaAnnotationTestSafeController::class, 'pay');
        $this->assertTrue(true);
    }

    public function testSaIgnoreSkipsCheck(): void
    {
        SaAnnotationProcessor::process(SaAnnotationTestLoginController::class, 'publicAction');
        $this->assertTrue(true);
    }

    public function testSaIgnoreOnClassSkipsAllChecks(): void
    {
        SaAnnotationProcessor::process(SaAnnotationTestIgnoreClassController::class, 'anything');
        $this->assertTrue(true);
    }

    public function testClassLevelAttributeAppliesToAllMethods(): void
    {
        $this->expectException(NotLoginException::class);
        SaAnnotationProcessor::process(SaAnnotationTestClassLevelController::class, 'list');
    }

    public function testClassLevelAttributeAppliesToSecondMethod(): void
    {
        $this->expectException(NotLoginException::class);
        SaAnnotationProcessor::process(SaAnnotationTestClassLevelController::class, 'detail');
    }

    public function testClassLevelAttributePassesWhenLoggedIn(): void
    {
        $this->loginAndGetToken();
        SaAnnotationProcessor::process(SaAnnotationTestClassLevelController::class, 'list');
        $this->assertTrue(true);
    }

    public function testCustomLoginType(): void
    {
        $this->expectException(NotLoginException::class);
        SaAnnotationProcessor::process(SaAnnotationTestCustomLoginTypeController::class, 'dashboard');
    }

    public function testCustomLoginTypePassesWhenLoggedIn(): void
    {
        $this->loginAndGetToken(10001, 'admin');
        SaAnnotationProcessor::process(SaAnnotationTestCustomLoginTypeController::class, 'dashboard');
        $this->assertTrue(true);
    }

    public function testSaCheckDisableThrowsWhenDisabled(): void
    {
        $this->loginAndGetToken();
        $this->logic->disable(10001, 'comment', 1, 3600);
        $this->expectException(DisableServiceException::class);
        SaAnnotationProcessor::process(SaAnnotationTestDisableController::class, 'comment');
    }

    public function testSaCheckDisablePassesWhenNotDisabled(): void
    {
        $this->loginAndGetToken();
        SaAnnotationProcessor::process(SaAnnotationTestDisableController::class, 'comment');
        $this->assertTrue(true);
    }

    public function testSaCheckDisableSkipsWhenNotLoggedIn(): void
    {
        SaAnnotationProcessor::process(SaAnnotationTestDisableController::class, 'comment');
        $this->assertTrue(true);
    }

    public function testGetMethodAttributesReturnsAttributeInstances(): void
    {
        $attrs = SaAnnotationProcessor::getMethodAttributes(SaAnnotationTestLoginController::class, 'doSomething');
        $this->assertCount(1, $attrs);
        $this->assertInstanceOf(SaCheckLogin::class, $attrs[0]);
    }

    public function testGetMethodAttributesReturnsEmptyForNoAttributes(): void
    {
        $attrs = SaAnnotationProcessor::getMethodAttributes(SaAnnotationTestMixedController::class, 'view');
        $this->assertNotEmpty($attrs);
        $hasLogin = false;
        $hasPermission = false;
        foreach ($attrs as $attr) {
            if ($attr instanceof SaCheckLogin) {
                $hasLogin = true;
            }
            if ($attr instanceof SaCheckPermission) {
                $hasPermission = true;
            }
        }
        $this->assertTrue($hasLogin);
        $this->assertTrue($hasPermission);
    }

    public function testGetMethodAttributesIncludesClassLevel(): void
    {
        $attrs = SaAnnotationProcessor::getMethodAttributes(SaAnnotationTestLoginController::class, 'publicAction');
        $hasIgnore = false;
        $hasLogin = false;
        foreach ($attrs as $attr) {
            if ($attr instanceof SaIgnore) {
                $hasIgnore = true;
            }
            if ($attr instanceof SaCheckLogin) {
                $hasLogin = true;
            }
        }
        $this->assertTrue($hasIgnore);
        $this->assertTrue($hasLogin);
    }

    public function testGetMethodAttributesPermissionDetails(): void
    {
        $attrs = SaAnnotationProcessor::getMethodAttributes(SaAnnotationTestPermissionAndController::class, 'manage');
        $this->assertCount(1, $attrs);
        $this->assertInstanceOf(SaCheckPermission::class, $attrs[0]);
        $this->assertEquals('user:add,user:delete', $attrs[0]->getValue());
        $this->assertEquals('AND', $attrs[0]->getMode());
    }

    public function testGetMethodAttributesSafeDetails(): void
    {
        $attrs = SaAnnotationProcessor::getMethodAttributes(SaAnnotationTestSafeController::class, 'pay');
        $this->assertCount(1, $attrs);
        $this->assertInstanceOf(SaCheckSafe::class, $attrs[0]);
        $this->assertEquals('payment', $attrs[0]->getService());
    }

    public function testGetMethodAttributesCustomLoginType(): void
    {
        $attrs = SaAnnotationProcessor::getMethodAttributes(SaAnnotationTestCustomLoginTypeController::class, 'dashboard');
        $this->assertCount(1, $attrs);
        $this->assertInstanceOf(SaCheckLogin::class, $attrs[0]);
        $this->assertEquals('admin', $attrs[0]->getLoginType());
    }
}
