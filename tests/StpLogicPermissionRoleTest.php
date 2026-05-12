<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Action\SaTokenActionInterface;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotPermissionException;
use SaToken\Exception\NotRoleException;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;
use SaToken\Util\SaTokenContext;

/**
 * StpLogic 权限/角色校验完整测试
 *
 * 覆盖：checkPermission, checkPermissionOr, checkPermissionAnd,
 *       hasPermission, checkRole, checkRoleOr, checkRoleAnd, hasRole
 */
class StpLogicPermissionRoleTest extends TestCase
{
    protected StpLogic $logic;
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
            'isReadHeader'    => true,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        SaToken::setDao(new SaTokenDaoMemory());

        $this->logic = new StpLogic('login');
        $this->tokenManager = new TokenManager();
    }

    protected function tearDown(): void
    {
        SaTokenContext::clear();
        SaToken::reset();
    }

    private function loginAndGetToken(mixed $loginId = 10001): string
    {
        $loginResult = $this->logic->login($loginId);
        $token = $loginResult->getAccessToken();
        // 将 token 注入请求上下文
        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $request->method('getHeader')->with('satoken')->willReturn([$token]);
        SaTokenContext::setRequest($request);
        return $token;
    }

    // ======== checkPermission ========

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

        $this->loginAndGetToken();
        // 不抛异常即成功
        $this->logic->checkPermission('user:add');
        $this->assertTrue(true);
    }

    public function testCheckPermissionFail(): void
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

        $this->loginAndGetToken();
        $this->expectException(NotPermissionException::class);
        $this->logic->checkPermission('user:delete');
    }

    public function testCheckPermissionNotLoggedIn(): void
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

        $this->expectException(NotLoginException::class);
        $this->logic->checkPermission('user:add');
    }

    // ======== checkPermissionOr ========

    public function testCheckPermissionOrAnyMatch(): void
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

        $this->loginAndGetToken();
        // user:view 在列表中，满足任一
        $this->logic->checkPermissionOr(['user:add', 'user:view', 'user:delete']);
        $this->assertTrue(true);
    }

    public function testCheckPermissionOrNoneMatch(): void
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

        $this->loginAndGetToken();
        $this->expectException(NotPermissionException::class);
        $this->logic->checkPermissionOr(['user:add', 'user:delete']);
    }

    public function testCheckPermissionOrNotLoggedIn(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
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

        $this->expectException(NotLoginException::class);
        $this->logic->checkPermissionOr(['user:add']);
    }

    // ======== checkPermissionAnd ========

    public function testCheckPermissionAndAllMatch(): void
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

        $this->loginAndGetToken();
        $this->logic->checkPermissionAnd(['user:add', 'user:delete']);
        $this->assertTrue(true);
    }

    public function testCheckPermissionAndPartialMatch(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return ['user:add', 'user:view'];
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

        $this->loginAndGetToken();
        $this->expectException(NotPermissionException::class);
        $this->logic->checkPermissionAnd(['user:add', 'user:delete']);
    }

    public function testCheckPermissionAndNoneMatch(): void
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

        $this->loginAndGetToken();
        $this->expectException(NotPermissionException::class);
        $this->logic->checkPermissionAnd(['user:add', 'user:delete']);
    }

    public function testCheckPermissionAndNotLoggedIn(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
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

        $this->expectException(NotLoginException::class);
        $this->logic->checkPermissionAnd(['user:add']);
    }

    // ======== hasPermission ========

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

        $this->loginAndGetToken();
        $this->assertTrue($this->logic->hasPermission('user:add'));
    }

    public function testHasPermissionFalse(): void
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

        $this->loginAndGetToken();
        $this->assertFalse($this->logic->hasPermission('user:add'));
    }

    public function testHasPermissionNotLoggedIn(): void
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

        $this->assertFalse($this->logic->hasPermission('user:add'));
    }

    // ======== checkRole ========

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

        $this->loginAndGetToken();
        $this->logic->checkRole('admin');
        $this->assertTrue(true);
    }

    public function testCheckRoleFail(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['user'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $this->loginAndGetToken();
        $this->expectException(NotRoleException::class);
        $this->logic->checkRole('admin');
    }

    public function testCheckRoleNotLoggedIn(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['admin'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $this->expectException(NotLoginException::class);
        $this->logic->checkRole('admin');
    }

    // ======== checkRoleOr ========

    public function testCheckRoleOrAnyMatch(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['user'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $this->loginAndGetToken();
        $this->logic->checkRoleOr(['admin', 'user', 'super']);
        $this->assertTrue(true);
    }

    public function testCheckRoleOrNoneMatch(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['guest'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $this->loginAndGetToken();
        $this->expectException(NotRoleException::class);
        $this->logic->checkRoleOr(['admin', 'super']);
    }

    // ======== checkRoleAnd ========

    public function testCheckRoleAndAllMatch(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['admin', 'user', 'super'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $this->loginAndGetToken();
        $this->logic->checkRoleAnd(['admin', 'user']);
        $this->assertTrue(true);
    }

    public function testCheckRoleAndPartialMatch(): void
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

        $this->loginAndGetToken();
        $this->expectException(NotRoleException::class);
        $this->logic->checkRoleAnd(['admin', 'super']);
    }

    // ======== hasRole ========

    public function testHasRoleTrue(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['admin'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $this->loginAndGetToken();
        $this->assertTrue($this->logic->hasRole('admin'));
    }

    public function testHasRoleFalse(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['user'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $this->loginAndGetToken();
        $this->assertFalse($this->logic->hasRole('admin'));
    }

    public function testHasRoleNotLoggedIn(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return ['admin'];
            }
            public function generateTokenValue(mixed $loginId, string $loginType): ?string
            {
                return null;
            }
        });

        $this->assertFalse($this->logic->hasRole('admin'));
    }

    // ======== 异常消息验证 ========

    public function testCheckPermissionExceptionContainsPermissionCode(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
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

        $this->loginAndGetToken();
        try {
            $this->logic->checkPermission('user:delete');
            $this->fail('Expected NotPermissionException');
        } catch (NotPermissionException $e) {
            $this->assertStringContainsString('user:delete', $e->getMessage());
        }
    }

    public function testCheckPermissionOrExceptionContainsAllCodes(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
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

        $this->loginAndGetToken();
        try {
            $this->logic->checkPermissionOr(['user:add', 'user:delete']);
            $this->fail('Expected NotPermissionException');
        } catch (NotPermissionException $e) {
            $this->assertStringContainsString('user:add', $e->getMessage());
            $this->assertStringContainsString('user:delete', $e->getMessage());
        }
    }

    public function testCheckRoleExceptionContainsRoleCode(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
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

        $this->loginAndGetToken();
        try {
            $this->logic->checkRole('super');
            $this->fail('Expected NotRoleException');
        } catch (NotRoleException $e) {
            $this->assertStringContainsString('super', $e->getMessage());
        }
    }
}
