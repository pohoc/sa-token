<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Action\SaTokenActionInterface;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\TokenManager;

class StpUtilTest extends TestCase
{
    protected SaTokenDaoMemory $dao;

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
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testLoginAndCheckLogin(): void
    {
        $token = StpUtil::login(10001);
        $this->assertNotEmpty($token);

        // 验证 token -> loginId 映射
        $loginId = $this->dao->get('satoken:login:token:' . $token);
        $this->assertEquals('10001', $loginId);
    }

    public function testLogout(): void
    {
        $token = StpUtil::login(10001);

        // 确认 token 存在
        $this->assertNotNull($this->dao->get('satoken:login:token:' . $token));

        StpUtil::logoutByLoginId(10001);

        // 验证 token 已删除
        $this->assertNull($this->dao->get('satoken:login:token:' . $token));
    }

    public function testKickout(): void
    {
        $token = StpUtil::login(10001);

        StpUtil::kickout(10001);

        $this->assertNull($this->dao->get('satoken:login:token:' . $token));
    }

    public function testMultiAccountSystem(): void
    {
        $token1 = StpUtil::login(10001);

        $adminLogic = SaToken::getStpLogic('admin');
        $token2 = $adminLogic->login(20001);

        // 两个体系的 token 独立
        $this->assertNotNull($this->dao->get('satoken:login:token:' . $token1));
        $this->assertNotNull($this->dao->get('satoken:login:token:' . $token2));

        // 注销 login 不影响 admin
        StpUtil::logoutByLoginId(10001);
        $this->assertNull($this->dao->get('satoken:login:token:' . $token1));
        $this->assertNotNull($this->dao->get('satoken:login:token:' . $token2));
    }

    public function testDisable(): void
    {
        StpUtil::disable(10001, 'comment', 1, 3600);

        $this->assertTrue(StpUtil::isDisable(10001, 'comment'));
        $this->assertEquals(1, StpUtil::getDisableLevel(10001, 'comment'));
    }

    public function testUntieDisable(): void
    {
        StpUtil::disable(10001, 'comment', 1, 3600);
        $this->assertTrue(StpUtil::isDisable(10001, 'comment'));

        StpUtil::untieDisable(10001, 'comment');
        $this->assertFalse(StpUtil::isDisable(10001, 'comment'));
    }

    public function testPermissionCheckWithToken(): void
    {
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return ['user:add', 'user:delete', 'user:view'];
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

        $token = StpUtil::login(10001);
        $logic = SaToken::getStpLogic('login');

        // 通过 TokenManager 直接操作来测试权限校验逻辑
        $loginId = $this->dao->get('satoken:login:token:' . $token);
        $this->assertEquals('10001', $loginId);

        // 直接测试权限获取
        $permissions = $logic->getPermissionList('10001');
        $this->assertEquals(['user:add', 'user:delete', 'user:view'], $permissions);

        $roles = $logic->getRoleList('10001');
        $this->assertEquals(['admin', 'user'], $roles);
    }

    public function testSaLoginParameter(): void
    {
        $param = new SaLoginParameter();
        $param->setDeviceType('PC')
            ->setIsLastingCookie(true)
            ->setTimeout(7200);

        $this->assertEquals('PC', $param->getDeviceType());
        $this->assertTrue($param->isLastingCookie());
        $this->assertEquals(7200, $param->getTimeout());
    }
}
