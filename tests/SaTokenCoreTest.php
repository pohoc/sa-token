<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Action\SaTokenActionInterface;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Listener\SaTokenListenerInterface;
use SaToken\SaToken;

class SaTokenCoreTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    // ---- init ----

    public function testInitWithArray(): void
    {
        SaToken::init(['tokenName' => 'my-token', 'timeout' => 7200]);
        $this->assertTrue(SaToken::isInitialized());
        $this->assertEquals('my-token', SaToken::getConfig()->getTokenName());
        $this->assertEquals(7200, SaToken::getConfig()->getTimeout());
    }

    public function testInitWithConfigObject(): void
    {
        $config = new SaTokenConfig(['tokenName' => 'obj-token']);
        SaToken::init($config);
        $this->assertEquals('obj-token', SaToken::getConfig()->getTokenName());
    }

    public function testInitAutoLoadsConfigFile(): void
    {
        SaToken::init();
        $this->assertTrue(SaToken::isInitialized());
        // 自动加载 config/sa_token.php
        $this->assertInstanceOf(SaTokenConfig::class, SaToken::getConfig());
    }

    public function testIsInitializedBeforeInit(): void
    {
        $this->assertFalse(SaToken::isInitialized());
    }

    // ---- setConfig / getConfig ----

    public function testSetAndGetConfig(): void
    {
        $config = new SaTokenConfig(['tokenName' => 'test-token']);
        SaToken::setConfig($config);
        $this->assertSame($config, SaToken::getConfig());
    }

    public function testGetConfigLazyInit(): void
    {
        // 未手动 init 时，getConfig 会自动 init
        $config = SaToken::getConfig();
        $this->assertInstanceOf(SaTokenConfig::class, $config);
        $this->assertTrue(SaToken::isInitialized());
    }

    // ---- setDao / getDao ----

    public function testSetAndGetDao(): void
    {
        $dao = new SaTokenDaoMemory();
        SaToken::setDao($dao);
        $this->assertSame($dao, SaToken::getDao());
    }

    public function testGetDaoDefault(): void
    {
        $dao = SaToken::getDao();
        $this->assertInstanceOf(SaTokenDaoMemory::class, $dao);
    }

    public function testGetDaoReturnsSameInstance(): void
    {
        $dao1 = SaToken::getDao();
        $dao2 = SaToken::getDao();
        $this->assertSame($dao1, $dao2);
    }

    // ---- getStpLogic / registerStpLogic ----

    public function testGetStpLogicDefault(): void
    {
        $logic = SaToken::getStpLogic('login');
        $this->assertEquals('login', $logic->getLoginType());
    }

    public function testGetStpLogicSameInstance(): void
    {
        $logic1 = SaToken::getStpLogic('login');
        $logic2 = SaToken::getStpLogic('login');
        $this->assertSame($logic1, $logic2);
    }

    public function testGetStpLogicDifferentTypes(): void
    {
        $login = SaToken::getStpLogic('login');
        $admin = SaToken::getStpLogic('admin');
        $this->assertNotSame($login, $admin);
        $this->assertEquals('login', $login->getLoginType());
        $this->assertEquals('admin', $admin->getLoginType());
    }

    public function testRegisterStpLogic(): void
    {
        $config = new SaTokenConfig(['isReadHeader' => false, 'isReadCookie' => false, 'isReadBody' => false, 'isWriteCookie' => false, 'isWriteHeader' => false]);
        SaToken::setConfig($config);
        SaToken::setDao(new SaTokenDaoMemory());

        $customLogic = new \SaToken\StpLogic('custom');
        SaToken::registerStpLogic($customLogic);

        $retrieved = SaToken::getStpLogic('custom');
        $this->assertSame($customLogic, $retrieved);
    }

    // ---- setAction / getAction ----

    public function testSetAndGetAction(): void
    {
        $action = new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }
        };
        SaToken::setAction($action);
        $this->assertSame($action, SaToken::getAction());
    }

    public function testGetActionDefaultNull(): void
    {
        $this->assertNull(SaToken::getAction());
    }

    // ---- addListener ----

    public function testAddListener(): void
    {
        $listener = new class () implements SaTokenListenerInterface {
            public function onLogin(string $loginType, mixed $loginId, string $tokenValue, mixed $parameter): void
            {
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
        $this->assertCount(1, SaToken::getEvent()->getListeners());
    }

    // ---- reset ----

    public function testResetClearsAllState(): void
    {
        SaToken::setConfig(new SaTokenConfig());
        SaToken::setDao(new SaTokenDaoMemory());
        SaToken::setAction(new class () implements SaTokenActionInterface {
            public function getPermissionList(mixed $loginId, string $loginType): array
            {
                return [];
            }
            public function getRoleList(mixed $loginId, string $loginType): array
            {
                return [];
            }
        });
        SaToken::getStpLogic('login');

        SaToken::reset();

        $this->assertFalse(SaToken::isInitialized());
        $this->assertNull(SaToken::getAction());
        // getDao 会重新创建默认 MemoryDao
        $this->assertInstanceOf(SaTokenDaoMemory::class, SaToken::getDao());
    }
}
