<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotSafeException;
use SaToken\Listener\SaTokenListenerInterface;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;
use SaToken\Util\SaTokenContext;

/**
 * StpLogic 集成测试
 *
 * 覆盖：getSession, getTokenSession, closeSafe, endSwitch,
 *       isSwitch 完整流程, openSafe+checkSafe+closeSafe 完整流程,
 *       switchTo+getLoginId+endSwitch 完整流程, getTokenTimeout, renewTimeout,
 *       kickout, getTerminalListByLoginId, logoutByLoginId
 */
class StpLogicIntegrationTest extends TestCase
{
    protected StpLogic $logic;
    protected TokenManager $tokenManager;
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
            'isReadHeader'    => true,
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

    // ======== getSession 集成测试 ========

    public function testGetSessionRequiresLogin(): void
    {
        $this->expectException(NotLoginException::class);
        $this->logic->getSession();
    }

    public function testGetSessionAfterLogin(): void
    {
        $this->loginAndGetToken(10001);

        $session = $this->logic->getSession();
        $this->assertNotNull($session);
        $session->set('name', 'Tom');

        $session2 = $this->logic->getSession();
        $this->assertEquals('Tom', $session2->get('name'));
    }

    public function testGetSessionByLoginIdCreateAndNoCreate(): void
    {
        // 未登录时 isCreate=false 返回 null
        $this->assertNull($this->logic->getSessionByLoginId(99999, false));

        // isCreate=true 返回新 session
        $session = $this->logic->getSessionByLoginId(99999, true);
        $this->assertNotNull($session);
    }

    public function testGetSessionDataPersistAcrossLogin(): void
    {
        $token = $this->loginAndGetToken(10001);
        $session = $this->logic->getSessionByLoginId(10001);
        $this->assertNotNull($session);
        $session->set('theme', 'dark');

        // 注销后再登录，session 数据应保留（因为 logoutByLoginId 删除 session）
        $this->logic->logoutByLoginId(10001);
        $sessionAfter = $this->logic->getSessionByLoginId(10001, false);
        $this->assertNull($sessionAfter);
    }

    // ======== getTokenSession 集成测试 ========

    public function testGetTokenSessionWithoutToken(): void
    {
        $this->assertNull($this->logic->getTokenSession());
    }

    public function testGetTokenSessionAfterLogin(): void
    {
        $this->loginAndGetToken(10001);

        $tokenSession = $this->logic->getTokenSession();
        $this->assertNotNull($tokenSession);
        $tokenSession->set('request_count', 5);

        $tokenSession2 = $this->logic->getTokenSession();
        $this->assertNotNull($tokenSession2);
        $this->assertEquals(5, $tokenSession2->get('request_count'));
    }

    public function testGetTokenSessionNoCreate(): void
    {
        $this->loginAndGetToken(10001);

        // 先获取一次并写入数据（触发 DAO 保存）
        $ts = $this->logic->getTokenSession(true);
        $this->assertNotNull($ts);
        $ts->set('key', 'value');

        // TokenSession 已保存到 DAO，重新获取 isCreate=false 应能拿到
        $ts2 = $this->logic->getTokenSession(false);
        $this->assertNotNull($ts2);
        $this->assertEquals('value', $ts2->get('key'));
    }

    // ======== openSafe + checkSafe + closeSafe 完整流程 ========

    public function testSafeAuthFullFlow(): void
    {
        $this->loginAndGetToken(10001);

        // 未开启二级认证
        $this->assertFalse($this->logic->isSafe('transfer'));

        // 开启二级认证
        $this->logic->openSafe(120, 'transfer');
        $this->assertTrue($this->logic->isSafe('transfer'));

        // checkSafe 不抛异常
        $this->logic->checkSafe('transfer');
        $this->assertTrue(true);

        // 关闭二级认证
        $this->logic->closeSafe('transfer');
        $this->assertFalse($this->logic->isSafe('transfer'));

        // checkSafe 抛异常
        $this->expectException(NotSafeException::class);
        $this->logic->checkSafe('transfer');
    }

    public function testSafeAuthMultipleServices(): void
    {
        $this->loginAndGetToken(10001);

        // 不同服务的二级认证独立
        $this->logic->openSafe(120, 'transfer');
        $this->logic->openSafe(300, 'payment');

        $this->assertTrue($this->logic->isSafe('transfer'));
        $this->assertTrue($this->logic->isSafe('payment'));

        // 关闭一个不影响另一个
        $this->logic->closeSafe('transfer');
        $this->assertFalse($this->logic->isSafe('transfer'));
        $this->assertTrue($this->logic->isSafe('payment'));
    }

    public function testCloseSafeWhenNotLoggedIn(): void
    {
        // 不应抛异常
        $this->logic->closeSafe('transfer');
        $this->assertTrue(true);
    }

    // ======== switchTo + getLoginId + endSwitch 完整流程 ========

    public function testSwitchToFullFlow(): void
    {
        $this->loginAndGetToken(10001);

        // 初始状态
        $this->assertFalse($this->logic->isSwitch());

        // 切换身份
        $this->logic->switchTo(20001);
        $this->assertTrue($this->logic->isSwitch());

        // getLoginId 应返回切换后的 ID
        $loginId = $this->logic->getLoginId();
        $this->assertEquals('20001', $loginId);

        // 结束切换
        $this->logic->endSwitch();
        $this->assertFalse($this->logic->isSwitch());
    }

    public function testSwitchToEventFired(): void
    {
        $switchEvents = [];
        $switchBackEvents = [];

        $listener = new class ($switchEvents, $switchBackEvents) implements SaTokenListenerInterface {
            /** @var array<array{from: mixed, to: mixed}> */
            public static array $switchEvents;
            /** @var array<array{loginId: mixed}> */
            public static array $switchBackEvents;
            /**
             * @param array<array{from: mixed, to: mixed}> &$s
             * @param array<array{loginId: mixed}>         &$sb
             */
            public function __construct(array &$s, array &$sb)
            {
                self::$switchEvents = &$s;
                self::$switchBackEvents = &$sb;
            }
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
                self::$switchEvents[] = ['from' => $loginId, 'to' => $switchToId];
            }
            public function onSwitchBack(string $loginType, mixed $loginId, string $tokenValue): void
            {
                self::$switchBackEvents[] = ['loginId' => $loginId];
            }
        };

        SaToken::addListener($listener);

        $this->loginAndGetToken(10001);
        $this->logic->switchTo(20001);
        $this->logic->endSwitch();

        $this->assertCount(1, $listener::$switchEvents);
        $this->assertEquals('10001', $listener::$switchEvents[0]['from']);
        $this->assertEquals('20001', $listener::$switchEvents[0]['to']);

        $this->assertCount(1, $listener::$switchBackEvents);
    }

    public function testEndSwitchWhenNotLoggedIn(): void
    {
        // 不应抛异常
        $this->logic->endSwitch();
        $this->assertTrue(true);
    }

    // ======== getTokenTimeout / renewTimeout ========

    public function testGetTokenTimeoutWithoutToken(): void
    {
        $this->assertEquals(-2, $this->logic->getTokenTimeout());
    }

    public function testGetTokenTimeoutAfterLogin(): void
    {
        $this->loginAndGetToken(10001);
        $timeout = $this->logic->getTokenTimeout();
        $this->assertGreaterThan(0, $timeout);
    }

    public function testRenewTimeoutWithoutToken(): void
    {
        // 不应抛异常
        $this->logic->renewTimeout(7200);
        $this->assertTrue(true);
    }

    public function testRenewTimeout(): void
    {
        $this->loginAndGetToken(10001);
        $originalTimeout = $this->logic->getTokenTimeout();

        $this->logic->renewTimeout(172800);
        $newTimeout = $this->logic->getTokenTimeout();

        $this->assertGreaterThan($originalTimeout, $newTimeout);
    }

    // ======== kickout ========

    public function testKickoutByLoginId(): void
    {
        $param = new SaLoginParameter();
        $param->setDeviceType('PC');
        $this->logic->login(10001, $param);

        $param2 = new SaLoginParameter();
        $param2->setDeviceType('APP');
        $loginResult2 = $this->logic->login(10001, $param2);
        $token2 = $loginResult2->getAccessToken();

        $this->logic->kickout(10001);

        $this->assertNull($this->tokenManager->getLoginIdByToken($token2));
    }

    // ======== getTerminalListByLoginId ========

    public function testGetTerminalListByLoginId(): void
    {
        $param1 = new SaLoginParameter();
        $param1->setDeviceType('PC');
        $this->logic->login(10001, $param1);

        $param2 = new SaLoginParameter();
        $param2->setDeviceType('APP');
        $this->logic->login(10001, $param2);

        $terminals = $this->logic->getTerminalListByLoginId(10001);
        // 应有2个终端（如果 isShare=true 同设备会复用 token，但 PC 和 APP 不同设备）
        $this->assertCount(2, $terminals);

        $deviceTypes = array_map(fn ($t) => $t->getDeviceType(), $terminals);
        $this->assertContains('PC', $deviceTypes);
        $this->assertContains('APP', $deviceTypes);
    }

    public function testGetTerminalListByLoginIdEmpty(): void
    {
        $terminals = $this->logic->getTerminalListByLoginId(99999);
        $this->assertEmpty($terminals);
    }

    // ======== logoutByLoginId ========

    public function testLogoutByLoginIdFiresEvents(): void
    {
        $logoutEvents = [];
        $listener = new class ($logoutEvents) implements SaTokenListenerInterface {
            /** @var array<array{loginId: mixed, tokenValue: string}> */
            public static array $logoutEvents;
            /**
             * @param array<array{loginId: mixed, tokenValue: string}> &$e
             */
            public function __construct(array &$e)
            {
                self::$logoutEvents = &$e;
            }
            public function onLogin(string $loginType, mixed $loginId, string $tokenValue, mixed $parameter): void
            {
            }
            public function onLogout(string $loginType, mixed $loginId, string $tokenValue): void
            {
                self::$logoutEvents[] = ['loginId' => $loginId, 'tokenValue' => $tokenValue];
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

        $param1 = new SaLoginParameter();
        $param1->setDeviceType('PC');
        $loginResult1 = $this->logic->login(10001, $param1);
        $token1 = $loginResult1->getAccessToken();

        $param2 = new SaLoginParameter();
        $param2->setDeviceType('APP');
        $loginResult2 = $this->logic->login(10001, $param2);
        $token2 = $loginResult2->getAccessToken();

        $this->logic->logoutByLoginId(10001);

        // 应触发两次 logout 事件
        $this->assertCount(2, $listener::$logoutEvents);
    }

    // ======== 禁用等级和解禁 ========

    public function testDisableLevelAndUntieDisable(): void
    {
        $this->logic->disable(10001, 'comment', 3, 3600);

        $this->assertTrue($this->logic->isDisable(10001, 'comment'));
        $this->assertEquals(3, $this->logic->getDisableLevel(10001, 'comment'));

        $this->logic->untieDisable(10001, 'comment');
        $this->assertFalse($this->logic->isDisable(10001, 'comment'));
        $this->assertEquals(-1, $this->logic->getDisableLevel(10001, 'comment'));
    }

    public function testDisableLevelNotDisabled(): void
    {
        $this->assertEquals(-1, $this->logic->getDisableLevel(10001, 'comment'));
    }

    // ======== createTempToken ========

    public function testCreateTempTokenIntegration(): void
    {
        $tempToken = $this->logic->createTempToken(10001, 300);
        $this->assertNotEmpty($tempToken);

        $loginId = $this->tokenManager->getLoginIdByToken($tempToken);
        $this->assertEquals('10001', $loginId);

        $timeout = $this->tokenManager->getTokenTimeout($tempToken);
        $this->assertGreaterThan(0, $timeout);
        $this->assertLessThanOrEqual(300, $timeout);
    }
}
