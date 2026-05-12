<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;

class StpLogicTest extends TestCase
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

    public function testSafeAuth(): void
    {
        $loginResult = $this->logic->login(10001);
        $token = $loginResult->getAccessToken();

        $this->assertFalse($this->tokenManager->isSafe($token, 'default', 'login'));

        // 开启安全窗口
        $this->tokenManager->openSafe($token, 'transfer', 120, 'login');
        $this->assertTrue($this->tokenManager->isSafe($token, 'transfer', 'login'));
        $this->assertFalse($this->tokenManager->isSafe($token, 'default', 'login'));

        // 关闭安全窗口
        $this->tokenManager->closeSafe($token, 'transfer', 'login');
        $this->assertFalse($this->tokenManager->isSafe($token, 'transfer', 'login'));
    }

    public function testSwitchTo(): void
    {
        $loginResult = $this->logic->login(10001);
        $token = $loginResult->getAccessToken();

        $this->tokenManager->setSwitchTo($token, 20001, 'login');
        $this->assertEquals('20001', $this->tokenManager->getSwitchTo($token, 'login'));

        // 结束切换
        $this->tokenManager->clearSwitch($token, 'login');
        $this->assertNull($this->tokenManager->getSwitchTo($token, 'login'));
    }

    public function testDisableWithLevel(): void
    {
        $this->logic->disable(10001, 'comment', 2, 3600);

        $this->assertTrue($this->logic->isDisable(10001, 'comment'));
        $this->assertEquals(2, $this->logic->getDisableLevel(10001, 'comment'));

        // 不同服务独立
        $this->assertFalse($this->logic->isDisable(10001, 'login'));
    }

    public function testLoginWithDeviceType(): void
    {
        $param = new SaLoginParameter();
        $param->setDeviceType('PC');

        $loginResult = $this->logic->login(10001, $param);
        $token = $loginResult->getAccessToken();

        $terminals = $this->logic->getTerminalListByLoginId(10001);
        $this->assertCount(1, $terminals);
        $this->assertEquals('PC', $terminals[0]->getDeviceType());
    }

    public function testConcurrentLogin(): void
    {
        $param1 = new SaLoginParameter();
        $param1->setDeviceType('PC');
        $loginResult1 = $this->logic->login(10001, $param1);
        $token1 = $loginResult1->getAccessToken();

        $param2 = new SaLoginParameter();
        $param2->setDeviceType('APP');
        $loginResult2 = $this->logic->login(10001, $param2);
        $token2 = $loginResult2->getAccessToken();

        $terminals = $this->logic->getTerminalListByLoginId(10001);
        $this->assertCount(2, $terminals);
    }

    public function testMaxLoginCount(): void
    {
        SaToken::getConfig()->setMaxLoginCount(2);

        $param1 = new SaLoginParameter();
        $param1->setDeviceType('PC');
        $this->logic->login(10001, $param1);

        $param2 = new SaLoginParameter();
        $param2->setDeviceType('APP');
        $this->logic->login(10001, $param2);

        $param3 = new SaLoginParameter();
        $param3->setDeviceType('MINI');
        $this->logic->login(10001, $param3);

        $terminals = $this->logic->getTerminalListByLoginId(10001);
        $this->assertCount(2, $terminals);
    }

    public function testCreateTempToken(): void
    {
        $tempToken = $this->logic->createTempToken(10001, 300);

        $loginId = $this->tokenManager->getLoginIdByToken($tempToken);
        $this->assertEquals('10001', $loginId);
    }
}
