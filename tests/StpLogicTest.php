<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;
use SaToken\Util\SaTokenContext;

class SaTokenContextParameterBagStub
{
    /** @param array<string, string> $values */
    public function __construct(private array $values)
    {
    }

    /** @return array<string, string> */
    public function all(): array
    {
        return $this->values;
    }
}

class SaTokenContextFrameworkRequestStub
{
    public function __construct(
        public SaTokenContextParameterBagStub $query,
        public SaTokenContextParameterBagStub $request
    ) {
    }

    public function input(string $name): ?string
    {
        return $this->request->all()[$name] ?? $this->query->all()[$name] ?? null;
    }

    public function header(string $name): string
    {
        return '';
    }

    public function getQueryString(): string
    {
        return 'satoken=' . rawurlencode($this->query->all()['satoken'] ?? '');
    }
}

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

    public function testConflictingQueryAndBodyTokensFailClosed(): void
    {
        SaToken::getConfig()->setIsReadBody(true);
        $queryToken = $this->logic->login('query-user')->getAccessToken();
        $bodyToken = $this->logic->login('body-user')->getAccessToken();

        $request = $this->createMock(\Psr\Http\Message\ServerRequestInterface::class);
        $uri = $this->createMock(\Psr\Http\Message\UriInterface::class);
        $uri->method('getQuery')->willReturn('satoken=' . rawurlencode($queryToken));
        $request->method('getUri')->willReturn($uri);
        $request->method('getQueryParams')->willReturn(['satoken' => $queryToken]);
        $request->method('getParsedBody')->willReturn(['satoken' => $bodyToken]);
        SaTokenContext::setRequest($request);

        self::assertNull($this->logic->getTokenValue());
        self::assertFalse($this->logic->isLogin());
    }

    public function testConflictingFrameworkQueryAndBodyTokensFailClosed(): void
    {
        SaToken::getConfig()->setIsReadBody(true);
        $queryToken = $this->logic->login('framework-query-user')->getAccessToken();
        $bodyToken = $this->logic->login('framework-body-user')->getAccessToken();
        $request = new SaTokenContextFrameworkRequestStub(
            new SaTokenContextParameterBagStub(['satoken' => $queryToken]),
            new SaTokenContextParameterBagStub(['satoken' => $bodyToken])
        );
        SaTokenContext::setRequest($request);

        self::assertNull($this->logic->getTokenValue());
        self::assertFalse($this->logic->isLogin());
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

    public function testZeroMaxLoginCountRejectedAtConfigurationTime(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('最大登录数必须是正整数，或使用 -1 表示不限制');
        SaToken::getConfig()->setMaxLoginCount(0);
    }

    public function testCreateTempToken(): void
    {
        $tempToken = $this->logic->createTempToken(10001, 300);

        $loginId = $this->tokenManager->getLoginIdByToken($tempToken);
        $this->assertEquals('10001', $loginId);
    }
}
