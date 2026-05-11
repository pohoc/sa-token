<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\Security\SaAuditLog;
use SaToken\StpLogic;

class SaAuditLogTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaAuditLog::reset();
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
        SaToken::setDao(new SaTokenDaoMemory());
    }

    protected function tearDown(): void
    {
        SaAuditLog::reset();
        SaToken::reset();
    }

    public function testEnableDisable(): void
    {
        $this->assertFalse(SaAuditLog::isEnabled());

        SaAuditLog::setEnabled(true);
        $this->assertTrue(SaAuditLog::isEnabled());

        SaAuditLog::setEnabled(false);
        $this->assertFalse(SaAuditLog::isEnabled());
    }

    public function testLogReturnsNullWhenDisabled(): void
    {
        SaAuditLog::setEnabled(false);

        $id = SaAuditLog::logLogin(10001, 'login', 'token123');
        $this->assertNull($id);
    }

    public function testLogLoginCreatesEntry(): void
    {
        SaAuditLog::setEnabled(true);

        $id = SaAuditLog::logLogin(10001, 'login', 'token123');
        $this->assertNotNull($id);
        $this->assertEquals(32, strlen($id));

        $log = SaAuditLog::getLog($id, 'login');
        $this->assertNotNull($log);
        $this->assertEquals('login', $log['event']);
        $this->assertEquals('10001', $log['loginId']);
        $this->assertEquals('login', $log['loginType']);
        $this->assertEquals('用户登录', $log['action']);
    }

    public function testLogLogoutCreatesEntry(): void
    {
        SaAuditLog::setEnabled(true);

        $id = SaAuditLog::logLogout(10001, 'login', 'token123');
        $this->assertNotNull($id);

        $log = SaAuditLog::getLog($id, 'login');
        $this->assertNotNull($log);
        $this->assertEquals('logout', $log['event']);
        $this->assertEquals('用户登出', $log['action']);
    }

    public function testLogKickoutCreatesEntry(): void
    {
        SaAuditLog::setEnabled(true);

        $id = SaAuditLog::logKickout(10001, 'login', 'token123');
        $this->assertNotNull($id);

        $log = SaAuditLog::getLog($id, 'login');
        $this->assertNotNull($log);
        $this->assertEquals('kickout', $log['event']);
        $this->assertEquals('账号被踢出', $log['action']);
    }

    public function testLogDisableCreatesEntry(): void
    {
        SaAuditLog::setEnabled(true);

        $id = SaAuditLog::logDisable(10001, 'login', 'spam');
        $this->assertNotNull($id);

        $log = SaAuditLog::getLog($id, 'login');
        $this->assertNotNull($log);
        $this->assertEquals('disable', $log['event']);
        $this->assertEquals('账号被封禁', $log['action']);
        $this->assertEquals('spam', $log['extra']['reason']);
    }

    public function testLogSwitchToCreatesEntry(): void
    {
        SaAuditLog::setEnabled(true);

        $id = SaAuditLog::logSwitchTo(10001, 20002, 'login');
        $this->assertNotNull($id);

        $log = SaAuditLog::getLog($id, 'login');
        $this->assertNotNull($log);
        $this->assertEquals('switch', $log['event']);
        $this->assertEquals('20002', $log['extra']['targetLoginId']);
    }

    public function testGetRecentLogs(): void
    {
        SaAuditLog::setEnabled(true);

        SaAuditLog::logLogin(10001, 'login');
        SaAuditLog::logLogout(10001, 'login');
        SaAuditLog::logLogin(10002, 'login');

        $logs = SaAuditLog::getRecentLogs('login', 10);
        $this->assertCount(3, $logs);
    }

    public function testGetLogsByLoginId(): void
    {
        SaAuditLog::setEnabled(true);

        SaAuditLog::logLogin(10001, 'login');
        SaAuditLog::logLogout(10001, 'login');
        SaAuditLog::logLogin(10002, 'login');

        $logs = SaAuditLog::getLogsByLoginId(10001, 'login', 10);
        $this->assertCount(2, $logs);

        foreach ($logs as $log) {
            $this->assertEquals('10001', $log['loginId']);
        }
    }

    public function testGetLogsByEvent(): void
    {
        SaAuditLog::setEnabled(true);

        SaAuditLog::logLogin(10001, 'login');
        SaAuditLog::logLogout(10001, 'login');
        SaAuditLog::logLogin(10002, 'login');

        $logs = SaAuditLog::getLogsByEvent('login', 'login', 10);
        $this->assertCount(2, $logs);

        foreach ($logs as $log) {
            $this->assertEquals('login', $log['event']);
        }
    }

    public function testGetLogNotFound(): void
    {
        SaAuditLog::setEnabled(true);

        $log = SaAuditLog::getLog('nonexistent', 'login');
        $this->assertNull($log);
    }

    public function testClearLogs(): void
    {
        SaAuditLog::setEnabled(true);

        SaAuditLog::logLogin(10001, 'login');
        SaAuditLog::logLogout(10001, 'login');

        $logs = SaAuditLog::getRecentLogs('login', 10);
        $this->assertCount(2, $logs);

        SaAuditLog::clearLogs('login');

        $logs = SaAuditLog::getRecentLogs('login', 10);
        $this->assertCount(0, $logs);
    }

    public function testTokenValueTruncated(): void
    {
        SaAuditLog::setEnabled(true);

        $longToken = str_repeat('a', 100);
        $id = SaAuditLog::logLogin(10001, 'login', $longToken);

        $log = SaAuditLog::getLog($id, 'login');
        $this->assertNotNull($log);
        $this->assertStringEndsWith('...', $log['tokenValue']);
        $this->assertEquals(35, strlen($log['tokenValue']));
    }

    public function testMaxEntriesLimit(): void
    {
        SaAuditLog::setEnabled(true);
        SaAuditLog::setMaxEntries(5);

        for ($i = 0; $i < 10; $i++) {
            SaAuditLog::logLogin(10000 + $i, 'login');
        }

        $logs = SaAuditLog::getRecentLogs('login', 100);
        $this->assertCount(5, $logs);
    }

    public function testIntegrationWithStpLogic(): void
    {
        SaAuditLog::setEnabled(true);

        $logic = new StpLogic('login');

        SaAuditLog::logLogin(10001, 'login', 'test-token');
        SaAuditLog::logLogout(10001, 'login');

        $logs = SaAuditLog::getLogsByLoginId(10001, 'login', 10);
        $this->assertNotEmpty($logs);

        $loginLog = null;
        foreach ($logs as $log) {
            if ($log['event'] === 'login') {
                $loginLog = $log;
                break;
            }
        }
        $this->assertNotNull($loginLog);
        $this->assertEquals('10001', $loginLog['loginId']);
    }

    public function testGetAuditLogById(): void
    {
        SaAuditLog::setEnabled(true);

        $logic = new StpLogic('login');

        $logId = SaAuditLog::logLogin(10001, 'login', 'test-token');
        $this->assertNotNull($logId);

        $log = SaAuditLog::getLog($logId, 'login');

        $this->assertNotNull($log);
        $this->assertEquals($logId, $log['id']);
    }
}
