<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\Security\SaAuditLog;
use SaToken\StpLogic;
use SaToken\Util\SaTokenContext;

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
        $this->assertEquals('spam', is_array($log['extra'] ?? null) ? ($log['extra']['reason'] ?? null) : null);
    }

    public function testLogSwitchToCreatesEntry(): void
    {
        SaAuditLog::setEnabled(true);

        $id = SaAuditLog::logSwitchTo(10001, 20002, 'login');
        $this->assertNotNull($id);

        $log = SaAuditLog::getLog($id, 'login');
        $this->assertNotNull($log);
        $this->assertEquals('switch', $log['event']);
        $this->assertEquals('20002', is_array($log['extra'] ?? null) ? ($log['extra']['targetLoginId'] ?? null) : null);
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

    public function testAuditLogQueriesDoNotCrossLoginTypeBoundaries(): void
    {
        SaAuditLog::setEnabled(true);
        $childId = SaAuditLog::log('login', 'private-user', 'admin:internal', '', null, '203.0.113.9');
        $adminId = SaAuditLog::log('login', 'admin-user', 'admin', '', null, '203.0.113.9');
        self::assertNotNull($childId);
        self::assertNotNull($adminId);

        // The legacy concatenated key for this crafted pair equals the child log key.
        self::assertNull(SaAuditLog::getLog('internal:' . $childId, 'admin'));
        self::assertSame('admin:internal', SaAuditLog::getLog($childId, 'admin:internal')['loginType'] ?? null);

        $adminLogs = SaAuditLog::getRecentLogs('admin', 10);
        self::assertCount(1, $adminLogs);
        self::assertSame('admin', $adminLogs[0]['loginType'] ?? null);
        self::assertCount(1, SaAuditLog::getLogsByIp('203.0.113.9', 'admin', 10));
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

    public function testClearLogsWithoutLoginTypeClearsEveryType(): void
    {
        SaAuditLog::setEnabled(true);

        SaAuditLog::logLogin(10001, 'login');
        SaAuditLog::logLogin(20002, 'admin');
        SaAuditLog::logLogin(30003, 'tenant:custom');

        SaAuditLog::clearLogs();

        $this->assertSame([], SaAuditLog::getRecentLogs('login'));
        $this->assertSame([], SaAuditLog::getRecentLogs('admin'));
        $this->assertSame([], SaAuditLog::getRecentLogs('tenant:custom'));
    }

    public function testClearLogsRemovesMoreThanConfiguredRetentionLimit(): void
    {
        SaAuditLog::setEnabled(true);
        SaAuditLog::setMaxEntries(1);

        $dao = SaToken::getDao();
        foreach (range(1, 25) as $index) {
            $id = str_pad((string) $index, 32, '0', STR_PAD_LEFT);
            $dao->set('satoken:audit:custom:' . $id, json_encode([
                'id' => $id,
                'loginType' => 'custom',
                'time' => time(),
            ], JSON_THROW_ON_ERROR));
        }

        SaAuditLog::clearLogs('custom');

        $this->assertSame([], SaAuditLog::getRecentLogs('custom', 100));
    }

    public function testTokenValueIsRedactedFromAuditLog(): void
    {
        SaAuditLog::setEnabled(true);

        $token = 'custom-token-123';
        $id = SaAuditLog::logLogin(10001, 'login', $token);

        $log = SaAuditLog::getLog($id ?? '', 'login');
        $this->assertNotNull($log);
        $this->assertSame('[redacted]', $log['tokenValue'] ?? null);
        $this->assertStringNotContainsString($token, json_encode($log) ?: '');
    }

    public function testTokenValueIsRedactedForTokensLongerThanOldTruncation(): void
    {
        SaAuditLog::setEnabled(true);

        $token = str_repeat('a', 100);
        $id = SaAuditLog::logLogin(10001, 'login', $token);

        $log = SaAuditLog::getLog($id ?? '', 'login');
        $this->assertNotNull($log);
        $this->assertSame('[redacted]', $log['tokenValue'] ?? null);
    }

    public function testInvalidUtf8UserAgentDoesNotEraseAuditEvent(): void
    {
        SaAuditLog::setEnabled(true);

        $id = SaAuditLog::log('login', 'audit-user', 'login', '用户登录', null, null, "agent-\xFF");

        self::assertNotNull($id);
        $log = SaAuditLog::getLog($id, 'login');
        self::assertNotNull($log);
        self::assertSame('login', $log['event'] ?? null);
        self::assertSame("agent-\u{FFFD}", $log['userAgent'] ?? null);
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

    public function testAuditLogQueryLimitsAreClamped(): void
    {
        SaAuditLog::setEnabled(true);
        SaAuditLog::logLogin('audit-user');

        self::assertSame([], SaAuditLog::getRecentLogs('login', -1));
        self::assertSame([], SaAuditLog::getLogsByLoginId('audit-user', 'login', 0));
        self::assertSame([], SaAuditLog::getLogsByEvent('login', 'login', -5));
        self::assertSame([], SaAuditLog::getLogsByIp('127.0.0.1', 'login', 0));
        self::assertCount(1, SaAuditLog::getRecentLogs('login', PHP_INT_MAX));
    }

    public function testNonPositiveAuditLogTtlCannotDisableExpiration(): void
    {
        SaAuditLog::setTtlDays(0);
        SaAuditLog::setEnabled(true);
        $id = SaAuditLog::logLogin('audit-user');

        self::assertNotNull($id);
        self::assertGreaterThan(0, SaToken::getDao()->getTimeout('satoken:audit:login:' . $id));
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

    public function testStpLogicAuditLogLookupRequiresCurrentAccountOwnership(): void
    {
        SaAuditLog::setEnabled(true);
        SaToken::getConfig()->setIsReadHeader(true);
        $logic = new StpLogic('login');
        $token = $logic->login('audit-owner')->getAccessToken();
        $ownLogId = SaAuditLog::logLogin('audit-owner');
        $otherLogId = SaAuditLog::logLogin('other-account');

        SaTokenContext::setRequest(new class ($token) {
            public function __construct(private string $token)
            {
            }

            public function getHeaderLine(string $name): string
            {
                return strtolower($name) === 'satoken' ? $this->token : '';
            }
        });

        self::assertNotNull($ownLogId);
        self::assertNotNull($otherLogId);
        self::assertSame($ownLogId, $logic->getAuditLog($ownLogId)['id'] ?? null);
        self::assertNull($logic->getAuditLog($otherLogId));

        SaTokenContext::setRequest(null);
        self::assertNull($logic->getAuditLog($ownLogId));
    }
}
