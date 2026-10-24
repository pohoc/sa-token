<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaSession;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\TokenManager;

class SaSessionPausingDao extends SaTokenDaoMemory
{
    public ?string $pauseUpdateKey = null;
    public ?string $pauseDeleteKey = null;

    public function compareAndUpdate(string $key, string $expectedValue, string $newValue): bool
    {
        if ($key === $this->pauseUpdateKey) {
            $this->pauseUpdateKey = null;
            \Fiber::suspend();
        }

        return parent::compareAndUpdate($key, $expectedValue, $newValue);
    }

    public function compareAndSet(string $key, ?string $expectedValue, ?string $newValue, ?int $timeout = null): bool
    {
        if ($newValue === null && $key === $this->pauseDeleteKey) {
            $this->pauseDeleteKey = null;
            \Fiber::suspend();
        }

        return parent::compareAndSet($key, $expectedValue, $newValue, $timeout);
    }
}

class SaSessionTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig());
        SaToken::setDao(new SaTokenDaoMemory());
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testSetAndGet(): void
    {
        $session = new SaSession('test-session-1');

        $session->set('name', '张三');
        $this->assertEquals('张三', $session->get('name'));

        $session->set('age', 25);
        $this->assertEquals(25, $session->get('age'));
    }

    public function testGetWithDefault(): void
    {
        $session = new SaSession('test-session-2');
        $this->assertNull($session->get('nonexistent'));
        $this->assertEquals('default', $session->get('nonexistent', 'default'));
    }

    public function testDelete(): void
    {
        $session = new SaSession('test-session-3');
        $session->set('key', 'value');
        $this->assertTrue($session->has('key'));

        $session->delete('key');
        $this->assertFalse($session->has('key'));
    }

    public function testClear(): void
    {
        $session = new SaSession('test-session-4');
        $session->set('key1', 'value1');
        $session->set('key2', 'value2');

        $session->clear();
        $this->assertFalse($session->has('key1'));
        $this->assertFalse($session->has('key2'));
    }

    public function testUpdate(): void
    {
        $session = new SaSession('test-session-5');
        $session->set('key1', 'value1');

        $session->update(['key2' => 'value2', 'key3' => 'value3']);

        $this->assertEquals('value1', $session->get('key1'));
        $this->assertEquals('value2', $session->get('key2'));
        $this->assertEquals('value3', $session->get('key3'));
    }

    public function testDestroy(): void
    {
        $session = new SaSession('test-session-6');
        $session->set('key', 'value');

        $session->destroy();

        // 重新从存储层加载，应该不存在
        $loaded = SaSession::getBySessionId('test-session-6');
        $this->assertNull($loaded);
    }

    public function testSessionCannotDeleteReservedAuthenticationStorageKey(): void
    {
        $tokenKey = TokenManager::TOKEN_PREFIX . 'protected-token';
        SaToken::getDao()->set($tokenKey, 'protected-login-id', 3600);

        try {
            (new SaSession($tokenKey))->destroy();
            $this->fail('SaSession 不应允许删除 Sa-Token 的认证存储键');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('保留存储命名空间', $e->getMessage());
        }

        $this->assertSame('protected-login-id', SaToken::getDao()->get($tokenKey));
    }

    public function testSessionLookupCannotReadReservedAuthenticationStorageKey(): void
    {
        $tokenKey = TokenManager::TOKEN_PREFIX . 'protected-token';
        SaToken::getDao()->set($tokenKey, 'protected-login-id', 3600);

        $this->expectException(SaTokenException::class);
        SaSession::getBySessionId($tokenKey);
    }

    public function testSessionCannotDeleteInternalSessionLockKey(): void
    {
        $sessionId = TokenManager::buildSessionId('login', 'victim');
        $lockKey = 'satoken:session:lock:' . $sessionId;
        SaToken::getDao()->set($lockKey, 'active-lock-owner', 5);

        try {
            (new SaSession($lockKey))->destroy();
            $this->fail('SaSession 不应允许删除内部会话锁键');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('保留存储命名空间', $e->getMessage());
        }

        $this->assertSame('active-lock-owner', SaToken::getDao()->get($lockKey));
    }

    public function testDestroyWaitsForConcurrentSessionMutationLock(): void
    {
        $sessionId = 'test-session-destroy-lock';
        $session = new SaSession($sessionId);
        $session->set('key', 'value');
        $lockKey = 'satoken:session:lock:' . $sessionId;
        $this->assertTrue(SaToken::getDao()->setIfNotExists($lockKey, 'other-writer', 5));

        try {
            $session->destroy();
            $this->fail('持有会话修改锁时 destroy 应等待并拒绝删除');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('会话并发冲突', $e->getMessage());
        }

        $this->assertNotNull(SaSession::getBySessionId($sessionId));
    }

    public function testPersistence(): void
    {
        $session = new SaSession('test-session-7');
        $session->set('persistent', 'data');

        // 从存储层重新加载
        $loaded = SaSession::getBySessionId('test-session-7');
        $this->assertNotNull($loaded);
        $this->assertEquals('data', $loaded->get('persistent'));
    }

    public function testExpiredLoadedSessionCannotBeRecreatedByStaleObject(): void
    {
        $session = new SaSession('expiring-session', false, 1);
        $session->set('state', 'original');
        $loaded = SaSession::getBySessionId('expiring-session');
        $this->assertNotNull($loaded);

        sleep(2);

        try {
            $loaded->set('state', 'resurrected');
            $this->fail('过期会话对象不能重新创建永久会话');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('已过期或销毁', $e->getMessage());
        }

        $this->assertNull(SaToken::getDao()->get('expiring-session'));
        $this->assertNull(SaSession::getBySessionId('expiring-session'));
    }

    public function testStaleObjectCannotMutateSessionRecreatedWithSameId(): void
    {
        $sessionId = TokenManager::buildSessionId('login', 'reused-account');
        $stale = new SaSession($sessionId);
        $stale->set('generation', 'old');
        $stale->destroy();

        $current = new SaSession($sessionId);
        $current->set('generation', 'new');

        try {
            $stale->set('staleMutation', 'from-old-object');
            self::fail('旧 Session 对象不能修改同 ID 新建的会话');
        } catch (SaTokenException $e) {
            self::assertStringContainsString('重新创建', $e->getMessage());
        }

        $loaded = SaSession::getBySessionId($sessionId);
        self::assertNotNull($loaded);
        self::assertSame('new', $loaded->get('generation'));
        self::assertFalse($loaded->has('staleMutation'));
    }

    public function testLegacySessionRecordMigratesWithoutLosingData(): void
    {
        SaToken::getDao()->set('legacy-session', json_encode(['legacy' => 'value'], JSON_THROW_ON_ERROR), 300);

        $session = SaSession::getBySessionId('legacy-session');

        self::assertNotNull($session);
        self::assertSame('value', $session->get('legacy'));
        self::assertStringStartsWith("\0sa-token-session:v1\n", (string) SaToken::getDao()->get('legacy-session'));
    }

    public function testStaleObjectCannotDestroySessionRecreatedWithSameId(): void
    {
        $sessionId = TokenManager::buildSessionId('login', 'reused-account-destroy');
        $stale = new SaSession($sessionId);
        $stale->set('generation', 'old');
        $stale->destroy();

        $current = new SaSession($sessionId);
        $current->set('generation', 'new');

        try {
            $stale->destroy();
            self::fail('旧 Session 对象不能销毁同 ID 新建的会话');
        } catch (SaTokenException $e) {
            self::assertStringContainsString('重新创建', $e->getMessage());
        }

        self::assertSame('new', SaSession::getBySessionId($sessionId)?->get('generation'));
    }

    public function testExpiredMutationLeaseCannotOverwriteRecreatedSession(): void
    {
        $dao = new SaSessionPausingDao();
        SaToken::setDao($dao);
        $sessionId = TokenManager::buildSessionId('login', 'lease-expiry');
        $stale = new SaSession($sessionId);
        $stale->set('generation', 'old');
        $dao->pauseUpdateKey = $sessionId;

        $mutation = new \Fiber(static fn () => $stale->set('late', 'old-writer'));
        $mutation->start();
        self::assertTrue($mutation->isSuspended());

        // Model the lock lease expiring while the old writer is blocked in storage.
        $dao->delete('satoken:session:lock:' . $sessionId);
        $current = new SaSession($sessionId);
        $current->destroy();
        $replacement = new SaSession($sessionId);
        $replacement->set('generation', 'new');

        try {
            $mutation->resume();
            self::fail('租约失效后的旧写入必须被条件更新拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('原子条件更新', $exception->getMessage());
        }

        self::assertSame('new', SaSession::getBySessionId($sessionId)?->get('generation'));
    }

    public function testExpiredDestroyLeaseCannotDeleteRecreatedSession(): void
    {
        $dao = new SaSessionPausingDao();
        SaToken::setDao($dao);
        $sessionId = TokenManager::buildSessionId('login', 'lease-expiry-destroy');
        $stale = new SaSession($sessionId);
        $stale->set('generation', 'old');
        $dao->pauseDeleteKey = $sessionId;

        $destroy = new \Fiber(static fn () => $stale->destroy());
        $destroy->start();
        self::assertTrue($destroy->isSuspended());

        $dao->delete('satoken:session:lock:' . $sessionId);
        $current = new SaSession($sessionId);
        $current->destroy();
        $replacement = new SaSession($sessionId);
        $replacement->set('generation', 'new');

        try {
            $destroy->resume();
            self::fail('旧销毁操作不能删除新代际会话');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('原子条件删除', $exception->getMessage());
        }

        self::assertSame('new', SaSession::getBySessionId($sessionId)?->get('generation'));
    }

    public function testUnloadedSessionObjectCannotDestroyExistingRecord(): void
    {
        $sessionId = TokenManager::buildSessionId('login', 'unloaded-destroy');
        $current = new SaSession($sessionId);
        $current->set('owned', 'current');
        $unloaded = new SaSession($sessionId, true);

        try {
            $unloaded->destroy();
            self::fail('未加载记录且未持有代际标识的对象不能删除会话');
        } catch (SaTokenException $e) {
            self::assertStringContainsString('未持有当前记录', $e->getMessage());
        }

        self::assertSame('current', SaSession::getBySessionId($sessionId)?->get('owned'));
    }

    public function testTokenSession(): void
    {
        $tokenSession = new SaSession('satoken:tokenSession:test-token-123');
        $tokenSession->set('request_count', 5);

        $loaded = SaSession::getBySessionId('satoken:tokenSession:test-token-123');
        $this->assertNotNull($loaded);
        $this->assertEquals(5, $loaded->get('request_count'));
    }

    public function testLoginSessionsCannotCollideAcrossLoginTypes(): void
    {
        $userLogic = new StpLogic('user');
        $adminLogic = new StpLogic('user:admin');
        $userSession = $userLogic->getSessionByLoginId('admin:42');
        $adminSession = $adminLogic->getSessionByLoginId('42');

        self::assertNotNull($userSession);
        self::assertNotNull($adminSession);
        self::assertNotSame($userSession->getId(), $adminSession->getId());
        $userSession->set('role', 'user-admin-data');
        self::assertNull($adminSession->get('role'));

        $adminSession->set('role', 'admin-data');
        $userLogic->getTokenManager()->deleteAllTokenByLoginId('admin:42', 'user');
        self::assertSame('admin-data', $adminLogic->getSessionByLoginId('42', false)?->get('role'));
    }
}
