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
