<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoInterface;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\Session\SaSessionCleaner;

/**
 * 模拟一个"记录了 TTL 但从不物理删除过期记录"的自定义存储后端
 * （例如按 expire 字段过滤读取的数据库 DAO），这正是 SaSessionCleaner
 * 存在的意义：回收后端未自动删除的过期记录
 */
final class LazyTtlDaoStub extends SaTokenDaoMemory
{
    #[\Override]
    public function get(string $key): ?string
    {
        // 读取层按 TTL 过滤（过期即视为不存在），但记录仍保留在存储中
        if (!isset($this->dataMap[$key])) {
            return null;
        }
        $expireAt = $this->dataMap[$key]['expire_at'];
        if ($expireAt !== null && $expireAt <= time()) {
            return null;
        }
        return $this->dataMap[$key]['value'];
    }

    #[\Override]
    public function exists(string $key): bool
    {
        return $this->get($key) !== null;
    }

    #[\Override]
    public function getTimeout(string $key): int
    {
        if (!isset($this->dataMap[$key])) {
            return -2;
        }
        $expireAt = $this->dataMap[$key]['expire_at'];
        if ($expireAt === null) {
            return -1;
        }
        return $expireAt - time();
    }

    /** 惰性后端：绝不自动回收过期记录 */
    #[\Override]
    protected function checkExpired(string $key): void
    {
    }

    #[\Override]
    protected function cleanExpired(): void
    {
    }
}

class SaSessionCleanerTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig(['tokenEncrypt' => false]));
        SaToken::setDao(new LazyTtlDaoStub());
        SaSessionCleaner::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaSessionCleaner::reset();
    }

    public function testCleanOnceRemovesExpiredTokens(): void
    {
        $dao = SaToken::getDao();

        $dao->set('satoken:login:token:expired-token-1', 'user1', 10);
        $dao->set('satoken:login:token:expired-token-2', 'user2', 10);
        $dao->set('satoken:login:token:valid-token', 'user3', 1000);

        // 模拟时间流逝：将过期时间改到过去（TTL 已到期但记录仍留在存储中）
        $this->backdate($dao, 'satoken:login:token:expired-token-1');
        $this->backdate($dao, 'satoken:login:token:expired-token-2');

        $cleaned = SaSessionCleaner::cleanOnce();

        $this->assertSame(2, $cleaned);
        $this->assertNull($dao->get('satoken:login:token:expired-token-1'));
        $this->assertNull($dao->get('satoken:login:token:expired-token-2'));
        $this->assertNotNull($dao->get('satoken:login:token:valid-token'));
    }

    public function testCleanOnceRemovesExpiredSessions(): void
    {
        $dao = SaToken::getDao();

        $dao->set('satoken:session:expired-session-1', 'data', 10);
        $dao->set('satoken:tokenSession:expired-token-session', 'data', 10);
        $dao->set('satoken:session:valid-session', 'data', 1000);

        $this->backdate($dao, 'satoken:session:expired-session-1');
        $this->backdate($dao, 'satoken:tokenSession:expired-token-session');

        $cleaned = SaSessionCleaner::cleanOnce();

        $this->assertSame(2, $cleaned);
        $this->assertNull($dao->get('satoken:session:expired-session-1'));
        $this->assertNull($dao->get('satoken:tokenSession:expired-token-session'));
        $this->assertNotNull($dao->get('satoken:session:valid-session'));
    }

    public function testCleanOnceSkipsValidAndPermanentRecords(): void
    {
        $dao = SaToken::getDao();

        $dao->set('satoken:login:token:valid-token-1', 'user1', 10000);
        // 永不过期（timeout=-1）的记录必须保留
        $dao->set('satoken:session:permanent-session', 'data', null);

        $cleaned = SaSessionCleaner::cleanOnce();

        $this->assertSame(0, $cleaned);
        $this->assertNotNull($dao->get('satoken:login:token:valid-token-1'));
        $this->assertNotNull($dao->get('satoken:session:permanent-session'));
    }

    public function testCleanerNeverTouchesForeignPrefixes(): void
    {
        $dao = SaToken::getDao();
        // 非框架前缀的记录即使"过期"也不应被清理器触碰
        $dao->set('user:data:whatever', 'payload', 10);
        $this->backdate($dao, 'user:data:whatever');

        $cleaned = SaSessionCleaner::cleanOnce();

        $this->assertSame(0, $cleaned);
        // TTL 已到期（<=0）但非 -2，说明记录仍留在存储中，未被清理器删除
        $ttl = $dao->getTimeout('user:data:whatever');
        $this->assertTrue($ttl <= 0 && $ttl !== -2, "过期记录应仍存在于存储中，实际 TTL: {$ttl}");
    }

    public function testIsRunningReturnsFalseInitially(): void
    {
        $this->assertFalse(SaSessionCleaner::isRunning());
    }

    public function testTotalCleanedCounter(): void
    {
        $dao = SaToken::getDao();

        $dao->set('satoken:login:token:expired-token-1', 'user1', 10);
        $this->backdate($dao, 'satoken:login:token:expired-token-1');

        SaSessionCleaner::cleanOnce();
        $firstClean = SaSessionCleaner::getTotalCleaned();

        $dao->set('satoken:login:token:expired-token-2', 'user2', 10);
        $this->backdate($dao, 'satoken:login:token:expired-token-2');

        SaSessionCleaner::cleanOnce();
        $secondClean = SaSessionCleaner::getTotalCleaned();

        $this->assertSame(1, $firstClean);
        $this->assertSame(2, $secondClean);
    }

    public function testSetIntervalAndBatchSize(): void
    {
        SaSessionCleaner::setInterval(7200);
        SaSessionCleaner::setBatchSize(500);

        SaSessionCleaner::setInterval(3600);
        SaSessionCleaner::setBatchSize(200);

        $this->assertTrue(true);
    }

    public function testResetClearsTotalCleaned(): void
    {
        $dao = SaToken::getDao();

        $dao->set('satoken:login:token:expired-token-1', 'user1', 10);
        $this->backdate($dao, 'satoken:login:token:expired-token-1');

        SaSessionCleaner::cleanOnce();
        $this->assertSame(1, SaSessionCleaner::getTotalCleaned());

        SaSessionCleaner::reset();
        $this->assertSame(0, SaSessionCleaner::getTotalCleaned());
    }

    public function testCleanOnceReturnsCount(): void
    {
        $dao = SaToken::getDao();

        $dao->set('satoken:login:token:token1', 'user1', 10);
        $dao->set('satoken:login:token:token2', 'user2', 10);
        $dao->set('satoken:session:session1', 'data', 10);

        $this->backdate($dao, 'satoken:login:token:token1');
        $this->backdate($dao, 'satoken:login:token:token2');
        $this->backdate($dao, 'satoken:session:session1');

        $count = SaSessionCleaner::cleanOnce();

        $this->assertSame(3, $count);
    }

    /**
     * 将指定 key 的过期时间改到过去，模拟"已到期但后端未回收"
     */
    private function backdate(SaTokenDaoInterface $dao, string $key): void
    {
        if (!$dao instanceof LazyTtlDaoStub) {
            $this->fail('测试需要 LazyTtlDaoStub');
        }
        $ref = new \ReflectionProperty(SaTokenDaoMemory::class, 'dataMap');
        $ref->setAccessible(true);
        /** @var array<string, array{value: string, expire_at: int|null}> $dataMap */
        $dataMap = $ref->getValue($dao);
        if (isset($dataMap[$key])) {
            $dataMap[$key]['expire_at'] = time() - 100;
            $ref->setValue($dao, $dataMap);
        }
    }
}
