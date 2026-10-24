<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoPsr16;

/**
 * SaTokenDaoPsr16 适配器测试
 *
 * 使用内存模拟 PSR-16 缓存实现，测试 DAO 适配层
 */
class SaTokenDaoPsr16Test extends TestCase
{
    protected SaTokenDaoPsr16 $dao;
    protected ArrayPsr16Cache $cache;

    protected function setUp(): void
    {
        $this->cache = new ArrayPsr16Cache();
        $this->dao = new SaTokenDaoPsr16($this->cache);
    }

    // ======== Basic CRUD ========

    public function testSetAndGet(): void
    {
        $this->dao->set('key1', 'value1');
        $this->assertEquals('value1', $this->dao->get('key1'));
    }

    public function testGetNonExistentKey(): void
    {
        $this->assertNull($this->dao->get('nonexistent'));
    }

    public function testOverwriteValue(): void
    {
        $this->dao->set('key1', 'value1');
        $this->dao->set('key1', 'value2');
        $this->assertEquals('value2', $this->dao->get('key1'));
    }

    public function testDelete(): void
    {
        $this->dao->set('key1', 'value1');
        $this->dao->delete('key1');
        $this->assertNull($this->dao->get('key1'));
    }

    public function testDeleteNonExistentKey(): void
    {
        // 不应抛异常
        $this->dao->delete('nonexistent');
        $this->assertNull($this->dao->get('nonexistent'));
    }

    public function testCompareAndExpireOnlyRenewsMatchingValue(): void
    {
        $this->dao->set('lock', 'owner-a', 60);

        self::assertFalse($this->dao->compareAndExpire('lock', 'owner-b', 120));
        self::assertLessThanOrEqual(60, $this->dao->getTimeout('lock'));
        self::assertTrue($this->dao->compareAndExpire('lock', 'owner-a', 120));
        self::assertLessThanOrEqual(120, $this->dao->getTimeout('lock'));
    }

    public function testCompareAndExpireNeverShortensAndCanMakeAKeyPermanent(): void
    {
        $this->dao->set('session-index', 'value', 180);

        self::assertTrue($this->dao->compareAndExpire('session-index', 'value', 30));
        self::assertGreaterThan(30, $this->dao->getTimeout('session-index'));
        self::assertTrue($this->dao->compareAndExpire('session-index', 'value', -1));
        self::assertSame(-1, $this->dao->getTimeout('session-index'));
    }

    public function testCompareAndExpireDoesNotReviveKeyThatExpiresDuringTtlRead(): void
    {
        $cache = new ArrayPsr16Cache();
        $dao = new class ($cache) extends SaTokenDaoPsr16 {
            public bool $reportExpired = false;

            public function getTimeout(string $key): int
            {
                return $this->reportExpired ? -2 : parent::getTimeout($key);
            }
        };
        $dao->set('expiring-session-index', 'value', 60);
        $dao->reportExpired = true;

        self::assertFalse($dao->compareAndExpire('expiring-session-index', 'value', 120));

        $dao->reportExpired = false;
        self::assertSame('value', $dao->get('expiring-session-index'));
        self::assertLessThanOrEqual(60, $dao->getTimeout('expiring-session-index'));
    }

    public function testCompareAndUpdatePreservesValueAndTtlOnMismatch(): void
    {
        $this->dao->set('session', 'old-record', 60);
        $ttl = $this->dao->getTimeout('session');
        self::assertFalse($this->dao->compareAndUpdate('session', 'stale-record', 'wrong'));
        self::assertSame('old-record', $this->dao->get('session'));
        self::assertTrue($this->dao->compareAndUpdate('session', 'old-record', 'new-record'));
        self::assertSame('new-record', $this->dao->get('session'));
        self::assertLessThanOrEqual($ttl, $this->dao->getTimeout('session'));
    }

    public function testCompareAndUpdateDoesNotMakeEvictedTtlMetadataPermanent(): void
    {
        $key = 'session-ttl-metadata-eviction';
        $this->dao->set($key, 'before', 120);
        $ttl = $this->dao->getTimeout($key);
        $ttlKey = 'sat_ttl_' . substr(hash('sha256', $key), 0, 56);
        $this->cache->delete($ttlKey);

        self::assertTrue($this->dao->compareAndUpdate($key, 'before', 'after'));
        self::assertSame('after', $this->dao->get($key));
        self::assertGreaterThan(0, $this->dao->getTimeout($key));
        self::assertLessThanOrEqual($ttl, $this->dao->getTimeout($key));
    }

    public function testUpdateDoesNotMakeEvictedTtlMetadataPermanent(): void
    {
        $key = 'updated-session-ttl-metadata-eviction';
        $this->dao->set($key, 'before', 120);
        $ttl = $this->dao->getTimeout($key);
        $ttlKey = 'sat_ttl_' . substr(hash('sha256', $key), 0, 56);
        $this->cache->delete($ttlKey);

        $this->dao->update($key, 'after');

        self::assertSame('after', $this->dao->get($key));
        self::assertGreaterThan(0, $this->dao->getTimeout($key));
        self::assertLessThanOrEqual($ttl, $this->dao->getTimeout($key));
    }

    // ======== update ========

    public function testUpdateExistingKey(): void
    {
        $this->dao->set('key1', 'value1');
        $this->dao->update('key1', 'updated');
        $this->assertEquals('updated', $this->dao->get('key1'));
    }

    public function testUpdatePreservesExactSharedExpiry(): void
    {
        $key = 'session';
        $ttlKey = 'sat_ttl_' . substr(hash('sha256', $key), 0, 56);
        $this->dao->set($key, 'before', 10);
        $expiresAt = $this->cache->get($ttlKey);

        $dao = new class ($this->cache) extends SaTokenDaoPsr16 {
            public function getTimeout(string $key): int
            {
                $timeout = parent::getTimeout($key);
                sleep(1);
                return $timeout;
            }
        };
        $dao->update($key, 'after');

        self::assertSame($expiresAt, $this->cache->get($ttlKey));
        self::assertSame('after', $dao->get($key));
    }

    public function testCorruptExpiryMetadataDoesNotOverrideEmbeddedExpiry(): void
    {
        $key = 'corrupt-ttl';
        $this->dao->set($key, 'value', 60);
        $ttlKey = 'sat_ttl_' . substr(hash('sha256', $key), 0, 56);
        $this->cache->set($ttlKey, 'not-an-expiry');

        self::assertSame('value', $this->dao->get($key));
        self::assertTrue($this->dao->exists($key));
        self::assertGreaterThan(0, $this->dao->getTimeout($key));
    }

    public function testUpdateNonExistentKey(): void
    {
        // PSR-16 的 update 实现通过 getTimeout 判断 key 是否存在
        // getTimeout 对不存在的 key 返回 -2，所以 update 会跳过
        $this->dao->update('key1', 'value');
        $this->assertNull($this->dao->get('key1'));
    }

    // ======== exists ========

    public function testExists(): void
    {
        $this->assertFalse($this->dao->exists('key1'));
        $this->dao->set('key1', 'value1');
        $this->assertTrue($this->dao->exists('key1'));
    }

    // ======== getTimeout ========

    public function testGetTimeoutNonExistent(): void
    {
        $this->assertEquals(-2, $this->dao->getTimeout('nonexistent'));
    }

    public function testGetTimeoutExistingKey(): void
    {
        $this->dao->set('key1', 'value1');
        // 无 TTL 的键使用共享 metadata 表示为永久键
        $this->assertEquals(-1, $this->dao->getTimeout('key1'));
    }

    public function testTtlIsPreservedAcrossAdapterInstances(): void
    {
        $this->dao->set('shared-counter', '1', 120);
        $secondDao = new SaTokenDaoPsr16($this->cache);
        $remaining = $secondDao->getTimeout('shared-counter');

        $this->assertGreaterThan(0, $remaining);
        $this->assertLessThanOrEqual(120, $remaining);

        $this->assertSame(2, $secondDao->increment('shared-counter', 1, 120));
        $thirdDao = new SaTokenDaoPsr16($this->cache);
        $remainingAfterIncrement = $thirdDao->getTimeout('shared-counter');
        $this->assertGreaterThan(0, $remainingAfterIncrement);
        $this->assertLessThanOrEqual($remaining, $remainingAfterIncrement);
    }

    public function testExpiredSharedCounterStartsAgainWithNewTtl(): void
    {
        $this->dao->set('expired-counter', '8', 1);
        sleep(2);
        $secondDao = new SaTokenDaoPsr16($this->cache);

        $this->assertSame(1, $secondDao->increment('expired-counter', 1, 60));
        $this->assertGreaterThan(0, $secondDao->getTimeout('expired-counter'));
    }

    // ======== expire ========

    public function testExpireExistingKey(): void
    {
        $this->dao->set('key1', 'value1');
        $this->dao->expire('key1', 3600);

        // 值仍然存在
        $this->assertEquals('value1', $this->dao->get('key1'));
    }

    public function testExpireNonExistentKey(): void
    {
        // 不应抛异常，也不应创建新 key
        $this->dao->expire('nonexistent', 3600);
        $this->assertNull($this->dao->get('nonexistent'));
    }

    // ======== getAndExpire ========

    public function testGetAndExpire(): void
    {
        $this->dao->set('key1', 'value1');
        $value = $this->dao->getAndExpire('key1', 7200);

        $this->assertEquals('value1', $value);
        $this->assertEquals('value1', $this->dao->get('key1'));
    }

    public function testGetAndExpireNonExistent(): void
    {
        $value = $this->dao->getAndExpire('nonexistent', 3600);
        $this->assertNull($value);
    }

    // ======== size ========

    public function testSizeReturnsUnsupported(): void
    {
        // PSR-16 不支持 size，返回 -1
        $this->assertEquals(-1, $this->dao->size());
    }

    // ======== set with timeout ========

    public function testSetWithTimeout(): void
    {
        $this->dao->set('key1', 'value1', 3600);
        $this->assertEquals('value1', $this->dao->get('key1'));
        $this->assertTrue($this->dao->exists('key1'));
    }

    public function testAtomicOperationsAreSerializedAcrossProcesses(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl is required for the multi-process lock test');
        }
        class_exists(ArrayPsr16Cache::class);

        $root = sys_get_temp_dir() . '/sa-token-psr16-test-' . bin2hex(random_bytes(8));
        $cacheDir = $root . '/cache';
        $lockDir = $root . '/locks';
        $resultDir = $root . '/results';
        mkdir($resultDir, 0700, true);

        try {
            $dao = new SaTokenDaoPsr16(new SharedFilePsr16Cache($cacheDir, 50000), $lockDir);
            $dao->set('one-time-token', 'payload');

            $runTwoProcesses = function (string $operation) use ($cacheDir, $lockDir, $resultDir): array {
                $pids = [];
                for ($index = 0; $index < 2; $index++) {
                    $pid = pcntl_fork();
                    if ($pid === -1) {
                        $this->fail('Could not fork worker process');
                    }
                    if ($pid === 0) {
                        $childDao = new SaTokenDaoPsr16(new SharedFilePsr16Cache($cacheDir, 50000), $lockDir);
                        $result = $operation === 'consume'
                            ? ($childDao->getAndDelete('one-time-token') === 'payload' ? 'consumed' : 'empty')
                            : ($childDao->setIfNotExists('single-claim', 'winner', 60) ? 'won' : 'lost');
                        file_put_contents($resultDir . '/' . $operation . '-' . $index, $result);
                        exit(0);
                    }
                    $pids[] = $pid;
                }

                foreach ($pids as $pid) {
                    $status = 0;
                    $waitedPid = pcntl_waitpid($pid, $status);
                    $this->assertSame($pid, $waitedPid);
                }
                return [
                    file_get_contents($resultDir . '/' . $operation . '-0'),
                    file_get_contents($resultDir . '/' . $operation . '-1'),
                ];
            };

            $consumeResults = $runTwoProcesses('consume');
            $this->assertSame(1, count(array_filter($consumeResults, static fn ($value): bool => $value === 'consumed')));
            $this->assertSame(1, count(array_filter($consumeResults, static fn ($value): bool => $value === 'empty')));

            $claimResults = $runTwoProcesses('claim');
            $this->assertSame(1, count(array_filter($claimResults, static fn ($value): bool => $value === 'won')));
            $this->assertSame(1, count(array_filter($claimResults, static fn ($value): bool => $value === 'lost')));
        } finally {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                if (!$item instanceof \SplFileInfo) {
                    continue;
                }
                $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
            }
            @rmdir($root);
        }
    }

    // ======== 特殊值 ========

    public function testEmptyValue(): void
    {
        $this->dao->set('key1', '');
        // 空字符串被 get 返回为空字符串
        $this->assertEquals('', $this->dao->get('key1'));
    }

    public function testBinaryValueRoundTrip(): void
    {
        $value = random_bytes(32) . "\0\xff";
        $this->dao->set('binary-value', $value, 60);

        self::assertSame($value, $this->dao->get('binary-value'));
    }

    public function testJsonValue(): void
    {
        $json = '{"name":"test","age":30}';
        $this->dao->set('key1', $json);
        $this->assertEquals($json, $this->dao->get('key1'));
    }
}
