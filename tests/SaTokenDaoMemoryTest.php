<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoMemory;

class SaTokenDaoMemoryTest extends TestCase
{
    protected SaTokenDaoMemory $dao;

    protected function setUp(): void
    {
        $this->dao = new SaTokenDaoMemory();
    }

    // ---- Basic CRUD ----

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

    public function testUpdate(): void
    {
        $this->dao->set('key1', 'value1');
        $this->dao->update('key1', 'updated');
        $this->assertEquals('updated', $this->dao->get('key1'));
    }

    public function testUpdateNonExistentKey(): void
    {
        // 不应创建新 key
        $this->dao->update('key1', 'value');
        $this->assertNull($this->dao->get('key1'));
    }

    public function testExists(): void
    {
        $this->assertFalse($this->dao->exists('key1'));

        $this->dao->set('key1', 'value1');
        $this->assertTrue($this->dao->exists('key1'));
    }

    // ---- Timeout / TTL ----

    public function testSetWithTimeout(): void
    {
        $this->dao->set('key1', 'value1', 3600);
        $timeout = $this->dao->getTimeout('key1');

        $this->assertGreaterThan(0, $timeout);
        $this->assertLessThanOrEqual(3600, $timeout);
    }

    public function testSetWithoutTimeout(): void
    {
        $this->dao->set('key1', 'value1');
        $this->assertEquals(-1, $this->dao->getTimeout('key1'));
    }

    public function testGetTimeoutNonExistent(): void
    {
        $this->assertEquals(-2, $this->dao->getTimeout('nonexistent'));
    }

    public function testExpire(): void
    {
        $this->dao->set('key1', 'value1');
        $this->assertEquals(-1, $this->dao->getTimeout('key1'));

        $this->dao->expire('key1', 7200);
        $timeout = $this->dao->getTimeout('key1');
        $this->assertGreaterThan(0, $timeout);
        $this->assertLessThanOrEqual(7200, $timeout);
    }

    public function testExpireNonExistent(): void
    {
        // 不应抛异常，也不应创建新 key
        $this->dao->expire('nonexistent', 3600);
        $this->assertNull($this->dao->get('nonexistent'));
    }

    public function testExpireToPersist(): void
    {
        $this->dao->set('key1', 'value1', 60);
        $this->dao->expire('key1', 0);
        $this->assertEquals(-1, $this->dao->getTimeout('key1'));
    }

    // ---- getAndExpire ----

    public function testGetAndExpire(): void
    {
        $this->dao->set('key1', 'value1');
        $value = $this->dao->getAndExpire('key1', 7200);

        $this->assertEquals('value1', $value);
        $timeout = $this->dao->getTimeout('key1');
        $this->assertGreaterThan(0, $timeout);
    }

    public function testGetAndExpireNonExistent(): void
    {
        $value = $this->dao->getAndExpire('nonexistent', 3600);
        $this->assertNull($value);
    }

    // ---- Size ----

    public function testSize(): void
    {
        $this->assertEquals(0, $this->dao->size());

        $this->dao->set('key1', 'value1');
        $this->assertEquals(1, $this->dao->size());

        $this->dao->set('key2', 'value2');
        $this->assertEquals(2, $this->dao->size());

        $this->dao->delete('key1');
        $this->assertEquals(1, $this->dao->size());
    }

    // ---- Expiration ----

    public function testExpiredKeyAutoCleanup(): void
    {
        $this->dao->set('key1', 'value1', 1);
        $this->assertNotNull($this->dao->get('key1'));

        // 等待过期
        sleep(2);
        $this->assertNull($this->dao->get('key1'));
    }

    public function testExpiredKeyNotExists(): void
    {
        $this->dao->set('key1', 'value1', 1);
        sleep(2);
        $this->assertFalse($this->dao->exists('key1'));
    }

    public function testExpiredKeyTimeoutIsNegativeTwo(): void
    {
        $this->dao->set('key1', 'value1', 1);
        sleep(2);
        $this->assertEquals(-2, $this->dao->getTimeout('key1'));
    }

    // ---- Clear ----

    public function testClear(): void
    {
        $this->dao->set('key1', 'value1');
        $this->dao->set('key2', 'value2');
        $this->dao->clear();
        $this->assertEquals(0, $this->dao->size());
    }

    // ---- Multiple Keys ----

    public function testMultipleKeys(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $this->dao->set("key:$i", "value:$i");
        }
        $this->assertEquals(100, $this->dao->size());

        for ($i = 0; $i < 100; $i++) {
            $this->assertEquals("value:$i", $this->dao->get("key:$i"));
        }
    }

    // ---- Special Values ----

    public function testEmptyValue(): void
    {
        $this->dao->set('key1', '');
        // 空字符串仍返回空字符串（不是 null）
        $this->assertEquals('', $this->dao->get('key1'));
    }

    public function testJsonValues(): void
    {
        $json = '{"name":"张三","age":25}';
        $this->dao->set('user:1', $json);
        $this->assertEquals($json, $this->dao->get('user:1'));
    }

    public function testLongKey(): void
    {
        $longKey = str_repeat('a', 500);
        $this->dao->set($longKey, 'value');
        $this->assertEquals('value', $this->dao->get($longKey));
    }
}
