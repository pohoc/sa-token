<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
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

    // ======== update ========

    public function testUpdateExistingKey(): void
    {
        $this->dao->set('key1', 'value1');
        $this->dao->update('key1', 'updated');
        $this->assertEquals('updated', $this->dao->get('key1'));
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
        // PSR-16 无法获取 TTL，默认返回 -1（永不过期）
        $this->assertEquals(-1, $this->dao->getTimeout('key1'));
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

    // ======== 特殊值 ========

    public function testEmptyValue(): void
    {
        $this->dao->set('key1', '');
        // 空字符串被 get 返回为空字符串
        $this->assertEquals('', $this->dao->get('key1'));
    }

    public function testJsonValue(): void
    {
        $json = '{"name":"test","age":30}';
        $this->dao->set('key1', $json);
        $this->assertEquals($json, $this->dao->get('key1'));
    }
}

/**
 * 内存 PSR-16 缓存实现（用于测试）
 */
class ArrayPsr16Cache implements CacheInterface
{
    protected array $data = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $this->data[$key] = $value;
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->data = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }
        return $result;
    }

    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }
}
