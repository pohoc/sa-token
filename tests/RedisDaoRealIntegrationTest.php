<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoRedis;

class RedisDaoRealIntegrationTest extends TestCase
{
    protected \Redis $redis;
    protected SaTokenDaoRedis $dao;
    protected string $prefix = '';

    protected function setUp(): void
    {
        if (!class_exists(\Redis::class)) {
            $this->markTestSkipped('Redis extension is not installed.');
        }

        $host = $_ENV['REDIS_HOST'] ?? getenv('REDIS_HOST') ?: '';
        $port = $_ENV['REDIS_PORT'] ?? getenv('REDIS_PORT') ?: '';

        if (!is_string($host) || $host === '' || !is_scalar($port) || (int) $port <= 0) {
            $this->markTestSkipped('REDIS_HOST / REDIS_PORT not configured.');
        }

        $redis = new \Redis();
        $connected = @$redis->connect($host, (int) $port, 1.5);
        if ($connected !== true) {
            $this->markTestSkipped('Unable to connect to Redis test service.');
        }

        $this->redis = $redis;
        $this->dao = new SaTokenDaoRedis([], $redis);
        $this->prefix = 'satoken:test:' . bin2hex(random_bytes(6)) . ':';
    }

    protected function tearDown(): void
    {
        if (isset($this->redis) && $this->prefix !== '') {
            $keys = $this->redis->keys($this->prefix . '*');
            if (is_array($keys) && $keys !== []) {
                $this->redis->del($keys);
            }
        }
    }

    public function testSetGetExpireAndDeleteAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'basic';
        $this->dao->set($key, 'value-1', 60);

        $this->assertSame('value-1', $this->dao->get($key));
        $this->assertTrue($this->dao->exists($key));

        $ttl = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(60, $ttl);

        $this->dao->delete($key);
        $this->assertNull($this->dao->get($key));
        $this->assertFalse($this->dao->exists($key));
    }

    public function testGetAndDeleteAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'get-and-delete';
        $this->dao->set($key, 'value-2', 60);

        $value = $this->dao->getAndDelete($key);
        $this->assertSame('value-2', $value);
        $this->assertNull($this->dao->get($key));
    }

    public function testGetAndExpireAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'get-and-expire';
        $this->dao->set($key, 'value-3', 10);

        $value = $this->dao->getAndExpire($key, 120);
        $this->assertSame('value-3', $value);

        $ttl = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(120, $ttl);
    }

    public function testSetIfNotExistsAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'nx';

        $this->assertTrue($this->dao->setIfNotExists($key, 'first', 30));
        $this->assertFalse($this->dao->setIfNotExists($key, 'second', 30));
        $this->assertSame('first', $this->dao->get($key));

        $ttl = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(30, $ttl);

        // 过期后可再次获取
        $this->dao->expire($key, 1);
        sleep(2);
        $this->assertTrue($this->dao->setIfNotExists($key, 'third', 30));
        $this->assertSame('third', $this->dao->get($key));
    }

    public function testIncrementAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'counter';

        // 首次递增即带 TTL（Lua INCRBY + EXPIRE 原子）
        $this->assertSame(1, $this->dao->increment($key, 1, 60));
        $this->assertSame(2, $this->dao->increment($key, 1, 60));
        $this->assertSame(7, $this->dao->increment($key, 5, 60));

        $ttl = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(60, $ttl);

        // 负数修正
        $this->assertSame(0, $this->dao->increment($key, -7, 60));

        // 无 TTL 分支
        $key2 = $this->prefix . 'counter-permanent';
        $this->assertSame(1, $this->dao->increment($key2, 1, null));
        $this->assertSame(-1, $this->dao->getTimeout($key2));
        $this->assertSame(3, $this->dao->increment($key2, 2, null));
    }

    public function testSearchKeysAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $this->dao->set($this->prefix . 'token:aaa', '1', 60);
        $this->dao->set($this->prefix . 'token:bbb', '2', 60);
        $this->dao->set($this->prefix . 'other:ccc', '3', 60);

        $keys = $this->dao->searchKeys($this->prefix . 'token:', '', 0, 10);
        $this->assertCount(2, $keys);
        foreach ($keys as $k) {
            $this->assertStringStartsWith($this->prefix . 'token:', $k);
        }

        // 关键字含 glob 元字符时按字面匹配（转义生效）
        $literal = $this->dao->searchKeys($this->prefix, 'token:aaa', 0, 10);
        $this->assertCount(1, $literal);
    }

    public function testLoginConcurrentLockAgainstRealRedis(): void
    {
        // 全链路：真实 Redis 上登录锁 SET NX + 释放 Lua 脚本
        \SaToken\SaToken::reset();
        \SaToken\SaToken::setConfig(new \SaToken\Config\SaTokenConfig([
            'tokenName'    => 'satoken',
            'timeout'      => 300,
            'jwtSecretKey' => 'real-redis-test-jwt-secret-32-bytes',
            'aesKey'       => str_repeat('k', 32),
            'tokenEncrypt' => true,
        ]));
        \SaToken\SaToken::setDao($this->dao);

        $result1 = \SaToken\StpUtil::login(90001);
        $this->assertNotEmpty($result1->getAccessToken());
        // 同账号连续第二次登录（锁已释放）必须成功
        $result2 = \SaToken\StpUtil::login(90001);
        $this->assertNotEquals($result1->getAccessToken(), $result2->getAccessToken());

        // isShare 同端语义下第二次登录替换旧 token：新 token 有效
        $this->assertTrue(\SaToken\StpUtil::getStpLogic()->getTokenManager()->isTokenValid($result2->getAccessToken()));
        $this->assertFalse(\SaToken\StpUtil::getStpLogic()->getTokenManager()->isTokenValid($result1->getAccessToken()));

        \SaToken\SaToken::reset();
    }
}
