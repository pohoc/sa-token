<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoRedis;

class RedisDaoTest extends TestCase
{
    /** @var \Redis&MockObject */
    protected $mockRedis;
    protected SaTokenDaoRedis $dao;

    protected function setUp(): void
    {
        // 创建 Redis Mock 对象
        $this->mockRedis = $this->createMock(\Redis::class);
        // 注入 Mock 到 SaTokenDaoRedis（需要通过构造函数或者反射注入）
        // 由于 SaTokenDaoRedis 没有提供直接注入的方式，我们用反射
        $reflection = new \ReflectionClass(SaTokenDaoRedis::class);
        $this->dao = $reflection->newInstanceWithoutConstructor();

        // 注入属性
        $clientProp = $reflection->getProperty('client');
        $clientProp->setAccessible(true);
        $clientProp->setValue($this->dao, $this->mockRedis);

        $saRedisProp = $reflection->getProperty('saRedis');
        $saRedisProp->setAccessible(true);
        $saRedisProp->setValue($this->dao, null);
    }

    public function testSetAndGet(): void
    {
        $key = 'test:key';
        $value = 'test:value';

        // 设置 mock 行为
        $this->mockRedis
            ->expects($this->once())
            ->method('setex')
            ->with($key, 3600, $value);

        $this->mockRedis
            ->expects($this->once())
            ->method('get')
            ->with($key)
            ->willReturn($value);

        $this->dao->set($key, $value, 3600);
        $result = $this->dao->get($key);
        $this->assertEquals($value, $result);
    }

    public function testDelete(): void
    {
        $key = 'test:delete';

        $this->mockRedis
            ->expects($this->once())
            ->method('del')
            ->with([$key]);

        $this->dao->delete($key);
    }

    public function testDeleteMultiple(): void
    {
        $keys = ['key1', 'key2', 'key3'];

        $this->mockRedis
            ->expects($this->once())
            ->method('del')
            ->with($keys);

        $this->dao->deleteMultiple($keys);
    }

    public function testExpire(): void
    {
        $key = 'test:expire';
        $ttl = 1800;

        $this->mockRedis
            ->expects($this->once())
            ->method('expire')
            ->with($key, $ttl);

        $this->dao->expire($key, $ttl);
    }

    public function testGetTimeout(): void
    {
        $key = 'test:timeout';
        $expectedTtl = 3600;

        $this->mockRedis
            ->expects($this->once())
            ->method('ttl')
            ->with($key)
            ->willReturn($expectedTtl);

        $ttl = $this->dao->getTimeout($key);
        $this->assertEquals($expectedTtl, $ttl);
    }

    public function testExists(): void
    {
        $key = 'test:exists';

        $this->mockRedis
            ->expects($this->exactly(2))
            ->method('exists')
            ->with($key)
            ->willReturnOnConsecutiveCalls(1, 0);

        $this->assertTrue($this->dao->exists($key));
        $this->assertFalse($this->dao->exists($key));
    }
}
