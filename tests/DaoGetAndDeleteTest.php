<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Dao\SaTokenDaoPsr16;

class DaoGetAndDeleteTest extends TestCase
{
    public function testMemoryGetAndDeleteReturnsValueAndRemovesKey(): void
    {
        $dao = new SaTokenDaoMemory();
        $dao->set('key1', 'value1');

        $value = $dao->getAndDelete('key1');
        $this->assertEquals('value1', $value);
        $this->assertNull($dao->get('key1'));
    }

    public function testMemoryGetAndDeleteOnNonExistentKeyReturnsNull(): void
    {
        $dao = new SaTokenDaoMemory();
        $value = $dao->getAndDelete('nonexistent');
        $this->assertNull($value);
    }

    public function testMemoryGetAndDeleteIsAtomic(): void
    {
        $dao = new SaTokenDaoMemory();
        $dao->set('key1', 'value1');

        $value = $dao->getAndDelete('key1');
        $this->assertEquals('value1', $value);
        $this->assertFalse($dao->exists('key1'));
        $this->assertNull($dao->get('key1'));

        $value2 = $dao->getAndDelete('key1');
        $this->assertNull($value2);
    }

    public function testPsr16GetAndDeleteReturnsValueAndRemovesKey(): void
    {
        $cache = new ArrayPsr16Cache();
        $dao = new SaTokenDaoPsr16($cache);
        $dao->set('key1', 'value1');

        $value = $dao->getAndDelete('key1');
        $this->assertEquals('value1', $value);
        $this->assertNull($dao->get('key1'));
    }

    public function testPsr16GetAndDeleteOnNonExistentKeyReturnsNull(): void
    {
        $cache = new ArrayPsr16Cache();
        $dao = new SaTokenDaoPsr16($cache);
        $value = $dao->getAndDelete('nonexistent');
        $this->assertNull($value);
    }

    public function testPsr16GetAndDeleteIsAtomic(): void
    {
        $cache = new ArrayPsr16Cache();
        $dao = new SaTokenDaoPsr16($cache);
        $dao->set('key1', 'value1');

        $value = $dao->getAndDelete('key1');
        $this->assertEquals('value1', $value);
        $this->assertFalse($dao->exists('key1'));
        $this->assertNull($dao->get('key1'));

        $value2 = $dao->getAndDelete('key1');
        $this->assertNull($value2);
    }

    public function testPsr16GetTimeoutReturnsCorrectRemainingTime(): void
    {
        $cache = new ArrayPsr16Cache();
        $dao = new SaTokenDaoPsr16($cache);
        $dao->set('key1', 'value1', 3600);

        $timeout = $dao->getTimeout('key1');
        $this->assertGreaterThan(0, $timeout);
        $this->assertLessThanOrEqual(3600, $timeout);
    }

    public function testPsr16UpdatePreservesTtl(): void
    {
        $cache = new ArrayPsr16Cache();
        $dao = new SaTokenDaoPsr16($cache);
        $dao->set('key1', 'value1', 3600);

        $timeoutBefore = $dao->getTimeout('key1');
        $this->assertGreaterThan(0, $timeoutBefore);

        $dao->update('key1', 'updated-value');
        $this->assertEquals('updated-value', $dao->get('key1'));

        $timeoutAfter = $dao->getTimeout('key1');
        $this->assertGreaterThan(0, $timeoutAfter);
        $this->assertLessThanOrEqual($timeoutBefore, $timeoutAfter);
    }
}
