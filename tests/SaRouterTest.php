<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\SaRouter;

class SaRouterTest extends TestCase
{
    protected function setUp(): void
    {
        SaRouter::fullReset();
    }

    protected function tearDown(): void
    {
        SaRouter::fullReset();
    }

    public function testExactMatch(): void
    {
        SaRouter::setCurrentPath('/user/info');

        $matched = false;
        SaRouter::match('/user/info')->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertTrue($matched);
    }

    public function testWildcardMatch(): void
    {
        SaRouter::setCurrentPath('/user/info/detail');

        $matched = false;
        SaRouter::match('/user/**')->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertTrue($matched);
    }

    public function testSingleLevelWildcard(): void
    {
        SaRouter::setCurrentPath('/user/info');

        $matched = false;
        SaRouter::match('/user/*')->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertTrue($matched);

        // 多级不应匹配
        SaRouter::fullReset();
        SaRouter::setCurrentPath('/user/info/detail');

        $matched2 = false;
        SaRouter::match('/user/*')->check(function () use (&$matched2) {
            $matched2 = true;
        });

        $this->assertFalse($matched2);
    }

    public function testNotMatch(): void
    {
        SaRouter::setCurrentPath('/public/api');

        $matched = false;
        SaRouter::notMatch('/public/**')->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertFalse($matched);
    }

    public function testNotMatchThenMatch(): void
    {
        SaRouter::setCurrentPath('/api/user');

        $matched = false;
        SaRouter::notMatch('/public/**')->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertTrue($matched);
    }

    public function testMultiplePatterns(): void
    {
        SaRouter::setCurrentPath('/admin/dashboard');

        $matched = false;
        SaRouter::match('/user/**', '/admin/**')->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertTrue($matched);
    }

    public function testNoMatch(): void
    {
        SaRouter::setCurrentPath('/other/path');

        $matched = false;
        SaRouter::match('/user/**')->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertFalse($matched);
    }

    public function testStop(): void
    {
        SaRouter::setCurrentPath('/user/info');

        $count = 0;
        SaRouter::match('/user/**')->check(function () use (&$count) {
            $count++;
        });

        // stop 之后不再匹配（新的 match 会重置状态）
        SaRouter::fullReset();
        SaRouter::setCurrentPath('/user/info');
        SaRouter::match('/user/**')->stop();

        $matched = false;
        SaRouter::match('/user/**')->check(function () use (&$matched) {
            $matched = true;
        });

        // stop 只影响当前链式调用，新 match 已重置
        $this->assertTrue($matched);
    }
}
