<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\SaRouter;

class SaRouterFullTest extends TestCase
{
    protected function setUp(): void
    {
        SaRouter::fullReset();
    }

    protected function tearDown(): void
    {
        SaRouter::fullReset();
    }

    // ======== 精确匹配 ========

    public function testExactMatch(): void
    {
        SaRouter::setCurrentPath('/user/info');
        $matched = false;
        SaRouter::match('/user/info')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testExactMatchFail(): void
    {
        SaRouter::setCurrentPath('/user/list');
        $matched = false;
        SaRouter::match('/user/info')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertFalse($matched);
    }

    // ======== ** 多级通配 ========

    public function testDoubleStarMatchSubPaths(): void
    {
        SaRouter::setCurrentPath('/user/info/detail');
        $matched = false;
        SaRouter::match('/user/**')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testDoubleStarMatchEmptyPath(): void
    {
        SaRouter::setCurrentPath('/user');
        $matched = false;
        SaRouter::match('/user/**')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testDoubleStarMatchRootSubPath(): void
    {
        SaRouter::setCurrentPath('/user/list');
        $matched = false;
        SaRouter::match('/user/**')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    // ======== * 单级通配 ========

    public function testSingleStarMatchOneLevel(): void
    {
        SaRouter::setCurrentPath('/user/info');
        $matched = false;
        SaRouter::match('/user/*')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testSingleStarNotMatchTwoLevels(): void
    {
        SaRouter::setCurrentPath('/user/info/detail');
        $matched = false;
        SaRouter::match('/user/*')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertFalse($matched);
    }

    // ======== notMatch ========

    public function testNotMatchExclude(): void
    {
        SaRouter::setCurrentPath('/public/api');
        $matched = false;
        SaRouter::notMatch('/public/**')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertFalse($matched);
    }

    public function testNotMatchPass(): void
    {
        SaRouter::setCurrentPath('/api/user');
        $matched = false;
        SaRouter::notMatch('/public/**')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testNotMatchMultiplePatterns(): void
    {
        SaRouter::setCurrentPath('/public/api');
        $matched = false;
        SaRouter::notMatch('/public/**', '/static/**')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertFalse($matched);
    }

    // ======== 多模式 ========

    public function testMultiplePatternsAnyMatch(): void
    {
        SaRouter::setCurrentPath('/admin/dashboard');
        $matched = false;
        SaRouter::match('/user/**', '/admin/**')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testMultiplePatternsNoneMatch(): void
    {
        SaRouter::setCurrentPath('/other/path');
        $matched = false;
        SaRouter::match('/user/**', '/admin/**')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertFalse($matched);
    }

    // ======== 边界情况 ========

    public function testRootPath(): void
    {
        SaRouter::setCurrentPath('/');
        $matched = false;
        SaRouter::match('/')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testEmptyPathNoMatch(): void
    {
        SaRouter::setCurrentPath('/user/info');
        $matched = false;
        SaRouter::match('')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertFalse($matched);
    }

    public function testPathWithTrailingSlash(): void
    {
        SaRouter::setCurrentPath('/user/info/');
        $matched = false;
        SaRouter::match('/user/info/')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testDoubleStarInMiddle(): void
    {
        SaRouter::setCurrentPath('/api/v1/user/list');
        $matched = false;
        SaRouter::match('/api/**/list')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testSingleStarInMiddle(): void
    {
        SaRouter::setCurrentPath('/api/v1/list');
        $matched = false;
        SaRouter::match('/api/*/list')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testSingleStarInMiddleNotMatchMultiLevel(): void
    {
        SaRouter::setCurrentPath('/api/v1/v2/list');
        $matched = false;
        SaRouter::match('/api/*/list')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertFalse($matched);
    }

    // ======== stop ========

    public function testStopPreventsCheck(): void
    {
        SaRouter::setCurrentPath('/user/info');

        $count = 0;
        SaRouter::match('/user/**')->check(function () use (&$count) {
            $count++;
        });

        // 新的链式调用，stop 应阻断后续 check
        SaRouter::fullReset();
        SaRouter::setCurrentPath('/user/info');
        SaRouter::match('/user/**')->stop();

        // stop 后同一链式调用不会再 check
        $this->assertEquals(1, $count); // 只执行了第一次
    }

    // ======== 组合链式调用 ========

    public function testNotMatchAndMatchCombined(): void
    {
        SaRouter::setCurrentPath('/api/user');

        $matched = false;
        SaRouter::notMatch('/public/**')
            ->match('/api/**')
            ->check(function () use (&$matched) {
                $matched = true;
            });

        $this->assertTrue($matched);
    }

    public function testNotMatchBlocksMatch(): void
    {
        SaRouter::setCurrentPath('/public/api');

        $matched = false;
        SaRouter::notMatch('/public/**')
            ->match('/api/**')
            ->check(function () use (&$matched) {
                $matched = true;
            });

        $this->assertFalse($matched);
    }

    // ======== 特殊字符路径 ========

    public function testPathWithNumbers(): void
    {
        SaRouter::setCurrentPath('/api/v2/users');
        $matched = false;
        SaRouter::match('/api/v2/users')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }

    public function testPathWithHyphen(): void
    {
        SaRouter::setCurrentPath('/user-profile/settings');
        $matched = false;
        SaRouter::match('/user-profile/settings')->check(function () use (&$matched) {
            $matched = true;
        });
        $this->assertTrue($matched);
    }
}
