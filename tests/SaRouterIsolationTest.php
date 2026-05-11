<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\SaRouter;
use SaToken\Util\SaTokenContext;

class SaRouterIsolationTest extends TestCase
{
    protected function setUp(): void
    {
        SaRouter::fullReset();
        SaTokenContext::setContextId('default');
    }

    protected function tearDown(): void
    {
        SaRouter::fullReset();
        SaTokenContext::setContextId('default');
    }

    public function testTwoMatchCallsDoNotInterfere(): void
    {
        SaRouter::setCurrentPath('/user/info');

        $matched1 = false;
        SaRouter::match('/user/**')->check(function () use (&$matched1) {
            $matched1 = true;
        });

        $this->assertTrue($matched1);

        SaRouter::setCurrentPath('/admin/dashboard');

        $matched2 = false;
        SaRouter::match('/user/**')->check(function () use (&$matched2) {
            $matched2 = true;
        });

        $this->assertFalse($matched2);
    }

    public function testStopOnOneContextDoesNotAffectAnother(): void
    {
        SaTokenContext::setContextId('ctx-a');
        SaRouter::setCurrentPath('/user/info');
        $routerA = SaRouter::match('/user/**')->stop();

        SaTokenContext::setContextId('ctx-b');
        SaRouter::setCurrentPath('/user/info');

        $matched = false;
        SaRouter::match('/user/**')->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertTrue($matched);

        SaTokenContext::setContextId('ctx-a');

        $checked = false;
        $routerA->check(function () use (&$checked) {
            $checked = true;
        });

        $this->assertFalse($checked);
    }

    public function testClearContextProperlyCleansUp(): void
    {
        SaRouter::setCurrentPath('/user/info');
        SaTokenContext::setContextId('ctx-clear');

        $matched = false;
        SaRouter::match('/user/**')->stop()->check(function () use (&$matched) {
            $matched = true;
        });

        $this->assertFalse($matched);

        SaRouter::clearContext();

        $matched2 = false;
        SaRouter::match('/user/**')->check(function () use (&$matched2) {
            $matched2 = true;
        });

        $this->assertTrue($matched2);
    }

    public function testFullResetClearsAllState(): void
    {
        SaTokenContext::setContextId('ctx-x');
        SaRouter::setCurrentPath('/user/info');
        SaRouter::match('/user/**')->stop();

        SaTokenContext::setContextId('ctx-y');
        SaRouter::setCurrentPath('/admin/panel');
        SaRouter::match('/admin/**')->stop();

        SaRouter::fullReset();

        SaTokenContext::setContextId('ctx-x');
        SaRouter::setCurrentPath('/user/info');

        $matched1 = false;
        SaRouter::match('/user/**')->check(function () use (&$matched1) {
            $matched1 = true;
        });
        $this->assertTrue($matched1);

        SaTokenContext::setContextId('ctx-y');
        SaRouter::setCurrentPath('/admin/panel');

        $matched2 = false;
        SaRouter::match('/admin/**')->check(function () use (&$matched2) {
            $matched2 = true;
        });
        $this->assertTrue($matched2);
    }
}
