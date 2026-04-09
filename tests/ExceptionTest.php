<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Exception\DisableServiceException;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotPermissionException;
use SaToken\Exception\NotRoleException;
use SaToken\Exception\NotSafeException;
use SaToken\Exception\SaTokenException;

class ExceptionTest extends TestCase
{
    // ---- SaTokenException ----

    public function testSaTokenExceptionMessage(): void
    {
        $e = new SaTokenException('test error');
        $this->assertEquals('test error', $e->getMessage());
    }

    public function testSaTokenExceptionCode(): void
    {
        $e = new SaTokenException('error', 500);
        $this->assertEquals(500, $e->getCode());
    }

    public function testSaTokenExceptionPrevious(): void
    {
        $prev = new \RuntimeException('previous');
        $e = new SaTokenException('error', 0, $prev);
        $this->assertSame($prev, $e->getPrevious());
    }

    public function testSaTokenExceptionIsRuntimeException(): void
    {
        $e = new SaTokenException('test');
        $this->assertInstanceOf(\RuntimeException::class, $e);
    }

    // ---- NotLoginException ----

    public function testNotLoginExceptionDefaultType(): void
    {
        $e = new NotLoginException('未登录');
        $this->assertEquals(NotLoginException::NOT_LOGIN, $e->getType());
        $this->assertEquals('-1', $e->getType());
    }

    public function testNotLoginExceptionTokenTimeout(): void
    {
        $e = new NotLoginException('Token 过期', NotLoginException::TOKEN_TIMEOUT);
        $this->assertEquals('-2', $e->getType());
        $this->assertTrue($e->isTimeout());
        $this->assertFalse($e->isKickout());
    }

    public function testNotLoginExceptionKickout(): void
    {
        $e = new NotLoginException('被踢', NotLoginException::TOKEN_KICKOUT);
        $this->assertEquals('-3', $e->getType());
        $this->assertTrue($e->isKickout());
        $this->assertFalse($e->isTimeout());
    }

    public function testNotLoginExceptionReplace(): void
    {
        $e = new NotLoginException('被顶', NotLoginException::TOKEN_REPLACE);
        $this->assertEquals('-4', $e->getType());
        $this->assertTrue($e->isReplace());
    }

    public function testNotLoginExceptionNotSafe(): void
    {
        $e = new NotLoginException('不安全', NotLoginException::NOT_SAFE);
        $this->assertEquals('-5', $e->getType());
        $this->assertTrue($e->isNotSafe());
    }

    public function testNotLoginExceptionInheritance(): void
    {
        $e = new NotLoginException('test');
        $this->assertInstanceOf(SaTokenException::class, $e);
    }

    // ---- NotPermissionException ----

    public function testNotPermissionException(): void
    {
        $e = new NotPermissionException('user:add');
        $this->assertEquals('user:add', $e->getPermission());
        $this->assertStringContainsString('user:add', $e->getMessage());
    }

    public function testNotPermissionExceptionInheritance(): void
    {
        $e = new NotPermissionException('test');
        $this->assertInstanceOf(SaTokenException::class, $e);
    }

    // ---- NotRoleException ----

    public function testNotRoleException(): void
    {
        $e = new NotRoleException('admin');
        $this->assertEquals('admin', $e->getRole());
        $this->assertStringContainsString('admin', $e->getMessage());
    }

    public function testNotRoleExceptionInheritance(): void
    {
        $e = new NotRoleException('test');
        $this->assertInstanceOf(SaTokenException::class, $e);
    }

    // ---- DisableServiceException ----

    public function testDisableServiceException(): void
    {
        $e = new DisableServiceException('comment', 2, 3600);
        $this->assertEquals('comment', $e->getService());
        $this->assertEquals(2, $e->getLevel());
        $this->assertEquals(3600, $e->getRemainingTime());
        $this->assertStringContainsString('comment', $e->getMessage());
        $this->assertStringContainsString('2', $e->getMessage());
    }

    public function testDisableServiceExceptionInheritance(): void
    {
        $e = new DisableServiceException('test', 1, 0);
        $this->assertInstanceOf(SaTokenException::class, $e);
    }

    // ---- NotSafeException ----

    public function testNotSafeExceptionDefaultMessage(): void
    {
        $e = new NotSafeException();
        $this->assertStringContainsString('二级认证', $e->getMessage());
    }

    public function testNotSafeExceptionCustomMessage(): void
    {
        $e = new NotSafeException('自定义消息');
        $this->assertEquals('自定义消息', $e->getMessage());
    }

    public function testNotSafeExceptionInheritance(): void
    {
        $e = new NotSafeException();
        $this->assertInstanceOf(SaTokenException::class, $e);
    }
}
