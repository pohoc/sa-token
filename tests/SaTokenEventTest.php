<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Listener\SaTokenEvent;
use SaToken\Listener\SaTokenListenerInterface;
use SaToken\SaLoginParameter;

class SaTokenEventTest extends TestCase
{
    protected SaTokenEvent $event;

    protected function setUp(): void
    {
        $this->event = new SaTokenEvent();
    }

    public function testAddListener(): void
    {
        $listener = $this->createMock(SaTokenListenerInterface::class);
        $this->event->addListener($listener);
        $this->assertCount(1, $this->event->getListeners());
    }

    public function testAddMultipleListeners(): void
    {
        $this->event->addListener($this->createMock(SaTokenListenerInterface::class));
        $this->event->addListener($this->createMock(SaTokenListenerInterface::class));
        $this->event->addListener($this->createMock(SaTokenListenerInterface::class));
        $this->assertCount(3, $this->event->getListeners());
    }

    public function testClearListeners(): void
    {
        $this->event->addListener($this->createMock(SaTokenListenerInterface::class));
        $this->event->addListener($this->createMock(SaTokenListenerInterface::class));
        $this->event->clearListeners();
        $this->assertCount(0, $this->event->getListeners());
    }

    // ---- Event Dispatch Tests ----

    public function testOnLogin(): void
    {
        $param = new SaLoginParameter();
        $listener = $this->createMock(SaTokenListenerInterface::class);
        $listener->expects($this->once())
            ->method('onLogin')
            ->with('login', 10001, 'token-123', $param);

        $this->event->addListener($listener);
        $this->event->onLogin('login', 10001, 'token-123', $param);
    }

    public function testOnLogout(): void
    {
        $listener = $this->createMock(SaTokenListenerInterface::class);
        $listener->expects($this->once())
            ->method('onLogout')
            ->with('login', 10001, 'token-123');

        $this->event->addListener($listener);
        $this->event->onLogout('login', 10001, 'token-123');
    }

    public function testOnKickout(): void
    {
        $listener = $this->createMock(SaTokenListenerInterface::class);
        $listener->expects($this->once())
            ->method('onKickout')
            ->with('login', 10001, 'token-123');

        $this->event->addListener($listener);
        $this->event->onKickout('login', 10001, 'token-123');
    }

    public function testOnReplaced(): void
    {
        $listener = $this->createMock(SaTokenListenerInterface::class);
        $listener->expects($this->once())
            ->method('onReplaced')
            ->with('login', 10001, 'token-123');

        $this->event->addListener($listener);
        $this->event->onReplaced('login', 10001, 'token-123');
    }

    public function testOnBlock(): void
    {
        $listener = $this->createMock(SaTokenListenerInterface::class);
        $listener->expects($this->once())
            ->method('onBlock')
            ->with('login', 10001, 'comment', 2, 3600);

        $this->event->addListener($listener);
        $this->event->onBlock('login', 10001, 'comment', 2, 3600);
    }

    public function testOnSwitch(): void
    {
        $listener = $this->createMock(SaTokenListenerInterface::class);
        $listener->expects($this->once())
            ->method('onSwitch')
            ->with('login', 10001, 20001, 'token-123');

        $this->event->addListener($listener);
        $this->event->onSwitch('login', 10001, 20001, 'token-123');
    }

    public function testOnSwitchBack(): void
    {
        $listener = $this->createMock(SaTokenListenerInterface::class);
        $listener->expects($this->once())
            ->method('onSwitchBack')
            ->with('login', 10001, 'token-123');

        $this->event->addListener($listener);
        $this->event->onSwitchBack('login', 10001, 'token-123');
    }

    // ---- Multiple Listener Dispatch ----

    public function testMultipleListenersAllReceiveEvent(): void
    {
        $listener1 = $this->createMock(SaTokenListenerInterface::class);
        $listener1->expects($this->once())->method('onLogin');

        $listener2 = $this->createMock(SaTokenListenerInterface::class);
        $listener2->expects($this->once())->method('onLogin');

        $listener3 = $this->createMock(SaTokenListenerInterface::class);
        $listener3->expects($this->once())->method('onLogin');

        $this->event->addListener($listener1);
        $this->event->addListener($listener2);
        $this->event->addListener($listener3);

        $this->event->onLogin('login', 10001, 'token', new SaLoginParameter());
    }

    public function testNoListenersNoError(): void
    {
        // 无监听器时不抛异常
        $this->event->onLogin('login', 10001, 'token', new SaLoginParameter());
        $this->event->onLogout('login', 10001, 'token');
        $this->assertTrue(true); // 只要没抛异常就通过
    }

    // ---- Listener Order ----

    public function testListenersCalledInOrder(): void
    {
        $order = [];
        $listener1 = $this->createMock(SaTokenListenerInterface::class);
        $listener1->method('onLogin')->willReturnCallback(function () use (&$order) {
            $order[] = 1;
        });
        $listener2 = $this->createMock(SaTokenListenerInterface::class);
        $listener2->method('onLogin')->willReturnCallback(function () use (&$order) {
            $order[] = 2;
        });

        $this->event->addListener($listener1);
        $this->event->addListener($listener2);
        $this->event->onLogin('login', 10001, 'token', new SaLoginParameter());

        $this->assertEquals([1, 2], $order);
    }
}
