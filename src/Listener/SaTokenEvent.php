<?php

declare(strict_types=1);

namespace SaToken\Listener;

/**
 * Sa-Token 事件分发器
 *
 * 支持注册多个监听器，事件触发时按注册顺序依次调用
 *
 * 使用示例：
 *   $dispatcher = new SaTokenEvent();
 *   $dispatcher->addListener(new MyListener());
 *   $dispatcher->onLogin('login', 10001, 'xxx-token', $parameter);
 */
class SaTokenEvent
{
    /**
     * 已注册的监听器列表
     * @var SaTokenListenerInterface[]
     */
    protected array $listeners = [];

    /**
     * 添加监听器
     *
     * @param  SaTokenListenerInterface $listener 事件监听器
     * @return static
     */
    public function addListener(SaTokenListenerInterface $listener): static
    {
        $this->listeners[] = $listener;
        return $this;
    }

    /**
     * 移除所有监听器
     *
     * @return static
     */
    public function clearListeners(): static
    {
        $this->listeners = [];
        return $this;
    }

    /**
     * 获取所有监听器
     *
     * @return SaTokenListenerInterface[]
     */
    public function getListeners(): array
    {
        return $this->listeners;
    }

    /**
     * 登录事件
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    登录 ID
     * @param  string $tokenValue Token 值
     * @param  mixed  $parameter  登录参数
     * @return void
     */
    public function onLogin(string $loginType, mixed $loginId, string $tokenValue, mixed $parameter): void
    {
        foreach ($this->listeners as $listener) {
            $listener->onLogin($loginType, $loginId, $tokenValue, $parameter);
        }
    }

    /**
     * 注销事件
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    登录 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onLogout(string $loginType, mixed $loginId, string $tokenValue): void
    {
        foreach ($this->listeners as $listener) {
            $listener->onLogout($loginType, $loginId, $tokenValue);
        }
    }

    /**
     * 踢人下线事件
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    登录 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onKickout(string $loginType, mixed $loginId, string $tokenValue): void
    {
        foreach ($this->listeners as $listener) {
            $listener->onKickout($loginType, $loginId, $tokenValue);
        }
    }

    /**
     * 被顶下线事件
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    登录 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onReplaced(string $loginType, mixed $loginId, string $tokenValue): void
    {
        foreach ($this->listeners as $listener) {
            $listener->onReplaced($loginType, $loginId, $tokenValue);
        }
    }

    /**
     * 封禁事件
     *
     * @param  string $loginType 登录类型
     * @param  mixed  $loginId   登录 ID
     * @param  string $service   封禁服务
     * @param  int    $level     封禁等级
     * @param  int    $timeout   封禁时长（秒）
     * @return void
     */
    public function onBlock(string $loginType, mixed $loginId, string $service, int $level, int $timeout): void
    {
        foreach ($this->listeners as $listener) {
            $listener->onBlock($loginType, $loginId, $service, $level, $timeout);
        }
    }

    /**
     * 身份切换事件
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    当前登录 ID
     * @param  mixed  $switchToId 切换目标 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onSwitch(string $loginType, mixed $loginId, mixed $switchToId, string $tokenValue): void
    {
        foreach ($this->listeners as $listener) {
            $listener->onSwitch($loginType, $loginId, $switchToId, $tokenValue);
        }
    }

    /**
     * 身份切换回来事件
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    当前登录 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onSwitchBack(string $loginType, mixed $loginId, string $tokenValue): void
    {
        foreach ($this->listeners as $listener) {
            $listener->onSwitchBack($loginType, $loginId, $tokenValue);
        }
    }
}
