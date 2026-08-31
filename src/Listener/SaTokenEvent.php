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
     * 最近一次被隔离的监听器异常（按触发顺序）
     * @var array<\Throwable>
     */
    protected array $listenerErrors = [];

    /**
     * 获取被隔离的监听器异常（用于调用方自行告警/记录）
     *
     * @return array<\Throwable>
     */
    public function getListenerErrors(): array
    {
        return $this->listenerErrors;
    }

    /**
     * 分发单个事件方法并隔离监听器异常。
     *
     * login() 等主流程在事件触发时已完成存储写入，
     * 监听器抛异常若不隔离会造成"已登录但调用方收到异常"的部分成功状态；
     * 隔离后通过 trigger_error 暴露问题，不静默吞掉
     */
    protected function dispatch(SaTokenListenerInterface $listener, callable $invocation): void
    {
        try {
            $invocation($listener);
        } catch (\Throwable $e) {
            $this->listenerErrors[] = $e;
            // error_log 而非 trigger_error：主流程必须继续，同时问题进入系统日志可被发现
            error_log(
                'Sa-Token 事件监听器异常（已隔离，不影响主流程）: ' . get_class($listener) . ' - ' . $e->getMessage()
            );
        }
    }

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
            $this->dispatch($listener, fn (SaTokenListenerInterface $l) => $l->onLogin($loginType, $loginId, $tokenValue, $parameter));
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
            $this->dispatch($listener, fn (SaTokenListenerInterface $l) => $l->onLogout($loginType, $loginId, $tokenValue));
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
            $this->dispatch($listener, fn (SaTokenListenerInterface $l) => $l->onKickout($loginType, $loginId, $tokenValue));
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
            $this->dispatch($listener, fn (SaTokenListenerInterface $l) => $l->onReplaced($loginType, $loginId, $tokenValue));
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
            $this->dispatch($listener, fn (SaTokenListenerInterface $l) => $l->onBlock($loginType, $loginId, $service, $level, $timeout));
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
            $this->dispatch($listener, fn (SaTokenListenerInterface $l) => $l->onSwitch($loginType, $loginId, $switchToId, $tokenValue));
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
            $this->dispatch($listener, fn (SaTokenListenerInterface $l) => $l->onSwitchBack($loginType, $loginId, $tokenValue));
        }
    }
}
