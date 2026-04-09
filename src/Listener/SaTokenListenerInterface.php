<?php

declare(strict_types=1);

namespace SaToken\Listener;

/**
 * Sa-Token 事件监听接口
 *
 * 用户实现此接口以监听登录/注销/踢出/封禁/身份切换等事件
 *
 * 使用示例：
 *   class MyListener implements SaTokenListenerInterface {
 *       public function onLogin(string $loginType, mixed $loginId, string $tokenValue, SaLoginParameter $parameter): void {
 *           // 记录登录日志
 *       }
 *   }
 */
interface SaTokenListenerInterface
{
    /**
     * 每次登录时触发
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    登录 ID
     * @param  string $tokenValue Token 值
     * @param  mixed  $parameter  登录参数
     * @return void
     */
    public function onLogin(string $loginType, mixed $loginId, string $tokenValue, mixed $parameter): void;

    /**
     * 每次注销时触发
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    登录 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onLogout(string $loginType, mixed $loginId, string $tokenValue): void;

    /**
     * 每次踢人下线时触发
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    登录 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onKickout(string $loginType, mixed $loginId, string $tokenValue): void;

    /**
     * 每次被顶下线时触发
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    登录 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onReplaced(string $loginType, mixed $loginId, string $tokenValue): void;

    /**
     * 每次账号被封禁时触发
     *
     * @param  string $loginType 登录类型
     * @param  mixed  $loginId   登录 ID
     * @param  string $service   封禁服务
     * @param  int    $level     封禁等级
     * @param  int    $timeout   封禁时长（秒）
     * @return void
     */
    public function onBlock(string $loginType, mixed $loginId, string $service, int $level, int $timeout): void;

    /**
     * 每次身份切换时触发
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    当前登录 ID
     * @param  mixed  $switchToId 切换目标 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onSwitch(string $loginType, mixed $loginId, mixed $switchToId, string $tokenValue): void;

    /**
     * 每次身份切换回来时触发
     *
     * @param  string $loginType  登录类型
     * @param  mixed  $loginId    当前登录 ID
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function onSwitchBack(string $loginType, mixed $loginId, string $tokenValue): void;
}
