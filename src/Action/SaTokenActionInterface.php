<?php

declare(strict_types=1);

namespace SaToken\Action;

/**
 * Sa-Token 业务行为接口
 *
 * 由用户业务实现，提供权限列表、角色列表等数据
 *
 * 使用示例：
 *   class MyAction implements SaTokenActionInterface {
 *       public function getPermissionList(mixed $loginId, string $loginType): array {
 *           return ['user:add', 'user:delete'];
 *       }
 *       public function getRoleList(mixed $loginId, string $loginType): array {
 *           return ['admin', 'user'];
 *       }
 *   }
 */
interface SaTokenActionInterface
{
    /**
     * 获取指定账号的权限列表
     *
     * @param  mixed         $loginId   登录 ID
     * @param  string        $loginType 登录类型
     * @return array<string> 权限码列表
     */
    public function getPermissionList(mixed $loginId, string $loginType): array;

    /**
     * 获取指定账号的角色列表
     *
     * @param  mixed         $loginId   登录 ID
     * @param  string        $loginType 登录类型
     * @return array<string> 角色标识列表
     */
    public function getRoleList(mixed $loginId, string $loginType): array;
}
