<?php

declare(strict_types=1);

namespace SaToken\Exception;

/**
 * 无权限异常
 *
 * 当用户缺少指定权限时抛出
 *
 * 使用示例：
 *   try {
 *       StpUtil::checkPermission('user:add');
 *   } catch (NotPermissionException $e) {
 *       echo $e->getPermission(); // 'user:add'
 *   }
 */
class NotPermissionException extends SaTokenException
{
    /**
     * 缺少的权限码
     * @var string
     */
    protected string $permission;

    /**
     * @param string          $permission 缺少的权限码
     * @param \Throwable|null $previous   上一个异常
     */
    public function __construct(string $permission, ?\Throwable $previous = null)
    {
        $this->permission = $permission;
        parent::__construct("缺少权限：{$permission}", 0, $previous);
    }

    /**
     * 获取缺少的权限码
     *
     * @return string
     */
    public function getPermission(): string
    {
        return $this->permission;
    }
}
