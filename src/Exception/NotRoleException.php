<?php

declare(strict_types=1);

namespace SaToken\Exception;

/**
 * 无角色异常
 *
 * 当用户缺少指定角色时抛出
 *
 * 使用示例：
 *   try {
 *       StpUtil::checkRole('admin');
 *   } catch (NotRoleException $e) {
 *       echo $e->getRole(); // 'admin'
 *   }
 */
class NotRoleException extends SaTokenException
{
    /**
     * 缺少的角色标识
     * @var string
     */
    protected string $role;

    /**
     * @param string          $role     缺少的角色标识
     * @param \Throwable|null $previous 上一个异常
     */
    public function __construct(string $role, ?\Throwable $previous = null)
    {
        $this->role = $role;
        parent::__construct("缺少角色：{$role}", 0, $previous);
    }

    /**
     * 获取缺少的角色标识
     *
     * @return string
     */
    public function getRole(): string
    {
        return $this->role;
    }
}
