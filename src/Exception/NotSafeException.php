<?php

declare(strict_types=1);

namespace SaToken\Exception;

/**
 * 二级认证未通过异常
 *
 * 当需要二级认证（Safe 验证）但未通过时抛出
 *
 * 使用示例：
 *   try {
 *       StpUtil::checkSafe();
 *   } catch (NotSafeException $e) {
 *       // 提示用户需要二次验证
 *   }
 */
class NotSafeException extends SaTokenException
{
    /**
     * @param string          $message  错误信息
     * @param \Throwable|null $previous 上一个异常
     */
    public function __construct(string $message = '二级认证未通过，请先完成二次验证', ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
