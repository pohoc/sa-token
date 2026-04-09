<?php

declare(strict_types=1);

namespace SaToken\Exception;

/**
 * Sa-Token 基础异常类
 *
 * 所有 Sa-Token 异常的基类，包含错误码和错误信息
 */
class SaTokenException extends \RuntimeException
{
    /**
     * @param string          $message  错误信息
     * @param int             $code     错误码
     * @param \Throwable|null $previous 上一个异常
     */
    public function __construct(string $message = '', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
