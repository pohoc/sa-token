<?php

declare(strict_types=1);

namespace SaToken\Exception;

/**
 * 未登录异常
 *
 * 当用户未登录或 Token 已过期/被踢/被顶时抛出
 *
 * 使用示例：
 *   try {
 *       StpUtil::checkLogin();
 *   } catch (NotLoginException $e) {
 *       echo $e->getType(); // 如 '-1'、'-2'、'-3'、'-4'、'-5'
 *   }
 */
class NotLoginException extends SaTokenException
{
    /**
     * 未登录类型常量
     */
    public const NOT_LOGIN = '-1';
    public const TOKEN_TIMEOUT = '-2';
    public const TOKEN_KICKOUT = '-3';
    public const TOKEN_REPLACE = '-4';
    public const NOT_SAFE = '-5';

    /**
     * 具体的未登录类型
     * @var string
     */
    protected string $type;

    /**
     * @param string          $message  错误信息
     * @param string          $type     未登录类型（NOT_LOGIN/TOKEN_TIMEOUT/TOKEN_KICKOUT/TOKEN_REPLACE/NOT_SAFE）
     * @param \Throwable|null $previous 上一个异常
     */
    public function __construct(string $message, string $type = self::NOT_LOGIN, ?\Throwable $previous = null)
    {
        $this->type = $type;
        parent::__construct($message, 0, $previous);
    }

    /**
     * 获取未登录的具体类型
     *
     * @return string 类型常量值
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * 是否为 Token 过期
     *
     * @return bool
     */
    public function isTimeout(): bool
    {
        return $this->type === self::TOKEN_TIMEOUT;
    }

    /**
     * 是否为 Token 被踢
     *
     * @return bool
     */
    public function isKickout(): bool
    {
        return $this->type === self::TOKEN_KICKOUT;
    }

    /**
     * 是否为 Token 被顶
     *
     * @return bool
     */
    public function isReplace(): bool
    {
        return $this->type === self::TOKEN_REPLACE;
    }

    /**
     * 是否为二级认证未通过
     *
     * @return bool
     */
    public function isNotSafe(): bool
    {
        return $this->type === self::NOT_SAFE;
    }
}
