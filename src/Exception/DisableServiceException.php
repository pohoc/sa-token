<?php

declare(strict_types=1);

namespace SaToken\Exception;

/**
 * 账号封禁异常
 *
 * 当被封禁的账号尝试操作时抛出，包含封禁服务、等级和剩余时间
 *
 * 使用示例：
 *   try {
 *       StpUtil::checkDisable(10001, 'comment');
 *   } catch (DisableServiceException $e) {
 *       echo $e->getService();      // 'comment'
 *       echo $e->getLevel();        // 1
 *       echo $e->getRemainingTime(); // 3600
 *   }
 */
class DisableServiceException extends SaTokenException
{
    /**
     * 封禁的服务标识
     * @var string
     */
    protected string $service;

    /**
     * 封禁等级
     * @var int
     */
    protected int $level;

    /**
     * 封禁剩余时间（秒）
     * @var int
     */
    protected int $remainingTime;

    /**
     * @param string          $service       封禁的服务标识
     * @param int             $level         封禁等级
     * @param int             $remainingTime 封禁剩余时间（秒）
     * @param \Throwable|null $previous      上一个异常
     */
    public function __construct(string $service, int $level, int $remainingTime, ?\Throwable $previous = null)
    {
        $this->service = $service;
        $this->level = $level;
        $this->remainingTime = $remainingTime;
        $message = "账号已被封禁：服务[{$service}]，等级[{$level}]，剩余时间[{$remainingTime}秒]";
        parent::__construct($message, 0, $previous);
    }

    /**
     * 获取封禁的服务标识
     *
     * @return string
     */
    public function getService(): string
    {
        return $this->service;
    }

    /**
     * 获取封禁等级
     *
     * @return int
     */
    public function getLevel(): int
    {
        return $this->level;
    }

    /**
     * 获取封禁剩余时间（秒）
     *
     * @return int
     */
    public function getRemainingTime(): int
    {
        return $this->remainingTime;
    }
}
