<?php

declare(strict_types=1);

namespace SaToken;

/**
 * Token 信息数据类
 *
 * 封装 Token 的完整元数据信息
 *
 * 使用示例：
 *   $info = StpUtil::getTokenInfo();
 *   echo $info->getTokenValue();
 *   echo $info->getLoginId();
 *   echo $info->getTimeout();
 */
class SaTokenInfo
{
    /**
     * Token 名称
     */
    protected string $tokenName = '';

    /**
     * Token 值
     */
    protected string $tokenValue = '';

    /**
     * 登录 ID
     */
    protected mixed $loginId = null;

    /**
     * 登录类型
     */
    protected string $loginType = '';

    /**
     * Token 创建时间（时间戳秒）
     */
    protected int $createTime = 0;

    /**
     * Token 绝对超时时间（秒），-1 表示永不过期
     */
    protected int $timeout = -1;

    /**
     * Token 活动超时时间（秒），-1 表示不限制
     */
    protected int $activityTimeout = -1;

    /**
     * 设备类型
     */
    protected string $deviceType = '';

    /**
     * 是否为 TokenSession 模式
     */
    protected bool $tokenSession = false;

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->$method($value);
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'tokenName'       => $this->tokenName,
            'tokenValue'      => $this->tokenValue,
            'loginId'         => $this->loginId,
            'loginType'       => $this->loginType,
            'createTime'      => $this->createTime,
            'timeout'         => $this->timeout,
            'activityTimeout' => $this->activityTimeout,
            'deviceType'      => $this->deviceType,
            'tokenSession'    => $this->tokenSession,
        ];
    }

    public function getTokenName(): string
    {
        return $this->tokenName;
    }

    public function setTokenName(string $tokenName): static
    {
        $this->tokenName = $tokenName;
        return $this;
    }

    public function getTokenValue(): string
    {
        return $this->tokenValue;
    }

    public function setTokenValue(string $tokenValue): static
    {
        $this->tokenValue = $tokenValue;
        return $this;
    }

    public function getLoginId(): mixed
    {
        return $this->loginId;
    }

    public function setLoginId(mixed $loginId): static
    {
        $this->loginId = $loginId;
        return $this;
    }

    public function getLoginType(): string
    {
        return $this->loginType;
    }

    public function setLoginType(string $loginType): static
    {
        $this->loginType = $loginType;
        return $this;
    }

    public function getCreateTime(): int
    {
        return $this->createTime;
    }

    public function setCreateTime(int $createTime): static
    {
        $this->createTime = $createTime;
        return $this;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    public function setTimeout(int $timeout): static
    {
        $this->timeout = $timeout;
        return $this;
    }

    public function getActivityTimeout(): int
    {
        return $this->activityTimeout;
    }

    public function setActivityTimeout(int $activityTimeout): static
    {
        $this->activityTimeout = $activityTimeout;
        return $this;
    }

    public function getDeviceType(): string
    {
        return $this->deviceType;
    }

    public function setDeviceType(string $deviceType): static
    {
        $this->deviceType = $deviceType;
        return $this;
    }

    public function isTokenSession(): bool
    {
        return $this->tokenSession;
    }

    public function setTokenSession(bool $tokenSession): static
    {
        $this->tokenSession = $tokenSession;
        return $this;
    }
}
