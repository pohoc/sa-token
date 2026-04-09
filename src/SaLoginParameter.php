<?php

declare(strict_types=1);

namespace SaToken;

/**
 * 登录参数类
 *
 * 登录时可选的组合参数，用于指定设备类型、记住我、超时时间等
 *
 * 使用示例：
 *   $param = new SaLoginParameter();
 *   $param->setDeviceType('PC')->setIsLastingCookie(true)->setTimeout(7200);
 *   StpUtil::login(10001, $param);
 */
class SaLoginParameter
{
    /**
     * 设备类型
     */
    protected string $deviceType = '';

    /**
     * 是否为持久化 Cookie（记住我）
     */
    protected bool $isLastingCookie = true;

    /**
     * Token 超时时间（秒），null 使用全局配置
     */
    protected ?int $timeout = null;

    /**
     * 同端最大登录数，null 使用全局配置
     */
    protected ?int $maxLoginCount = null;

    /**
     * 是否共享 Token（isShare）
     */
    protected ?bool $isShare = null;

    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->$method($value);
            }
        }
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

    public function isLastingCookie(): bool
    {
        return $this->isLastingCookie;
    }

    public function setIsLastingCookie(bool $isLastingCookie): static
    {
        $this->isLastingCookie = $isLastingCookie;
        return $this;
    }

    public function getTimeout(): ?int
    {
        return $this->timeout;
    }

    public function setTimeout(?int $timeout): static
    {
        $this->timeout = $timeout;
        return $this;
    }

    public function getMaxLoginCount(): ?int
    {
        return $this->maxLoginCount;
    }

    public function setMaxLoginCount(?int $maxLoginCount): static
    {
        $this->maxLoginCount = $maxLoginCount;
        return $this;
    }

    public function getIsShare(): ?bool
    {
        return $this->isShare;
    }

    public function setIsShare(?bool $isShare): static
    {
        $this->isShare = $isShare;
        return $this;
    }
}
