<?php

declare(strict_types=1);

namespace SaToken;

/**
 * 终端信息数据类
 *
 * 封装登录终端的设备类型、Token 值、登录时间等信息
 *
 * 使用示例：
 *   $terminals = StpUtil::getTerminalListByLoginId(10001);
 *   foreach ($terminals as $t) {
 *       echo $t->getDeviceType();
 *       echo $t->getTokenValue();
 *   }
 */
class SaTerminalInfo
{
    /**
     * 设备类型
     */
    protected string $deviceType = '';

    /**
     * Token 值
     */
    protected string $tokenValue = '';

    /**
     * 登录时间（时间戳秒）
     */
    protected int $loginTime = 0;

    /**
     * Token 创建时间
     */
    protected int $createTime = 0;

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
            'deviceType' => $this->deviceType,
            'tokenValue' => $this->tokenValue,
            'loginTime'  => $this->loginTime,
            'createTime' => $this->createTime,
        ];
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

    public function getTokenValue(): string
    {
        return $this->tokenValue;
    }

    public function setTokenValue(string $tokenValue): static
    {
        $this->tokenValue = $tokenValue;
        return $this;
    }

    public function getLoginTime(): int
    {
        return $this->loginTime;
    }

    public function setLoginTime(int $loginTime): static
    {
        $this->loginTime = $loginTime;
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
}
