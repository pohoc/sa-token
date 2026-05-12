<?php

declare(strict_types=1);

namespace SaToken\Data;

class SaLoginDevice
{
    protected string $tokenValue;
    protected string $deviceType;
    protected string $deviceName;
    protected string $ip;
    protected string $os;
    protected string $browser;
    protected int $loginTime;
    protected ?int $lastActiveTime;
    protected ?int $expireAt;
    protected string $loginType;

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(array $data = [])
    {
        $this->tokenValue = is_string($data['tokenValue'] ?? null) ? $data['tokenValue'] : '';
        $this->deviceType = is_string($data['deviceType'] ?? null) ? $data['deviceType'] : 'unknown';
        $this->deviceName = is_string($data['deviceName'] ?? null) ? $data['deviceName'] : '未知设备';
        $this->ip = is_string($data['ip'] ?? null) ? $data['ip'] : '0.0.0.0';
        $this->os = is_string($data['os'] ?? null) ? $data['os'] : 'unknown';
        $this->browser = is_string($data['browser'] ?? null) ? $data['browser'] : 'unknown';
        $loginTime = $data['loginTime'] ?? time();
        $this->loginTime = is_int($loginTime) ? $loginTime : time();
        $this->lastActiveTime = isset($data['lastActiveTime']) && is_int($data['lastActiveTime']) ? $data['lastActiveTime'] : null;
        $this->expireAt = isset($data['expireAt']) && is_int($data['expireAt']) ? $data['expireAt'] : null;
        $this->loginType = is_string($data['loginType'] ?? null) ? $data['loginType'] : 'login';
    }

    public function getTokenValue(): string
    {
        return $this->tokenValue;
    }
    public function getDeviceType(): string
    {
        return $this->deviceType;
    }
    public function getDeviceName(): string
    {
        return $this->deviceName;
    }
    public function getIp(): string
    {
        return $this->ip;
    }
    public function getOs(): string
    {
        return $this->os;
    }
    public function getBrowser(): string
    {
        return $this->browser;
    }
    public function getLoginTime(): int
    {
        return $this->loginTime;
    }
    public function getLastActiveTime(): ?int
    {
        return $this->lastActiveTime;
    }
    public function getExpireAt(): ?int
    {
        return $this->expireAt;
    }
    public function getLoginType(): string
    {
        return $this->loginType;
    }

    public function setTokenValue(string $tokenValue): static
    {
        $this->tokenValue = $tokenValue;
        return $this;
    }
    public function setDeviceType(string $deviceType): static
    {
        $this->deviceType = $deviceType;
        return $this;
    }
    public function setDeviceName(string $deviceName): static
    {
        $this->deviceName = $deviceName;
        return $this;
    }
    public function setIp(string $ip): static
    {
        $this->ip = $ip;
        return $this;
    }
    public function setOs(string $os): static
    {
        $this->os = $os;
        return $this;
    }
    public function setBrowser(string $browser): static
    {
        $this->browser = $browser;
        return $this;
    }
    public function setLoginTime(int $loginTime): static
    {
        $this->loginTime = $loginTime;
        return $this;
    }
    public function setLastActiveTime(?int $lastActiveTime): static
    {
        $this->lastActiveTime = $lastActiveTime;
        return $this;
    }
    public function setExpireAt(?int $expireAt): static
    {
        $this->expireAt = $expireAt;
        return $this;
    }
    public function setLoginType(string $loginType): static
    {
        $this->loginType = $loginType;
        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'tokenValue' => $this->tokenValue,
            'deviceType' => $this->deviceType,
            'deviceName' => $this->deviceName,
            'ip' => $this->ip,
            'os' => $this->os,
            'browser' => $this->browser,
            'loginTime' => $this->loginTime,
            'lastActiveTime' => $this->lastActiveTime,
            'expireAt' => $this->expireAt,
            'loginType' => $this->loginType,
        ];
    }

    public function getDeviceId(): string
    {
        return md5($this->deviceType . '-' . $this->deviceName . '-' . $this->ip);
    }
}
