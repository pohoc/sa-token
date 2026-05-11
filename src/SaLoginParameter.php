<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Data\SaLoginDevice;

class SaLoginParameter
{
    protected string $deviceType = '';

    protected bool $isLastingCookie = true;

    protected ?int $timeout = null;

    protected ?int $maxLoginCount = null;

    protected ?bool $isShare = null;

    protected ?SaLoginDevice $device = null;

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

    public function getDevice(): ?SaLoginDevice
    {
        return $this->device;
    }

    public function setDevice(?SaLoginDevice $device): static
    {
        $this->device = $device;
        return $this;
    }
}
