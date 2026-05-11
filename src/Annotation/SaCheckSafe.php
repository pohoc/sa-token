<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD)]
class SaCheckSafe
{
    protected string $service = 'default';
    protected string $loginType = 'login';

    public function __construct(string $service = 'default', string $loginType = 'login')
    {
        $this->service = $service;
        $this->loginType = $loginType;
    }

    public function getService(): string
    {
        return $this->service;
    }

    public function getLoginType(): string
    {
        return $this->loginType;
    }
}
