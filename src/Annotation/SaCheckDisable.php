<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD)]
class SaCheckDisable
{
    protected string $service;
    protected string $loginType = 'login';

    public function __construct(string $service, string $loginType = 'login')
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
