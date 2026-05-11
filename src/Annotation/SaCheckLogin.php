<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
class SaCheckLogin
{
    protected string $loginType = 'login';

    public function __construct(string $loginType = 'login')
    {
        $this->loginType = $loginType;
    }

    public function getLoginType(): string
    {
        return $this->loginType;
    }
}
