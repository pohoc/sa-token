<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
class SaCheckPermission
{
    protected string $value;
    protected string $mode = 'AND';
    protected string $loginType = 'login';

    public function __construct(string $value, string $mode = 'AND', string $loginType = 'login')
    {
        $this->value = $value;
        $this->mode = $mode;
        $this->loginType = $loginType;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function getMode(): string
    {
        return $this->mode;
    }

    public function getLoginType(): string
    {
        return $this->loginType;
    }
}
