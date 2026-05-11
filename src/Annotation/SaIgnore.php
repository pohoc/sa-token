<?php

declare(strict_types=1);

namespace SaToken\Annotation;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
class SaIgnore
{
}
