<?php

declare(strict_types=1);

namespace SaToken\Util;

use SaToken\Exception\SaTokenException;

final class SaTokenTimeout
{
    public static function validate(int $seconds, string $subject = 'Token'): void
    {
        if ($seconds === -1) {
            return;
        }

        if ($seconds <= 0 || $seconds > PHP_INT_MAX - time() - 60) {
            throw new SaTokenException("{$subject} 有效期必须是可表示的正整数秒数，或使用 -1 表示永不过期");
        }
    }
}
