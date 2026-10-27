<?php

declare(strict_types=1);

namespace SaToken\Util;

use SaToken\Exception\SaTokenException;

final class SaTokenCryptoType
{
    public static function validate(string $cryptoType): string
    {
        if (!in_array($cryptoType, ['intl', 'sm'], true)) {
            throw new SaTokenException("不支持的加密类型：{$cryptoType}，仅支持 intl 或 sm");
        }

        return $cryptoType;
    }
}
