<?php

declare(strict_types=1);

namespace SaToken\Util;

/**
 * 通用工具类
 *
 * 提供随机字符串、UUID、时间处理等通用方法
 */
class SaFoxUtil
{
    /**
     * 生成 UUID v4
     *
     * @return string 36 字符的 UUID 字符串
     */
    public static function uuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // version 4
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // variant 10

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * 生成简单随机字符串
     *
     * @param  int    $length 字符串长度，默认 32
     * @return string
     */
    public static function randomString(int $length = 32): string
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $str = '';
        $max = strlen($chars) - 1;
        for ($i = 0; $i < $length; $i++) {
            $str .= $chars[random_int(0, $max)];
        }
        return $str;
    }

    /**
     * 生成随机数字字符串
     *
     * @param  int    $length 字符串长度
     * @return string
     */
    public static function randomNumber(int $length): string
    {
        $chars = '0123456789';
        $str = '';
        $max = strlen($chars) - 1;
        for ($i = 0; $i < $length; $i++) {
            $str .= $chars[random_int(0, $max)];
        }
        return $str;
    }

    /**
     * 获取当前时间戳（秒）
     *
     * @return int
     */
    public static function getTime(): int
    {
        return time();
    }

    /**
     * 获取当前时间戳（毫秒）
     *
     * @return int
     */
    public static function getMsTime(): int
    {
        return (int) (microtime(true) * 1000);
    }

    /**
     * 判断字符串是否为空
     *
     * @param  string|null $str 字符串
     * @return bool
     */
    public static function isEmpty(?string $str): bool
    {
        return $str === null || $str === '';
    }

    /**
     * 判断字符串是否不为空
     *
     * @param  string|null $str 字符串
     * @return bool
     */
    public static function isNotEmpty(?string $str): bool
    {
        return !self::isEmpty($str);
    }

    /**
     * 判断数组中是否包含指定元素
     *
     * @param  array $array 数组
     * @param  mixed $value 值
     * @return bool
     */
    public static function inArray(array $array, mixed $value): bool
    {
        return in_array($value, $array, true);
    }

    /**
     * 将值转换为字符串
     *
     * @param  mixed  $value 值
     * @return string
     */
    public static function toString(mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_null($value)) {
            return '';
        }
        if (is_array($value)) {
            return json_encode($value, JSON_UNESCAPED_UNICODE);
        }
        return (string) $value;
    }

    /**
     * 安全的 JSON 编码
     *
     * @param  mixed  $value 值
     * @return string
     */
    public static function toJson(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * 安全的 JSON 解码
     *
     * @param  string $json  JSON 字符串
     * @param  bool   $assoc 是否返回关联数组
     * @return mixed
     */
    public static function fromJson(string $json, bool $assoc = true): mixed
    {
        return json_decode($json, $assoc, 512, JSON_BIGINT_AS_STRING);
    }

    /**
     * 确保值是字符串类型
     *
     * @param  mixed       $value 值
     * @return string|null
     */
    public static function valueToString(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }
        return self::toString($value);
    }

    /**
     * 确保值是整数类型
     *
     * @param  mixed    $value 值
     * @return int|null
     */
    public static function valueToInt(mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }
        return (int) $value;
    }
}
