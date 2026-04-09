<?php

declare(strict_types=1);

namespace SaToken\Dao;

/**
 * Sa-Token 存储抽象接口
 *
 * 所有存储后端（内存、Redis、PSR-16 适配等）都必须实现此接口
 * 提供键值存储和过期时间管理的基本操作
 */
interface SaTokenDaoInterface
{
    /**
     * 获取指定 key 的值
     *
     * @param  string      $key 存储键
     * @return string|null 值，不存在时返回 null
     */
    public function get(string $key): ?string;

    /**
     * 设置键值对
     *
     * @param  string   $key     存储键
     * @param  string   $value   存储值
     * @param  int|null $timeout 过期时间（秒），null 表示永不过期
     * @return void
     */
    public function set(string $key, string $value, ?int $timeout = null): void;

    /**
     * 更新指定 key 的值（不改变过期时间）
     *
     * @param  string $key   存储键
     * @param  string $value 新值
     * @return void
     */
    public function update(string $key, string $value): void;

    /**
     * 删除指定 key
     *
     * @param  string $key 存储键
     * @return void
     */
    public function delete(string $key): void;

    /**
     * 获取指定 key 的剩余过期时间（秒）
     *
     * @param  string $key 存储键
     * @return int    剩余秒数，-1 表示永不过期，-2 表示不存在
     */
    public function getTimeout(string $key): int;

    /**
     * 更新指定 key 的过期时间
     *
     * @param  string $key     存储键
     * @param  int    $timeout 过期时间（秒）
     * @return void
     */
    public function expire(string $key, int $timeout): void;

    /**
     * 获取指定 key 的值并更新过期时间
     *
     * @param  string      $key     存储键
     * @param  int         $timeout 过期时间（秒）
     * @return string|null 值，不存在时返回 null
     */
    public function getAndExpire(string $key, int $timeout): ?string;

    /**
     * 判断指定 key 是否存在
     *
     * @param  string $key 存储键
     * @return bool
     */
    public function exists(string $key): bool;

    /**
     * 获取存储中数据总数量
     *
     * @return int
     */
    public function size(): int;
}
