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
     * 获取指定 key 的值并删除（原子操作）
     *
     * @param  string      $key 存储键
     * @return string|null 值，不存在时返回 null
     */
    public function getAndDelete(string $key): ?string;

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

    /**
     * 搜索匹配指定前缀和关键字的键，返回对应的值列表
     *
     * @param  string        $prefix  键前缀
     * @param  string        $keyword 搜索关键字
     * @param  int           $start   起始偏移量
     * @param  int           $size    返回数量上限
     * @return array<string> 匹配的值列表
     */
    public function search(string $prefix, string $keyword, int $start, int $size): array;

    /**
     * 批量删除指定 key 列表
     *
     * @param  array<string> $keys 存储键列表
     * @return void
     */
    public function deleteMultiple(array $keys): void;

    /**
     * 搜索匹配指定前缀和关键字的键，返回键名列表（区别于 search 返回值列表）
     *
     * @param  string        $prefix  键前缀
     * @param  string        $keyword 搜索关键字
     * @param  int           $start   起始偏移量
     * @param  int           $size    返回数量上限
     * @return array<string> 匹配的键名列表
     */
    public function searchKeys(string $prefix, string $keyword, int $start, int $size): array;

    /**
     * 仅当 key 不存在时设置值（原子操作，用于分布式锁等场景）
     *
     * @param  string   $key     存储键
     * @param  string   $value   存储值
     * @param  int|null $timeout 过期时间（秒），null 表示永不过期
     * @return bool     key 原本不存在且设置成功时返回 true，否则返回 false
     */
    public function setIfNotExists(string $key, string $value, ?int $timeout = null): bool;

    /**
     * 原子递增计数器（用于防暴力破解等并发安全计数场景）
     *
     * @param  string   $key     存储键
     * @param  int      $amount  递增量（可为负）
     * @param  int|null $timeout 过期时间（秒），仅在计数器首次创建时生效，null 表示永不过期
     * @return int      递增后的计数值
     */
    public function increment(string $key, int $amount = 1, ?int $timeout = null): int;
}
