<?php

declare(strict_types=1);

namespace SaToken\Dao;

/**
 * 内存存储默认实现
 *
 * 单进程/测试用的兜底方案，数据仅存在于当前进程内存中
 * 不适用于分布式环境或多进程场景
 *
 * 使用示例：
 *   $dao = new SaTokenDaoMemory();
 *   $dao->set('key', 'value', 3600);
 *   echo $dao->get('key'); // 'value'
 */
class SaTokenDaoMemory implements SaTokenDaoInterface
{
    /**
     * 存储数据 [key => ['value' => string, 'expire_at' => int|null]]
     * @var array<string, array{value: string, expire_at: int|null}>
     */
    protected array $dataMap = [];

    /**
     * @inheritdoc
     */
    public function get(string $key): ?string
    {
        $this->checkExpired($key);

        if (!isset($this->dataMap[$key])) {
            return null;
        }

        return $this->dataMap[$key]['value'];
    }

    /**
     * @inheritdoc
     */
    public function set(string $key, string $value, ?int $timeout = null): void
    {
        $expireAt = ($timeout !== null && $timeout > 0) ? time() + $timeout : null;
        $this->dataMap[$key] = [
            'value'     => $value,
            'expire_at' => $expireAt,
        ];
    }

    /**
     * @inheritdoc
     */
    public function update(string $key, string $value): void
    {
        if (!isset($this->dataMap[$key])) {
            return;
        }
        $this->dataMap[$key]['value'] = $value;
    }

    /**
     * @inheritdoc
     */
    public function delete(string $key): void
    {
        unset($this->dataMap[$key]);
    }

    /**
     * @inheritdoc
     */
    public function getTimeout(string $key): int
    {
        $this->checkExpired($key);

        if (!isset($this->dataMap[$key])) {
            return -2;
        }

        $expireAt = $this->dataMap[$key]['expire_at'];
        if ($expireAt === null) {
            return -1;
        }

        return max(0, $expireAt - time());
    }

    /**
     * @inheritdoc
     */
    public function expire(string $key, int $timeout): void
    {
        if (!isset($this->dataMap[$key])) {
            return;
        }
        $this->dataMap[$key]['expire_at'] = ($timeout > 0) ? time() + $timeout : null;
    }

    /**
     * @inheritdoc
     */
    public function getAndExpire(string $key, int $timeout): ?string
    {
        $value = $this->get($key);
        if ($value !== null) {
            $this->expire($key, $timeout);
        }
        return $value;
    }

    /**
     * @inheritdoc
     */
    public function getAndDelete(string $key): ?string
    {
        $this->checkExpired($key);

        if (!isset($this->dataMap[$key])) {
            return null;
        }

        $value = $this->dataMap[$key]['value'];
        unset($this->dataMap[$key]);
        return $value;
    }

    /**
     * @inheritdoc
     */
    public function exists(string $key): bool
    {
        $this->checkExpired($key);
        return isset($this->dataMap[$key]);
    }

    /**
     * @inheritdoc
     */
    public function size(): int
    {
        $this->cleanExpired();
        return count($this->dataMap);
    }

    /**
     * @inheritdoc
     */
    public function deleteMultiple(array $keys): void
    {
        foreach ($keys as $key) {
            unset($this->dataMap[$key]);
        }
    }

    public function search(string $prefix, string $keyword, int $start, int $size): array
    {
        $this->cleanExpired();

        $values = [];
        foreach ($this->dataMap as $key => $item) {
            if (str_starts_with($key, $prefix) && str_contains($key, $keyword)) {
                $values[] = $item['value'];
            }
        }

        return array_slice($values, $start, $size);
    }

    /**
     * 清除所有数据
     *
     * @return void
     */
    public function clear(): void
    {
        $this->dataMap = [];
    }

    /**
     * 检查并清除过期的 key
     *
     * @param  string $key 存储键
     * @return void
     */
    protected function checkExpired(string $key): void
    {
        if (!isset($this->dataMap[$key])) {
            return;
        }

        $expireAt = $this->dataMap[$key]['expire_at'];
        if ($expireAt !== null && $expireAt <= time()) {
            unset($this->dataMap[$key]);
        }
    }

    /**
     * 批量清除所有过期 key
     *
     * @return void
     */
    protected function cleanExpired(): void
    {
        $now = time();
        foreach ($this->dataMap as $key => $item) {
            if ($item['expire_at'] !== null && $item['expire_at'] <= $now) {
                unset($this->dataMap[$key]);
            }
        }
    }
}
