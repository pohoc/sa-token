<?php

declare(strict_types=1);

namespace SaToken\Dao;

use SaToken\Exception\SaTokenException;

/**
 * 本地文件存储实现
 *
 * 适用于单机部署、无 Redis 环境的开发/小规模生产场景。
 * 每个 key 对应一个数据文件（内容为 JSON：原始 key + base64 值 + 过期时间戳），
 * 过期采用读取时惰性删除。
 *
 * 并发语义：读-改-写类操作（getAndDelete/setIfNotExists/increment/expire/update）
 * 通过独立锁文件 flock 互斥，单机多进程（FPM/CLI）下安全。
 * 注意：文件锁不支持 NFS 等网络文件系统，跨机器共享请使用 Redis。
 *
 * 使用示例：
 *   $dao = new SaTokenDaoFile(['path' => __DIR__ . '/runtime/sa-token']);
 *   SaToken::setDao($dao);
 *
 * 或通过配置（SaToken::init 自动装配）：
 *   'storage' => ['type' => 'file', 'path' => 'runtime/sa-token']
 */
class SaTokenDaoFile implements SaTokenDaoInterface, SaTokenDaoCompareAndDeleteInterface, SaTokenDaoCompareAndExpireInterface, SaTokenDaoCompareAndSetInterface, SaTokenDaoCompareAndUpdateInterface, SaTokenDaoDeleteIfExpiredInterface
{
    protected string $dataDir;

    protected string $lockDir;

    /**
     * search/searchKeys 单次扫描的文件数上限（防大目录拖垮性能）
     */
    protected int $scanLimit = 10000;

    /**
     * @param array<string, mixed>|string $config 'path' 存储目录，字符串时视为路径
     */
    public function __construct(array|string $config = [])
    {
        $path = is_string($config) ? $config : ($config['path'] ?? null);
        if (!is_string($path) || $path === '') {
            $path = sys_get_temp_dir() . '/sa-token';
        }

        $this->dataDir = rtrim($path, '/') . '/data';
        $this->lockDir = rtrim($path, '/') . '/locks';
        $this->ensureDirectory($this->dataDir);
        $this->ensureDirectory($this->lockDir);

        $scanLimit = $config['scanLimit'] ?? null;
        if (is_int($scanLimit) && $scanLimit > 0) {
            $this->scanLimit = $scanLimit;
        }
    }

    protected function ensureDirectory(string $dir): void
    {
        if (is_link($dir)) {
            throw new SaTokenException("文件存储目录不能是符号链接：{$dir}");
        }
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new SaTokenException("文件存储目录创建失败：{$dir}");
        }
        // 配置目录可能早已存在且权限宽松；持有 token/密钥数据的目录必须
        // 在每次装配时重新收紧，不能只依赖 mkdir 的初始 mode。
        $stat = @lstat($dir);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0040000 || !@chmod($dir, 0700)) {
            throw new SaTokenException("文件存储目录权限设置失败：{$dir}");
        }
    }

    protected function dataFile(string $key): string
    {
        return $this->dataDir . '/' . hash('sha256', $key) . '.dat';
    }

    protected function lockFile(string $key): string
    {
        return $this->lockDir . '/' . hash('sha256', $key) . '.lock';
    }

    /**
     * 以独占锁执行读-改-写操作，保证多进程原子性
     *
     * @template T
     * @param  callable(): T $operation
     * @return T
     */
    protected function withLock(string $key, callable $operation): mixed
    {
        $lockPath = $this->lockFile($key);
        $fp = fopen($lockPath, 'c');
        if ($fp === false) {
            throw new SaTokenException("文件存储锁打开失败：{$lockPath}");
        }
        if (!@chmod($lockPath, 0600)) {
            fclose($fp);
            throw new SaTokenException("文件存储锁权限设置失败：{$lockPath}");
        }

        $locked = flock($fp, LOCK_EX);
        if ($locked === false) {
            fclose($fp);
            throw new SaTokenException("文件存储锁获取失败：{$lockPath}");
        }

        try {
            return $operation();
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /**
     * Run a local operation while holding an OS file lock for the full callback.
     * The lock is released by the operating system if the worker exits, so long
     * cache operations cannot outlive a time-based lease and overlap another
     * process using the same lock directory.
     *
     * @template T
     * @param  callable(): T $operation
     * @return T
     */
    public function executeAtomically(string $key, callable $operation): mixed
    {
        return $this->withLock($key, $operation);
    }

    /**
     * @return array{key: string, v: string, e: int|null}|null
     */
    protected function readRecord(string $key): ?array
    {
        $path = $this->dataFile($key);
        if (!is_file($path)) {
            return null;
        }

        $raw = file_get_contents($path);
        if ($raw === false || $raw === '') {
            return null;
        }

        $record = json_decode($raw, true);
        $expireAt = is_array($record) ? ($record['e'] ?? null) : null;
        if (!is_array($record)
            || !array_key_exists('e', $record)
            || !is_string($record['key'] ?? null)
            || $record['key'] !== $key
            || !is_string($record['v'] ?? null)
            || ($expireAt !== null && !is_int($expireAt))) {
            // 损坏的记录文件视为不存在并清理
            @unlink($path);
            return null;
        }

        return [
            'key' => $key,
            'v' => $record['v'],
            'e' => $expireAt,
        ];
    }

    protected function isExpired(?int $expireAt): bool
    {
        return $expireAt !== null && $expireAt <= time();
    }

    protected function writeRecord(string $key, string $value, ?int $expireAt): void
    {
        $this->writeRecordRaw($key, base64_encode($value), $expireAt);
    }

    /**
     * 写入已编码（base64）的值
     */
    protected function writeRecordRaw(string $key, string $encodedValue, ?int $expireAt): void
    {
        $payload = json_encode([
            'key' => $key,
            'v'   => $encodedValue,
            'e'   => $expireAt,
        ], JSON_UNESCAPED_UNICODE);
        if ($payload === false) {
            throw new SaTokenException('文件存储序列化失败');
        }

        // 临时文件 + rename 保证读取方永远看不到半写状态
        $path = $this->dataFile($key);
        $tmpPath = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (file_put_contents($tmpPath, $payload) === false) {
            throw new SaTokenException("文件存储写入失败：{$path}");
        }
        if (!@chmod($tmpPath, 0600)) {
            @unlink($tmpPath);
            throw new SaTokenException("文件存储权限设置失败：{$path}");
        }
        if (!@rename($tmpPath, $path)) {
            @unlink($tmpPath);
            throw new SaTokenException("文件存储写入失败（rename）：{$path}");
        }
    }

    /**
     * 读取有效值：过期时惰性删除文件并返回 null
     */
    protected function readValue(string $key): ?string
    {
        $record = $this->readRecord($key);
        if ($record === null) {
            return null;
        }
        if ($this->isExpired($record['e'])) {
            @unlink($this->dataFile($key));
            return null;
        }
        $decoded = base64_decode($record['v'], true);
        return $decoded !== false ? $decoded : null;
    }

    public function get(string $key): ?string
    {
        return $this->withLock($key, fn (): ?string => $this->readValue($key));
    }

    public function set(string $key, string $value, ?int $timeout = null): void
    {
        $this->withLock($key, function () use ($key, $value, $timeout): void {
            $this->writeRecord($key, $value, ($timeout !== null && $timeout > 0) ? time() + $timeout : null);
        });
    }

    public function update(string $key, string $value): void
    {
        $this->withLock($key, function () use ($key, $value): void {
            $record = $this->readRecord($key);
            if ($record === null || $this->isExpired($record['e'])) {
                return;
            }
            $this->writeRecord($key, $value, $record['e']);
        });
    }

    public function delete(string $key): void
    {
        $this->withLock($key, fn () => @unlink($this->dataFile($key)));
    }

    public function getTimeout(string $key): int
    {
        return $this->withLock($key, function () use ($key): int {
            $record = $this->readRecord($key);
            if ($record === null) {
                return -2;
            }
            if ($this->isExpired($record['e'])) {
                @unlink($this->dataFile($key));
                return -2;
            }
            if ($record['e'] === null) {
                return -1;
            }
            return max(0, $record['e'] - time());
        });
    }

    public function expire(string $key, int $timeout): void
    {
        $this->withLock($key, function () use ($key, $timeout): void {
            $record = $this->readRecord($key);
            if ($record === null) {
                return;
            }
            if ($this->isExpired($record['e'])) {
                @unlink($this->dataFile($key));
                return;
            }
            // 直接透传 base64 值：decode 失败再重写会把原值破坏为空串
            $this->writeRecordRaw($key, $record['v'], ($timeout > 0) ? time() + $timeout : null);
        });
    }

    public function getAndExpire(string $key, int $timeout): ?string
    {
        return $this->withLock($key, function () use ($key, $timeout): ?string {
            $value = $this->readValue($key);
            if ($value !== null) {
                $this->writeRecord($key, $value, ($timeout > 0) ? time() + $timeout : null);
            }
            return $value;
        });
    }

    public function getAndDelete(string $key): ?string
    {
        return $this->withLock($key, function () use ($key): ?string {
            $value = $this->readValue($key);
            if ($value !== null) {
                @unlink($this->dataFile($key));
            }
            return $value;
        });
    }

    public function compareAndDelete(string $key, string $expectedValue): bool
    {
        return $this->withLock($key, function () use ($key, $expectedValue): bool {
            $value = $this->readValue($key);
            if ($value === null || $value !== $expectedValue) {
                return false;
            }
            return @unlink($this->dataFile($key));
        });
    }

    public function compareAndExpire(string $key, string $expectedValue, int $timeout): bool
    {
        if ($timeout !== -1 && $timeout <= 0) {
            return false;
        }

        return $this->withLock($key, function () use ($key, $expectedValue, $timeout): bool {
            $record = $this->readRecord($key);
            if ($record === null || $this->isExpired($record['e']) || $this->readValue($key) !== $expectedValue) {
                return false;
            }

            if ($record['e'] === null || ($timeout !== -1 && $record['e'] >= time() + $timeout)) {
                return true;
            }

            $expireAt = $timeout === -1 ? null : time() + $timeout;
            $this->writeRecordRaw($key, $record['v'], $expireAt);

            return true;
        });
    }

    public function compareAndSet(string $key, ?string $expectedValue, ?string $newValue, ?int $timeout = null): bool
    {
        return $this->withLock($key, function () use ($key, $expectedValue, $newValue, $timeout): bool {
            if ($this->readValue($key) !== $expectedValue) {
                return false;
            }
            if ($newValue === null) {
                @unlink($this->dataFile($key));
            } else {
                $this->writeRecord($key, $newValue, ($timeout !== null && $timeout > 0) ? time() + $timeout : null);
            }
            return true;
        });
    }

    public function compareAndUpdate(string $key, string $expectedValue, string $newValue): bool
    {
        return $this->withLock($key, function () use ($key, $expectedValue, $newValue): bool {
            $record = $this->readRecord($key);
            if ($record === null || $this->isExpired($record['e'])) {
                return false;
            }

            $current = base64_decode($record['v'], true);
            if ($current === false || $current !== $expectedValue) {
                return false;
            }

            $this->writeRecord($key, $newValue, $record['e']);
            return true;
        });
    }

    public function deleteIfExpired(string $key): bool
    {
        return $this->withLock($key, function () use ($key): bool {
            $record = $this->readRecord($key);
            if ($record === null || !$this->isExpired($record['e'])) {
                return false;
            }
            return @unlink($this->dataFile($key));
        });
    }

    public function exists(string $key): bool
    {
        return $this->withLock($key, fn (): bool => $this->readValue($key) !== null);
    }

    public function setIfNotExists(string $key, string $value, ?int $timeout = null): bool
    {
        return $this->withLock($key, function () use ($key, $value, $timeout): bool {
            if ($this->readValue($key) !== null) {
                return false;
            }
            $this->writeRecord($key, $value, ($timeout !== null && $timeout > 0) ? time() + $timeout : null);
            return true;
        });
    }

    public function increment(string $key, int $amount = 1, ?int $timeout = null): int
    {
        return $this->withLock($key, function () use ($key, $amount, $timeout): int {
            $record = $this->readRecord($key);
            $current = 0;
            $exists = false;
            if ($record !== null && !$this->isExpired($record['e'])) {
                $decoded = base64_decode($record['v'], true);
                if ($decoded !== false && $decoded !== '') {
                    $current = (int) $decoded;
                    $exists = true;
                }
            }

            $newValue = max(0, $current + $amount);
            $expireAt = null;
            if ($exists && $record !== null) {
                // 已存在的记录保留原 TTL（timeout 仅在首次创建时生效）
                $expireAt = $record['e'];
            } elseif ($timeout !== null && $timeout > 0) {
                $expireAt = time() + $timeout;
            }

            $this->writeRecord($key, (string) $newValue, $expireAt);
            return $newValue;
        });
    }

    public function size(): int
    {
        return count($this->scanDataFiles(static fn (): bool => true));
    }

    public function deleteMultiple(array $keys): void
    {
        foreach ($keys as $key) {
            if (is_string($key)) {
                $this->delete($key);
            }
        }
    }

    public function search(string $prefix, string $keyword, int $start, int $size): array
    {
        $values = [];
        foreach ($this->scanMatching($prefix, $keyword) as $record) {
            $decoded = base64_decode($record['v'], true);
            $values[] = $decoded !== false ? $decoded : '';
        }
        return array_slice($values, $start, $size);
    }

    public function searchKeys(string $prefix, string $keyword, int $start, int $size): array
    {
        $keys = [];
        foreach ($this->scanMatching($prefix, $keyword) as $record) {
            $keys[] = $record['key'];
        }
        return array_slice($keys, $start, $size);
    }

    /**
     * 扫描数据目录并返回匹配前缀/关键字的记录（惰性清理过期文件）
     *
     * @return iterable<array{key: string, v: string, e: int|null}>
     */
    protected function scanMatching(string $prefix, string $keyword): iterable
    {
        foreach ($this->scanDataFiles() as $path) {
            $raw = @file_get_contents($path);
            if ($raw === false || $raw === '') {
                continue;
            }
            $record = json_decode($raw, true);
            if (!is_array($record) || !is_string($record['key'] ?? null) || !is_string($record['v'] ?? null)) {
                continue;
            }
            /** @var array{key: string, v: string, e: int|null} $record */
            $record = $this->withLock($record['key'], function () use ($record): ?array {
                $latest = $this->readRecord($record['key']);
                if ($latest === null) {
                    return null;
                }
                if ($this->isExpired($latest['e'])) {
                    @unlink($this->dataFile($record['key']));
                    return null;
                }
                return $latest;
            });
            if ($record === null) {
                continue;
            }
            if (!str_starts_with($record['key'], $prefix)) {
                continue;
            }
            if ($keyword !== '' && !str_contains($record['key'], $keyword)) {
                continue;
            }
            yield $record;
        }
    }

    /**
     * @return array<string>
     */
    protected function scanDataFiles(?callable $filter = null): array
    {
        $files = @scandir($this->dataDir);
        if ($files === false) {
            return [];
        }

        $result = [];
        $scanned = 0;
        foreach ($files as $file) {
            if ($scanned >= $this->scanLimit) {
                break;
            }
            if (!str_ends_with($file, '.dat')) {
                continue;
            }
            $path = $this->dataDir . '/' . $file;
            if (!is_file($path)) {
                continue;
            }
            $scanned++;
            if ($filter === null || $filter($path)) {
                $result[] = $path;
            }
        }
        return $result;
    }
}
