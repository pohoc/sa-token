<?php

declare(strict_types=1);

namespace SaToken\Tests;

use Psr\SimpleCache\CacheInterface;

class ArrayPsr16Cache implements CacheInterface
{
    /** @var array<string, mixed> */
    protected array $data = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $this->data[(string) $key] = $value;
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->data = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }
        return $result;
    }

    /**
     * @param iterable<string|int, mixed> $values
     */
    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }
}

class StrictArrayPsr16Cache extends ArrayPsr16Cache
{
    protected function assertLegalKey(string $key): void
    {
        if ($key === '' || preg_match('/[{}()\/\\\\@:]/', $key) === 1 || strlen($key) > 64) {
            throw new StrictPsr16InvalidArgumentException('Illegal PSR-16 cache key');
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $this->assertLegalKey($key);
        return parent::get($key, $default);
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $this->assertLegalKey($key);
        return parent::set($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        $this->assertLegalKey($key);
        return parent::delete($key);
    }

    public function has(string $key): bool
    {
        $this->assertLegalKey($key);
        return parent::has($key);
    }
}

class StrictPsr16InvalidArgumentException extends \InvalidArgumentException implements \Psr\SimpleCache\InvalidArgumentException
{
}

class SharedFilePsr16Cache implements CacheInterface
{
    public function __construct(private string $directory, private int $readDelayMicroseconds = 0)
    {
        if (!is_dir($directory)) {
            mkdir($directory, 0700, true);
        }
    }

    private function path(string $key): string
    {
        return $this->directory . '/' . hash('sha256', $key) . '.json';
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $path = $this->path($key);
        $raw = @file_get_contents($path);
        $record = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($record) || !array_key_exists('value', $record)) {
            $value = $default;
        } elseif (is_int($record['expiresAt'] ?? null) && $record['expiresAt'] <= time()) {
            @unlink($path);
            $value = $default;
        } else {
            $value = $record['value'];
        }
        if ($this->readDelayMicroseconds > 0) {
            usleep($this->readDelayMicroseconds);
        }
        return $value;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $expiresAt = is_int($ttl) && $ttl > 0 ? time() + $ttl : null;
        $json = json_encode(['value' => $value, 'expiresAt' => $expiresAt]);
        if (!is_string($json)) {
            return false;
        }
        $path = $this->path($key);
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (file_put_contents($tmp, $json) === false || !rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }

    public function delete(string $key): bool
    {
        $path = $this->path($key);
        return !is_file($path) || @unlink($path);
    }

    public function clear(): bool
    {
        $files = glob($this->directory . '/*.json') ?: [];
        foreach ($files as $file) {
            @unlink($file);
        }
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }
        return $values;
    }

    /** @param iterable<string, mixed> $values */
    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        $success = true;
        foreach ($values as $key => $value) {
            $success = $this->set($key, $value, $ttl) && $success;
        }
        return $success;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        $success = true;
        foreach ($keys as $key) {
            $success = $this->delete($key) && $success;
        }
        return $success;
    }

    public function has(string $key): bool
    {
        return $this->get($key, null) !== null;
    }
}
