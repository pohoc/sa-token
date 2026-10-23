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
