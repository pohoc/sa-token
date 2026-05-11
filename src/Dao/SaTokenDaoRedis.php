<?php

declare(strict_types=1);

namespace SaToken\Dao;

class SaTokenDaoRedis implements SaTokenDaoInterface
{
    protected \Redis $client;

    protected int $database = 0;

    public function __construct(array|string $config = [], ?\Redis $client = null)
    {
        if ($client !== null) {
            $this->client = $client;
            return;
        }

        $config = is_string($config) ? ['url' => $config] : $config;
        $this->database = (int) ($config['database'] ?? 0);

        $this->client = new \Redis();
        $host = $config['host'] ?? '127.0.0.1';
        $port = (int) ($config['port'] ?? 6379);
        $timeout = $config['timeout'] ?? 0;

        $this->client->connect($host, $port, $timeout);

        if (!empty($config['password'])) {
            $this->client->auth($config['password']);
        }
        if (isset($config['database'])) {
            $this->client->select((int) $config['database']);
        }
    }

    public function get(string $key): ?string
    {
        $value = $this->client->get($key);
        return $value === false ? null : (string) $value;
    }

    public function set(string $key, string $value, ?int $timeout = null): void
    {
        if ($timeout !== null && $timeout > 0) {
            $this->client->setex($key, $timeout, $value);
        } else {
            $this->client->set($key, $value);
        }
    }

    public function update(string $key, string $value): void
    {
        $this->client->set($key, $value, ['XX' => true]);
    }

    public function delete(string $key): void
    {
        $this->client->del([$key]);
    }

    public function getTimeout(string $key): int
    {
        $ttl = $this->client->ttl($key);
        if ($ttl === -2) {
            return -2;
        }
        if ($ttl === -1) {
            return -1;
        }
        return (int) $ttl;
    }

    public function expire(string $key, int $timeout): void
    {
        if ($timeout > 0) {
            $this->client->expire($key, $timeout);
        } else {
            $this->client->persist($key);
        }
    }

    public function getAndExpire(string $key, int $timeout): ?string
    {
        $script = <<<'LUA'
local value = redis.call('GET', KEYS[1])
if value then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return value
LUA;
        $result = $this->client->eval($script, array_merge([$key], [$timeout]), 1);
        return $result === false ? null : (string) $result;
    }

    public function getAndDelete(string $key): ?string
    {
        $script = <<<'LUA'
local value = redis.call('GET', KEYS[1])
if value then
    redis.call('DEL', KEYS[1])
end
return value
LUA;
        $result = $this->client->eval($script, [$key], 1);
        return $result === false ? null : (string) $result;
    }

    public function exists(string $key): bool
    {
        return (bool) $this->client->exists($key);
    }

    public function size(): int
    {
        $info = $this->client->info('keyspace');
        if (!is_array($info)) {
            return 0;
        }

        $dbKey = 'db' . $this->database;
        if (!isset($info[$dbKey])) {
            return 0;
        }

        $dbInfo = $info[$dbKey];
        if (is_array($dbInfo) && isset($dbInfo['keys'])) {
            return (int) $dbInfo['keys'];
        }
        if (is_string($dbInfo)) {
            preg_match('/keys=(\d+)/', $dbInfo, $matches);
            return isset($matches[1]) ? (int) $matches[1] : 0;
        }
        return 0;
    }

    public function getClient(): \Redis
    {
        return $this->client;
    }
}
