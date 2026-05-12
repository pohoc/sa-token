<?php

declare(strict_types=1);

namespace SaToken\Dao;

class SaTokenDaoRedis implements SaTokenDaoInterface
{
    protected \Redis $client;

    protected ?\Redis $saRedis = null;

    protected int $database = 0;

    /**
     * @param array<string, mixed>|string $config
     */
    public function __construct(array|string $config = [], ?\Redis $client = null)
    {
        if ($client !== null) {
            $this->client = $client;
            return;
        }

        $config = is_string($config) ? ['url' => $config] : $config;
        $database = $config['database'] ?? 0;
        $this->database = is_int($database) ? $database : (is_numeric($database) ? (int) $database : 0);

        $this->client = new \Redis();
        $host = $config['host'] ?? '127.0.0.1';
        $port = $config['port'] ?? 6379;
        $timeout = $config['timeout'] ?? 0;

        $this->client->connect(is_string($host) ? $host : '127.0.0.1', is_int($port) ? $port : (is_numeric($port) ? (int) $port : 6379), is_numeric($timeout) ? (float) $timeout : 0.0);

        if (!empty($config['password'])) {
            $password = $config['password'];
            if (is_string($password)) {
                $this->client->auth($password);
            } elseif (is_array($password)) {
                /** @var array<string> $password */
                $this->client->auth($password);
            }
        }
        if (isset($config['database'])) {
            $db = $config['database'];
            $this->client->select(is_int($db) ? $db : (is_numeric($db) ? (int) $db : 0));
        }
    }

    public function get(string $key): ?string
    {
        $value = ($this->saRedis ?? $this->client)->get($key);
        if ($value === false) {
            return null;
        }
        if (is_string($value)) {
            return $value;
        }
        if (is_scalar($value)) {
            return (string) $value;
        }
        return null;
    }

    public function set(string $key, string $value, ?int $timeout = null): void
    {
        $client = $this->saRedis ?? $this->client;
        if ($timeout !== null && $timeout > 0) {
            $client->setex($key, $timeout, $value);
        } else {
            $client->set($key, $value);
        }
    }

    public function update(string $key, string $value): void
    {
        ($this->saRedis ?? $this->client)->set($key, $value, ['XX' => true]);
    }

    public function delete(string $key): void
    {
        ($this->saRedis ?? $this->client)->del([$key]);
    }

    public function getTimeout(string $key): int
    {
        $ttl = ($this->saRedis ?? $this->client)->ttl($key);
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
        $client = $this->saRedis ?? $this->client;
        if ($timeout > 0) {
            $client->expire($key, $timeout);
        } else {
            $client->persist($key);
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
        $result = ($this->saRedis ?? $this->client)->eval($script, array_merge([$key], [$timeout]), 1);
        if ($result === false) {
            return null;
        }
        if (is_string($result)) {
            return $result;
        }
        if (is_scalar($result)) {
            return (string) $result;
        }
        return null;
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
        $result = ($this->saRedis ?? $this->client)->eval($script, [$key], 1);
        if ($result === false) {
            return null;
        }
        if (is_string($result)) {
            return $result;
        }
        if (is_scalar($result)) {
            return (string) $result;
        }
        return null;
    }

    public function exists(string $key): bool
    {
        return (bool) ($this->saRedis ?? $this->client)->exists($key);
    }

    public function size(): int
    {
        $info = ($this->saRedis ?? $this->client)->info('keyspace');
        if (!is_array($info)) {
            return 0;
        }

        $dbKey = 'db' . $this->database;
        if (!isset($info[$dbKey])) {
            return 0;
        }

        $dbInfo = $info[$dbKey];
        if (is_array($dbInfo) && isset($dbInfo['keys'])) {
            $keys = $dbInfo['keys'];
            return is_int($keys) ? $keys : (is_numeric($keys) ? (int) $keys : 0);
        }
        if (is_string($dbInfo)) {
            preg_match('/keys=(\d+)/', $dbInfo, $matches);
            return isset($matches[1]) ? (int) $matches[1] : 0;
        }
        return 0;
    }

    public function search(string $prefix, string $keyword, int $start, int $size): array
    {
        $client = $this->saRedis ?? $this->client;
        $pattern = $prefix . '*' . $keyword . '*';
        $keys = [];
        $iterator = null;
        $maxIterations = 100;
        $iterations = 0;

        while (($scanResult = $client->scan($iterator, $pattern, 100)) !== false) {
            $keys = array_merge($keys, $scanResult);
            $iterations++;
            if ($iterations >= $maxIterations || $iterator === 0) {
                break;
            }
        }

        $keys = array_unique($keys);

        if (empty($keys)) {
            return [];
        }

        $values = [];
        $pipe = $client->pipeline();
        foreach ($keys as $key) {
            $pipe->get($key);
        }
        $results = $pipe->exec();

        foreach ($results as $value) {
            if ($value !== false && $value !== null) {
                if (is_string($value)) {
                    $values[] = $value;
                } elseif (is_scalar($value)) {
                    $values[] = (string) $value;
                }
            }
        }

        return array_slice($values, $start, $size);
    }

    public function deleteMultiple(array $keys): void
    {
        if (empty($keys)) {
            return;
        }
        $client = $this->saRedis ?? $this->client;
        $client->del($keys);
    }

    public function getClient(): \Redis
    {
        return $this->client;
    }

    public function setSaRedis(\Redis $redis): void
    {
        $this->saRedis = $redis;
    }

    /**
     * @param array<string, mixed> $mainConfig
     * @param array<string, mixed> $separateConfig
     */
    public static function createWithSeparateRedis(array $mainConfig, array $separateConfig): self
    {
        $instance = new self($mainConfig);

        $saRedis = new \Redis();
        $host = $separateConfig['host'] ?? '127.0.0.1';
        $port = $separateConfig['port'] ?? 6379;
        $timeout = $separateConfig['timeout'] ?? 0;

        $saRedis->connect(is_string($host) ? $host : '127.0.0.1', is_int($port) ? $port : (is_numeric($port) ? (int) $port : 6379), is_numeric($timeout) ? (float) $timeout : 0.0);

        if (!empty($separateConfig['password'])) {
            $password = $separateConfig['password'];
            if (is_string($password)) {
                $saRedis->auth($password);
            } elseif (is_array($password)) {
                /** @var array<string> $password */
                $saRedis->auth($password);
            }
        }
        if (isset($separateConfig['db'])) {
            $db = $separateConfig['db'];
            $saRedis->select(is_int($db) ? $db : (is_numeric($db) ? (int) $db : 0));
        }

        $instance->setSaRedis($saRedis);

        return $instance;
    }
}
