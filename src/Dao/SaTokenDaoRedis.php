<?php

declare(strict_types=1);

namespace SaToken\Dao;

use SaToken\Exception\SaTokenException;

class SaTokenDaoRedis implements SaTokenDaoInterface, SaTokenDaoCompareAndDeleteInterface, SaTokenDaoCompareAndExpireInterface, SaTokenDaoCompareAndSetInterface, SaTokenDaoDeleteIfExpiredInterface
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

        $config = $this->normalizeConfig($config);
        $database = $config['database'] ?? 0;
        $this->database = is_int($database) ? $database : (is_numeric($database) ? (int) $database : 0);
        $this->client = $this->connectClient($config);
    }

    /** @param array<string, mixed> $config */
    protected function connectClient(array $config): \Redis
    {
        $client = new \Redis();
        $host = $config['host'] ?? '127.0.0.1';
        $port = $config['port'] ?? 6379;
        $timeout = $config['timeout'] ?? 0;

        $connected = $client->connect(
            is_string($host) ? $host : '127.0.0.1',
            is_int($port) ? $port : (is_numeric($port) ? (int) $port : 6379),
            is_numeric($timeout) ? (float) $timeout : 0.0
        );
        if ($connected !== true) {
            throw new SaTokenException('Redis 连接失败');
        }

        $password = $config['password'] ?? null;
        if ($password !== null && $password !== '') {
            if (isset($config['username']) && is_string($config['username']) && is_string($password)) {
                $authenticated = $client->auth([$config['username'], $password]);
            } elseif (is_string($password)) {
                $authenticated = $client->auth($password);
            } elseif (is_array($password)) {
                /** @var array<string> $password */
                $authenticated = $client->auth($password);
            } else {
                $authenticated = false;
            }
            if ($authenticated !== true) {
                throw new SaTokenException('Redis 身份验证失败');
            }
        }
        if (isset($config['database'])) {
            $db = $config['database'];
            $selected = $client->select(is_int($db) ? $db : (is_numeric($db) ? (int) $db : 0));
            if ($selected !== true) {
                throw new SaTokenException('Redis 数据库选择失败');
            }
        }

        return $client;
    }

    /**
     * @param  array<string, mixed>|string $config
     * @return array<string, mixed>
     */
    protected function normalizeConfig(array|string $config): array
    {
        $config = is_string($config) ? ['url' => $config] : $config;
        if (isset($config['url'])) {
            if (!is_string($config['url'])) {
                throw new SaTokenException('Redis URL 必须是字符串');
            }
            $config = array_merge($this->parseUrl($config['url']), $config);
            unset($config['url']);
        }
        if (!isset($config['database']) && isset($config['db'])) {
            $config['database'] = $config['db'];
        }

        return $config;
    }

    /** @return array<string, mixed> */
    protected function parseUrl(string $url): array
    {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw new SaTokenException('Redis URL 格式无效');
        }

        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['redis', 'rediss'], true)) {
            throw new SaTokenException('Redis URL 仅支持 redis:// 或 rediss://');
        }

        $host = $scheme === 'rediss' ? 'tls://' . $parts['host'] : $parts['host'];
        $config = [
            'host' => $host,
            'port' => $parts['port'] ?? 6379,
        ];

        if (isset($parts['user'])) {
            $config['username'] = rawurldecode($parts['user']);
        }
        if (isset($parts['pass'])) {
            $config['password'] = rawurldecode($parts['pass']);
        }
        if (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/') {
            $database = substr($parts['path'], 1);
            if (!ctype_digit($database)) {
                throw new SaTokenException('Redis URL 中的数据库编号必须是非负整数');
            }
            $config['database'] = (int) $database;
        }
        if (isset($parts['query'])) {
            parse_str($parts['query'], $query);
            if (isset($query['timeout']) && is_numeric($query['timeout'])) {
                $config['timeout'] = (float) $query['timeout'];
            }
        }

        return $config;
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
        $script = <<<'LUA'
local ttl = redis.call('PTTL', KEYS[1])
if ttl == -2 or ttl == 0 then
    return 0
end
if ttl == -1 then
    redis.call('SET', KEYS[1], ARGV[1])
else
    redis.call('SET', KEYS[1], ARGV[1], 'PX', ttl)
end
return 1
LUA;
        ($this->saRedis ?? $this->client)->eval($script, [$key, $value], 1);
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
    local timeout = tonumber(ARGV[1])
    if timeout and timeout > 0 then
        redis.call('EXPIRE', KEYS[1], timeout)
    else
        redis.call('PERSIST', KEYS[1])
    end
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

    public function compareAndDelete(string $key, string $expectedValue): bool
    {
        $script = <<<'LUA'
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
LUA;
        $result = ($this->saRedis ?? $this->client)->eval($script, [$key, $expectedValue], 1);
        return $result === 1;
    }

    public function compareAndExpire(string $key, string $expectedValue, int $timeout): bool
    {
        if ($timeout <= 0) {
            return false;
        }
        $script = <<<'LUA'
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 0
LUA;
        $result = ($this->saRedis ?? $this->client)->eval($script, [$key, $expectedValue, (string) $timeout], 1);
        return $result === 1;
    }

    public function compareAndSet(string $key, ?string $expectedValue, ?string $newValue, ?int $timeout = null): bool
    {
        $script = <<<'LUA'
local current = redis.call('GET', KEYS[1])
if ARGV[1] == '1' then
    if current ~= ARGV[2] then return 0 end
else
    if current then return 0 end
end
if ARGV[3] == '1' then
    if tonumber(ARGV[5]) and tonumber(ARGV[5]) > 0 then
        redis.call('SET', KEYS[1], ARGV[4], 'EX', ARGV[5])
    else
        redis.call('SET', KEYS[1], ARGV[4])
    end
else
    redis.call('DEL', KEYS[1])
end
return 1
LUA;
        $result = ($this->saRedis ?? $this->client)->eval($script, [
            $key, $expectedValue !== null ? '1' : '0', $expectedValue ?? '',
            $newValue !== null ? '1' : '0', $newValue ?? '', (string) ($timeout ?? 0),
        ], 1);
        return $result === 1;
    }

    public function deleteIfExpired(string $key): bool
    {
        $script = <<<'LUA'
local ttl = redis.call('PTTL', KEYS[1])
if ttl == -2 or ttl == -1 or ttl > 0 then
    return 0
end
return redis.call('DEL', KEYS[1])
LUA;
        $result = ($this->saRedis ?? $this->client)->eval($script, [$key], 1);
        return $result === 1;
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
        $escapedKeyword = str_replace(['\\', '*', '?', '[', ']'], ['\\\\', '\\*', '\\?', '\\[', '\\]'], $keyword);
        $pattern = $prefix . '*' . $escapedKeyword . '*';
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

    public function searchKeys(string $prefix, string $keyword, int $start, int $size): array
    {
        $client = $this->saRedis ?? $this->client;
        $escapedKeyword = str_replace(['\\', '*', '?', '[', ']'], ['\\\\', '\\*', '\\?', '\\[', '\\]'], $keyword);
        $pattern = $prefix . '*' . $escapedKeyword . '*';
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

        $keys = array_values(array_unique($keys));
        return array_slice($keys, $start, $size);
    }

    public function deleteMultiple(array $keys): void
    {
        if (empty($keys)) {
            return;
        }
        $client = $this->saRedis ?? $this->client;
        $client->del($keys);
    }

    public function setIfNotExists(string $key, string $value, ?int $timeout = null): bool
    {
        $client = $this->saRedis ?? $this->client;
        $options = ['NX'];
        if ($timeout !== null && $timeout > 0) {
            $options['EX'] = $timeout;
        }
        $result = $client->set($key, $value, $options);
        return $result === true || $result === 'OK';
    }

    public function increment(string $key, int $amount = 1, ?int $timeout = null): int
    {
        $client = $this->saRedis ?? $this->client;
        if ($timeout !== null && $timeout > 0) {
            // 仅在 key 首次创建时设置 TTL，保证"计数 + 过期"原子生效
            $script = <<<'LUA'
local existed = redis.call('EXISTS', KEYS[1]) == 1
local value = redis.call('INCRBY', KEYS[1], ARGV[1])
if not existed then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end
return value
LUA;
            $result = $client->eval($script, [$key, (string) $amount, (string) $timeout], 1);
            return is_int($result) ? $result : 0;
        }

        $result = $client->incrBy($key, $amount);
        return is_int($result) ? $result : 0;
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
        $instance->setSaRedis($instance->connectClient($instance->normalizeConfig($separateConfig)));

        return $instance;
    }
}
