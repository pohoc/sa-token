<?php

declare(strict_types=1);

namespace SaToken\Dao;

use SaToken\Exception\SaTokenException;

/**
 * Redis 存储实现
 *
 * 支持分布式会话，优先使用 phpredis 扩展，回退到 Predis
 *
 * 使用示例：
 *   $dao = new SaTokenDaoRedis(['host' => '127.0.0.1', 'port' => 6379]);
 *   $dao->set('key', 'value', 3600);
 */
class SaTokenDaoRedis implements SaTokenDaoInterface
{
    /**
     * Redis 连接实例
     * @var \Redis|\Predis\Client|null
     */
    protected mixed $client = null;

    /**
     * @param  array|string               $config Redis 配置数组或连接参数
     *                                            - 使用 phpredis: ['host' => '127.0.0.1', 'port' => 6379, 'database' => 0, 'password' => null]
     *                                            - 使用 Predis: ['scheme' => 'tcp', 'host' => '127.0.0.1', 'port' => 6379]
     * @param  \Redis|\Predis\Client|null $client 已有的 Redis 客户端实例
     * @throws SaTokenException           当 Redis 扩展/库不可用时
     */
    public function __construct(array|string $config = [], mixed $client = null)
    {
        if ($client !== null) {
            $this->client = $client;
            return;
        }

        $config = is_string($config) ? ['url' => $config] : $config;

        // 优先使用 phpredis 扩展
        if (extension_loaded('redis')) {
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
            return;
        }

        // 其次使用 Predis
        $this->client = new \Predis\Client($config);
    }

    /**
     * @inheritdoc
     */
    public function get(string $key): ?string
    {
        $value = $this->client->get($key);
        return $value === false || $value === null ? null : (string) $value;
    }

    /**
     * @inheritdoc
     */
    public function set(string $key, string $value, ?int $timeout = null): void
    {
        if ($timeout !== null && $timeout > 0) {
            $this->client->setex($key, $timeout, $value);
        } else {
            $this->client->set($key, $value);
        }
    }

    /**
     * @inheritdoc
     */
    public function update(string $key, string $value): void
    {
        $this->client->set($key, $value, ['XX' => true]);
    }

    /**
     * @inheritdoc
     */
    public function delete(string $key): void
    {
        $this->client->del([$key]);
    }

    /**
     * @inheritdoc
     */
    public function getTimeout(string $key): int
    {
        $ttl = $this->client->ttl($key);
        if ($ttl === -2) {
            return -2; // key 不存在
        }
        if ($ttl === -1) {
            return -1; // 永不过期
        }
        return (int) $ttl;
    }

    /**
     * @inheritdoc
     */
    public function expire(string $key, int $timeout): void
    {
        if ($timeout > 0) {
            $this->client->expire($key, $timeout);
        } else {
            $this->client->persist($key);
        }
    }

    /**
     * @inheritdoc
     */
    public function getAndExpire(string $key, int $timeout): ?string
    {
        // 使用 Lua 脚本保证原子性
        $script = <<<'LUA'
local value = redis.call('GET', KEYS[1])
if value then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return value
LUA;
        $result = $this->evalScript($script, [$key], [$timeout]);
        return $result === false || $result === null ? null : (string) $result;
    }

    /**
     * @inheritdoc
     */
    public function exists(string $key): bool
    {
        return (bool) $this->client->exists($key);
    }

    /**
     * @inheritdoc
     */
    public function size(): int
    {
        $info = $this->client->info('keyspace');
        if (is_array($info) && isset($info['db0'])) {
            $dbInfo = $info['db0'];
            if (is_array($dbInfo) && isset($dbInfo['keys'])) {
                return (int) $dbInfo['keys'];
            }
            // phpredis 返回格式：'keys=100,expires=50,avg_ttl=0'
            if (is_string($dbInfo)) {
                preg_match('/keys=(\d+)/', $dbInfo, $matches);
                return isset($matches[1]) ? (int) $matches[1] : 0;
            }
        }
        return 0;
    }

    /**
     * 执行 Lua 脚本
     *
     * @param  string $script Lua 脚本
     * @param  array  $keys   键列表
     * @param  array  $args   参数列表
     * @return mixed
     */
    protected function evalScript(string $script, array $keys, array $args): mixed
    {
        if ($this->client instanceof \Redis) {
            return $this->client->eval($script, array_merge($keys, $args), count($keys));
        }

        // Predis — 使用 array_values 确保数字索引，避免 named arguments 问题
        return $this->client->eval($script, count($keys), ...array_values(array_merge($keys, $args)));
    }

    /**
     * 获取 Redis 客户端实例
     *
     * @return \Redis|\Predis\Client
     */
    public function getClient(): mixed
    {
        return $this->client;
    }
}
