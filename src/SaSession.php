<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Util\SaFoxUtil;
use SaToken\Util\SaTokenEncryptor;

/**
 * 会话管理类
 *
 * 提供键值对存储和生命周期管理，支持全端共享和单端独享
 *
 * 使用示例：
 *   $session = StpUtil::getSession();
 *   $session->set('name', '张三');
 *   echo $session->get('name'); // '张三'
 *   $session->delete('name');
 */
class SaSession
{
    /**
     * Session ID
     */
    protected string $id;

    /**
     * 会话数据
     * @var array<string, mixed>
     */
    protected array $dataMap = [];

    /**
     * 是否已加载
     */
    protected bool $loaded = false;

    /** Whether this object was loaded from an existing storage record. */
    protected bool $persisted = false;

    protected ?int $timeout = null;

    public function __construct(string $id, bool $skipLoad = false, ?int $timeout = null)
    {
        self::assertSafeSessionId($id);
        $this->id = $id;
        $this->timeout = $timeout;
        if (!$skipLoad) {
            $this->loadData();
        }
    }

    /**
     * 根据 Session ID 获取已有会话
     *
     * @param  string      $sessionId Session ID
     * @return static|null 不存在返回 null
     */
    public static function getBySessionId(string $sessionId): ?static
    {
        self::assertSafeSessionId($sessionId);
        $dao = SaToken::getDao();
        $json = $dao->get($sessionId);
        if ($json === null) {
            return null;
        }

        $encryptor = self::getEncryptor();
        $decrypted = $encryptor->decryptChecked($json);
        if ($decrypted === null) {
            throw new \SaToken\Exception\SaTokenException('会话数据完整性校验失败');
        }

        $session = new static($sessionId, true);
        $dataMap = SaFoxUtil::fromJson($decrypted);
        /** @var array<string, mixed> $dataMap */
        $dataMap = is_array($dataMap) ? $dataMap : [];
        $session->dataMap = $dataMap;
        $session->loaded = true;
        $session->persisted = true;
        return $session;
    }

    /**
     * Session helpers can delete and overwrite their backing DAO key. Keep
     * caller-supplied IDs out of Sa-Token's authentication and security state
     * namespaces; only the two session namespaces are valid under satoken:.
     */
    protected static function assertSafeSessionId(string $sessionId): void
    {
        if (str_starts_with($sessionId, 'satoken:session:lock:')) {
            throw new \SaToken\Exception\SaTokenException('Session ID 不能使用 Sa-Token 保留存储命名空间');
        }

        if (!str_starts_with($sessionId, 'satoken:')) {
            return;
        }

        if (str_starts_with($sessionId, TokenManager::SESSION_PREFIX)
            || str_starts_with($sessionId, TokenManager::TOKEN_SESSION_PREFIX)) {
            return;
        }

        throw new \SaToken\Exception\SaTokenException('Session ID 不能使用 Sa-Token 保留存储命名空间');
    }

    /**
     * 获取 Session ID
     *
     * @return string
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * 获取会话数据
     *
     * @param  string $key     键名
     * @param  mixed  $default 默认值
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $this->loadData();
        return $this->dataMap[$key] ?? $default;
    }

    /**
     * 设置会话数据
     *
     * @param  string $key   键名
     * @param  mixed  $value 值
     * @return void
     */
    public function set(string $key, mixed $value): void
    {
        $this->mutate(function (array &$data) use ($key, $value): void {
            $data[$key] = $value;
        });
    }

    /**
     * 删除会话数据
     *
     * @param  string $key 键名
     * @return void
     */
    public function delete(string $key): void
    {
        $this->mutate(function (array &$data) use ($key): void {
            unset($data[$key]);
        });
    }

    /**
     * 判断指定键是否存在
     *
     * @param  string $key 键名
     * @return bool
     */
    public function has(string $key): bool
    {
        $this->loadData();
        return array_key_exists($key, $this->dataMap);
    }

    /**
     * 清空所有会话数据
     *
     * @return void
     */
    public function clear(): void
    {
        $this->mutate(function (array &$data): void {
            $data = [];
        });
    }

    /**
     * 获取所有会话数据
     *
     * @return array<string, mixed>
     */
    public function getDataMap(): array
    {
        $this->loadData();
        return $this->dataMap;
    }

    /**
     * 更新会话数据（批量）
     *
     * @param  array<string, mixed> $data 数据
     * @return void
     */
    public function update(array $data): void
    {
        $this->mutate(function (array &$fresh) use ($data): void {
            $fresh = array_merge($fresh, $data);
        });
    }

    /**
     * 销毁此会话
     *
     * @return void
     */
    public function destroy(): void
    {
        $dao = SaToken::getDao();
        $lockKey = 'satoken:session:lock:' . $this->id;
        $lockValue = bin2hex(random_bytes(16));

        for ($i = 0; $i < 10; $i++) {
            if (\SaToken\Dao\SaTokenDaoLock::acquire($dao, $lockKey, $lockValue, 5)) {
                try {
                    $dao->delete($this->id);
                    $this->dataMap = [];
                    $this->loaded = true;
                    $this->persisted = true;
                    return;
                } finally {
                    \SaToken\Dao\SaTokenDaoLock::release($dao, $lockKey, $lockValue);
                }
            }
            usleep(50000);
        }

        throw new \SaToken\Exception\SaTokenException('会话并发冲突：锁获取超时，请稍后重试');
    }

    /**
     * 互斥修改会话：setIfNotExists 分布式锁 + 锁内重读最新数据 + 合并写。
     *
     * 整包读改写在并发下会互相覆盖（后写者用旧快照覆盖前者的修改），
     * 可能导致安全状态（登录信息、二级认证标记）静默回退。
     * 锁 TTL 5 秒：持锁进程崩溃后自动释放
     *
     * @param  callable(array<string, mixed>): void $fn 接收最新数据引用并就地修改
     * @return void
     * @throws \SaToken\Exception\SaTokenException  锁获取超时
     */
    protected function mutate(callable $fn): void
    {
        $dao = SaToken::getDao();
        $lockKey = 'satoken:session:lock:' . $this->id;
        $lockValue = bin2hex(random_bytes(16));

        for ($i = 0; $i < 10; $i++) {
            if (\SaToken\Dao\SaTokenDaoLock::acquire($dao, $lockKey, $lockValue, 5)) {
                try {
                    $fresh = $this->readFreshDataMap();
                    $fn($fresh);
                    $previousDataMap = $this->dataMap;
                    $previousLoaded = $this->loaded;
                    $this->dataMap = $fresh;
                    $this->loaded = true;
                    try {
                        $this->saveData();
                    } catch (\Throwable $exception) {
                        $this->dataMap = $previousDataMap;
                        $this->loaded = $previousLoaded;
                        throw $exception;
                    }
                    return;
                } finally {
                    \SaToken\Dao\SaTokenDaoLock::release($dao, $lockKey, $lockValue);
                }
            }
            usleep(50000);
        }

        throw new \SaToken\Exception\SaTokenException('会话并发冲突：锁获取超时，请稍后重试');
    }

    /**
     * 从存储层强制重读最新数据（不解密失败静默清空：用 decryptChecked 区分）
     *
     * @return array<string, mixed>
     */
    protected function readFreshDataMap(): array
    {
        $dao = SaToken::getDao();
        $json = $dao->get($this->id);
        if ($json === null) {
            if ($this->persisted) {
                throw new \SaToken\Exception\SaTokenException('会话已过期或销毁，拒绝重新创建');
            }
            return [];
        }

        $encryptor = self::getEncryptor();
        $decrypted = $encryptor->decryptChecked($json);
        if ($decrypted === null) {
            // 密文被篡改或密钥错配：拒绝静默清空后盲写（那会掩盖完整性破坏）
            throw new \SaToken\Exception\SaTokenException('会话数据完整性校验失败，拒绝修改（请检查加密配置或存储是否被篡改）');
        }

        $data = SaFoxUtil::fromJson($decrypted);
        /** @var array<string, mixed> $data */
        return is_array($data) ? $data : [];
    }

    /**
     * 加载会话数据
     *
     * @return void
     */
    protected function loadData(): void
    {
        if ($this->loaded) {
            return;
        }

        $json = SaToken::getDao()->get($this->id);
        if ($json !== null) {
            $this->persisted = true;
            $encryptor = self::getEncryptor();
            $decrypted = $encryptor->decryptChecked($json);
            if ($decrypted === null) {
                throw new \SaToken\Exception\SaTokenException('会话数据完整性校验失败');
            }
            $data = SaFoxUtil::fromJson($decrypted);
            /** @var array<string, mixed> $data */
            $this->dataMap = is_array($data) ? $data : [];
        }
        $this->loaded = true;
    }

    /**
     * 保存会话数据
     *
     * @return void
     */
    protected function saveData(): void
    {
        // 序列化失败时（如存入 NAN/非法 UTF-8）绝不能写空串——
        // 那会把整个会话的所有键值一并销毁
        $json = SaFoxUtil::toJson($this->dataMap);
        if ($json === '' && $this->dataMap !== []) {
            throw new \SaToken\Exception\SaTokenException('会话数据序列化失败，已中止写入以保护存量数据');
        }

        $encryptor = self::getEncryptor();
        $encrypted = $encryptor->encrypt($json);

        if ($this->persisted) {
            // update preserves the storage record's TTL and never creates a
            // new record after expiry. Recreating with set() could turn an
            // expired session into a permanent one when a stale object is used.
            $dao = SaToken::getDao();
            $dao->update($this->id, $encrypted);
            if ($dao->get($this->id) === null) {
                throw new \SaToken\Exception\SaTokenException('会话已过期或销毁，拒绝重新创建');
            }
            return;
        }

        SaToken::getDao()->set($this->id, $encrypted, $this->timeout);
        $this->persisted = true;
    }

    protected static function getEncryptor(): SaTokenEncryptor
    {
        $config = SaToken::getConfig();
        $key = $config->getTokenEncryptKey() ?: $config->getAesKey();
        if ($config->getCryptoType() === 'sm') {
            $key = $config->getTokenEncryptKey() ?: $config->getSm4Key();
        }
        return new SaTokenEncryptor($config->isTokenEncrypt(), $key, $config->getCryptoType());
    }
}
