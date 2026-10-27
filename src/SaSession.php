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
    protected const RECORD_PREFIX = "\0sa-token-session:v1\n";

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

    protected string $generation;

    protected ?int $timeout = null;

    public function __construct(string $id, bool $skipLoad = false, ?int $timeout = null)
    {
        self::assertSafeSessionId($id);
        $this->id = $id;
        $this->timeout = $timeout;
        $this->generation = bin2hex(random_bytes(16));
        if (!$skipLoad) {
            $this->loadData();
        }
    }

    public static function create(string $id, bool $skipLoad = false, ?int $timeout = null): static
    {
        return new static($id, $skipLoad, $timeout);
    }

    /** @internal Create a session after its owner has validated the login ID. */
    public static function forLoginSession(string $id, ?int $timeout = null): static
    {
        self::assertSafeSessionId($id, true);
        return self::createReservedSession($id, $timeout);
    }

    /** @internal Create a token session after its owner has validated the bearer token. */
    public static function forTokenSession(string $id, ?int $timeout = null): static
    {
        self::assertSafeSessionId($id, false, true);
        return self::createReservedSession($id, $timeout);
    }

    protected static function createReservedSession(string $id, ?int $timeout): static
    {
        $session = (new \ReflectionClass(static::class))->newInstanceWithoutConstructor();
        $session->id = $id;
        $session->timeout = $timeout;
        $session->generation = bin2hex(random_bytes(16));
        $session->loadData();
        return $session;
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
        $session = new static($sessionId);
        return $session->persisted ? $session : null;
    }

    /** @internal Resolve a login session after its owner has validated the login ID. */
    public static function getLoginSessionById(string $sessionId): ?static
    {
        self::assertSafeSessionId($sessionId, true);
        $session = self::forLoginSession($sessionId);
        return $session->persisted ? $session : null;
    }

    /** @internal Resolve a token session after its owner has validated the bearer token. */
    public static function getTokenSessionById(string $sessionId): ?static
    {
        self::assertSafeSessionId($sessionId, false, true);
        $session = self::forTokenSession($sessionId);
        return $session->persisted ? $session : null;
    }

    /**
     * Session helpers can delete and overwrite their backing DAO key. Keep
     * caller-supplied IDs out of Sa-Token's authentication and security state
     * namespaces; only the two session namespaces are valid under satoken:.
     */
    protected static function assertSafeSessionId(
        string $sessionId,
        bool $allowLoginSession = false,
        bool $allowTokenSession = false,
    ): void {
        if (str_starts_with($sessionId, 'satoken:session:lock:')
            || (!$allowLoginSession && str_starts_with($sessionId, TokenManager::SESSION_PREFIX))
            || (!$allowTokenSession && str_starts_with($sessionId, TokenManager::TOKEN_SESSION_PREFIX))) {
            throw new \SaToken\Exception\SaTokenException('Session ID 不能使用 Sa-Token 保留存储命名空间');
        }

        if (!str_starts_with($sessionId, 'satoken:')) {
            return;
        }

        if ($allowLoginSession && str_starts_with($sessionId, TokenManager::SESSION_PREFIX)) {
            return;
        }

        if ($allowTokenSession && str_starts_with($sessionId, TokenManager::TOKEN_SESSION_PREFIX)) {
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
        $this->withSessionLock(function (): void {
            $current = $this->readFreshSession();
            if ($current === null) {
                return;
            }
            if (!$this->persisted) {
                throw new \SaToken\Exception\SaTokenException('会话对象未持有当前记录，拒绝销毁');
            }
            if (!hash_equals($this->generation, $current['generation'])) {
                throw new \SaToken\Exception\SaTokenException('会话已被销毁并重新创建，拒绝旧对象销毁');
            }
            $dao = SaToken::getDao();
            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                || !$dao->compareAndSet($this->id, $current['raw'], null)) {
                throw new \SaToken\Exception\SaTokenException('会话已并发变更或 DAO 不支持原子条件删除，请重试');
            }
            $this->dataMap = [];
            $this->loaded = true;
            $this->persisted = true;
        });
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
        $this->withSessionLock(function () use ($fn): void {
            $previousDataMap = $this->dataMap;
            $previousLoaded = $this->loaded;
            $previousPersisted = $this->persisted;
            $previousGeneration = $this->generation;
            $current = $this->readFreshSession();
            if ($current === null) {
                if ($this->persisted) {
                    throw new \SaToken\Exception\SaTokenException('会话已过期或销毁，拒绝重新创建');
                }
                $fresh = [];
            } else {
                if ($this->persisted && !hash_equals($this->generation, $current['generation'])) {
                    throw new \SaToken\Exception\SaTokenException('会话已被销毁并重新创建，拒绝旧对象写入');
                }
                $this->generation = $current['generation'];
                $this->persisted = true;
                $fresh = $current['data'];
            }

            $fn($fresh);
            $this->dataMap = $fresh;
            $this->loaded = true;
            try {
                $this->saveData($current['raw'] ?? null);
            } catch (\Throwable $exception) {
                $this->dataMap = $previousDataMap;
                $this->loaded = $previousLoaded;
                $this->persisted = $previousPersisted;
                $this->generation = $previousGeneration;
                throw $exception;
            }
        });
    }

    /**
     * 从存储层强制重读最新数据及其代际标识。
     *
     * @return array{generation: string, data: array<string, mixed>, raw: string}|null
     */
    protected function readFreshSession(): ?array
    {
        $dao = SaToken::getDao();
        $json = $dao->get($this->id);
        if ($json === null) {
            return null;
        }

        $encryptor = self::getEncryptor();
        $decrypted = $encryptor->decryptCheckedForContext($json, $this->id);
        if ($decrypted === null) {
            // 密文被篡改或密钥错配：拒绝静默清空后盲写（那会掩盖完整性破坏）
            throw new \SaToken\Exception\SaTokenException('会话数据完整性校验失败，拒绝修改（请检查加密配置或存储是否被篡改）');
        }

        $record = self::decodeRecord($decrypted);
        if ($record === null) {
            throw new \SaToken\Exception\SaTokenException('会话数据格式无效');
        }
        return $record + ['raw' => $json];
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
            $decrypted = self::getEncryptor()->decryptCheckedForContext($json, $this->id);
            if ($decrypted === null) {
                throw new \SaToken\Exception\SaTokenException('会话数据完整性校验失败');
            }

            if (str_starts_with($decrypted, self::RECORD_PREFIX)) {
                $record = self::decodeRecord($decrypted);
                if ($record === null) {
                    throw new \SaToken\Exception\SaTokenException('会话数据格式无效');
                }
                $this->generation = $record['generation'];
                $this->dataMap = $record['data'];
            } else {
                $this->withSessionLock(function (): void {
                    $latest = SaToken::getDao()->get($this->id);
                    if ($latest === null) {
                        return;
                    }
                    $latestData = self::getEncryptor()->decryptCheckedForContext($latest, $this->id);
                    if ($latestData === null) {
                        throw new \SaToken\Exception\SaTokenException('会话数据完整性校验失败');
                    }
                    if (str_starts_with($latestData, self::RECORD_PREFIX)) {
                        $record = self::decodeRecord($latestData);
                        if ($record === null) {
                            throw new \SaToken\Exception\SaTokenException('会话数据格式无效');
                        }
                        $this->generation = $record['generation'];
                        $this->dataMap = $record['data'];
                    } else {
                        // Migrate under the session lock. update preserves storage TTL.
                        $this->dataMap = self::normalizeDataMap(SaFoxUtil::fromJson($latestData));
                        $this->generation = bin2hex(random_bytes(16));
                        $dao = SaToken::getDao();
                        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndUpdateInterface
                            || !$dao->compareAndUpdate($this->id, $latest, self::getEncryptor()->encryptForContext($this->encodeRecord(), $this->id))) {
                            throw new \SaToken\Exception\SaTokenException('会话已并发变更或 DAO 不支持原子条件更新，请重试');
                        }
                    }
                    $this->persisted = true;
                });
                $this->loaded = true;
                return;
            }
            $this->persisted = true;
        }
        $this->loaded = true;
    }

    /**
     * 保存会话数据
     *
     * @return void
     */
    protected function saveData(?string $expectedRaw = null): void
    {
        $encryptor = self::getEncryptor();
        $encrypted = $encryptor->encryptForContext($this->encodeRecord(), $this->id);

        if ($this->persisted) {
            // update preserves the storage record's TTL and never creates a
            // new record after expiry. Recreating with set() could turn an
            // expired session into a permanent one when a stale object is used.
            $dao = SaToken::getDao();
            if ($expectedRaw === null) {
                throw new \SaToken\Exception\SaTokenException('会话已过期或销毁，拒绝重新创建');
            }
            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndUpdateInterface
                || !$dao->compareAndUpdate($this->id, $expectedRaw, $encrypted)) {
                throw new \SaToken\Exception\SaTokenException('会话已并发变更或 DAO 不支持原子条件更新，请重试');
            }
            return;
        }

        if (!SaToken::getDao()->setIfNotExists($this->id, $encrypted, $this->timeout)) {
            throw new \SaToken\Exception\SaTokenException('会话已并发创建，请重新加载后重试');
        }
        $this->persisted = true;
    }

    protected function encodeRecord(): string
    {
        $json = SaFoxUtil::toJson([
            'generation' => $this->generation,
            'data' => $this->dataMap,
        ]);
        if ($json === '') {
            throw new \SaToken\Exception\SaTokenException('会话数据序列化失败，已中止写入以保护存量数据');
        }
        return self::RECORD_PREFIX . $json;
    }

    /** @return array{generation: string, data: array<string, mixed>}|null */
    protected static function decodeRecord(string $record): ?array
    {
        if (!str_starts_with($record, self::RECORD_PREFIX)) {
            return null;
        }
        $decoded = SaFoxUtil::fromJson(substr($record, strlen(self::RECORD_PREFIX)));
        if (!is_array($decoded)
            || !is_string($decoded['generation'] ?? null)
            || preg_match('/^[a-f0-9]{32}$/D', $decoded['generation']) !== 1
            || !is_array($decoded['data'] ?? null)) {
            return null;
        }

        $data = self::normalizeDataMap($decoded['data']);
        return ['generation' => $decoded['generation'], 'data' => $data];
    }

    /** @return array<string, mixed> */
    protected static function normalizeDataMap(mixed $data): array
    {
        if (!is_array($data)) {
            return [];
        }

        $normalized = [];
        foreach ($data as $key => $value) {
            $normalized[(string) $key] = $value;
        }
        return $normalized;
    }

    /** @param callable(): void $operation */
    protected function withSessionLock(callable $operation): void
    {
        $dao = SaToken::getDao();
        $lockKey = 'satoken:session:lock:' . $this->id;
        $lockValue = bin2hex(random_bytes(16));

        for ($i = 0; $i < 10; $i++) {
            if (\SaToken\Dao\SaTokenDaoLock::acquire($dao, $lockKey, $lockValue, 5)) {
                try {
                    $operation();
                    return;
                } finally {
                    \SaToken\Dao\SaTokenDaoLock::release($dao, $lockKey, $lockValue);
                }
            }
            usleep(50000);
        }

        throw new \SaToken\Exception\SaTokenException('会话并发冲突：锁获取超时，请稍后重试');
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
