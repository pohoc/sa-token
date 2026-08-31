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

    protected ?int $timeout = null;

    public function __construct(string $id, bool $skipLoad = false, ?int $timeout = null)
    {
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
        $dao = SaToken::getDao();
        $json = $dao->get($sessionId);
        if ($json === null) {
            return null;
        }

        $encryptor = self::getEncryptor();
        $decrypted = $encryptor->decrypt($json);

        $session = new static($sessionId, true);
        $dataMap = SaFoxUtil::fromJson($decrypted);
        /** @var array<string, mixed> $dataMap */
        $dataMap = is_array($dataMap) ? $dataMap : [];
        $session->dataMap = $dataMap;
        $session->loaded = true;
        return $session;
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
        $this->dataMap = [];
        SaToken::getDao()->delete($this->id);
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

        for ($i = 0; $i < 10; $i++) {
            if ($dao->setIfNotExists($lockKey, '1', 5)) {
                try {
                    $fresh = $this->readFreshDataMap();
                    $fn($fresh);
                    $this->dataMap = $fresh;
                    $this->loaded = true;
                    $this->saveData();
                    return;
                } finally {
                    $dao->delete($lockKey);
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
            $encryptor = self::getEncryptor();
            $decrypted = $encryptor->decrypt($json);
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

        // 经 getBySessionId 读取的会话 timeout 为 null：
        // 直接写 null 会让已存在会话变成"永不过期"，必须回读并保留原 TTL
        $timeout = $this->timeout;
        if ($timeout === null && SaToken::getDao()->exists($this->id)) {
            $currentTtl = SaToken::getDao()->getTimeout($this->id);
            $timeout = $currentTtl > 0 ? $currentTtl : null;
        }
        SaToken::getDao()->set($this->id, $encrypted, $timeout);
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
