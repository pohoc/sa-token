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
        $session->dataMap = SaFoxUtil::fromJson($decrypted) ?: [];
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
        $this->loadData();
        $this->dataMap[$key] = $value;
        $this->saveData();
    }

    /**
     * 删除会话数据
     *
     * @param  string $key 键名
     * @return void
     */
    public function delete(string $key): void
    {
        $this->loadData();
        unset($this->dataMap[$key]);
        $this->saveData();
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
        $this->dataMap = [];
        $this->saveData();
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
        $this->loadData();
        $this->dataMap = array_merge($this->dataMap, $data);
        $this->saveData();
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
        $json = SaFoxUtil::toJson($this->dataMap);
        $encryptor = self::getEncryptor();
        $encrypted = $encryptor->encrypt($json);
        SaToken::getDao()->set($this->id, $encrypted, $this->timeout);
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
