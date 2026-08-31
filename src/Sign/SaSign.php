<?php

declare(strict_types=1);

namespace SaToken\Sign;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;

class SaSign
{
    /**
     * 仅允许强哈希算法。MD5/SHA1 不再允许：
     * 配合签名 oracle 可被碰撞伪造
     */
    private const ALLOWED_ALGORITHMS = ['sha256'];

    protected string $key = '';

    protected int $timestampGap = 600;

    protected string $signAlg = 'sha256';

    /**
     * 是否启用内置 nonce 防重放存储（默认开启）。
     * 关闭后防重放完全依赖外部 nonceValidator
     */
    protected bool $nonceStoreEnabled = true;

    /** @var callable(string): bool|null */
    protected $nonceValidator = null;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [])
    {
        $key = $config['key'] ?? '';
        $this->key = is_string($key) ? $key : '';
        if ($this->key === '') {
            throw new SaTokenException('签名密钥未配置');
        }
        $timestampGap = $config['timestampGap'] ?? 600;
        $this->timestampGap = is_int($timestampGap) ? $timestampGap : 600;
        $signAlg = $config['signAlg'] ?? 'sha256';
        $this->setSignAlg(is_string($signAlg) ? $signAlg : 'sha256');
        $nonceStore = $config['nonceStore'] ?? true;
        $this->nonceStoreEnabled = is_bool($nonceStore) ? $nonceStore : true;
    }

    /**
     * 生成签名参数（自动补齐 timestamp / nonce / sign）
     *
     * @param  array<string, string|int> $params
     * @return array<string, string|int>
     */
    public function signParams(array $params, ?string $method = null, ?string $path = null): array
    {
        if (!isset($params['timestamp'])) {
            $params['timestamp'] = (string) time();
        }
        if (!isset($params['nonce'])) {
            $params['nonce'] = bin2hex(random_bytes(16));
        }
        $params['sign'] = $this->createSign($params, $method, $path);
        return $params;
    }

    /**
     * 校验签名
     *
     * timestamp 与 nonce 为必需参数（缺失即拒绝）；
     * 签名验证通过后原子记录 nonce，同一 nonce 的后续请求一律视为重放拒绝。
     * Web 场景建议传入 method/path 将 HTTP 方法与请求路径纳入签名，
     * 防止已签名参数被重放到同密钥的其他端点
     *
     * @param array<string, string|int> $params
     */
    public function verifySign(array $params, ?string $method = null, ?string $path = null): bool
    {
        $sign = $params['sign'] ?? null;
        if ($sign === null || $sign === '') {
            return false;
        }

        // 时间戳是防重放的第一道闸门，缺失即拒绝（旧实现静默跳过等于无时效约束）
        if (!isset($params['timestamp']) || !is_numeric((string) $params['timestamp'])) {
            return false;
        }
        if (abs(time() - (int) (string) $params['timestamp']) > $this->timestampGap) {
            return false;
        }

        $nonce = $params['nonce'] ?? null;
        if (!is_string($nonce) || $nonce === '') {
            return false;
        }

        $expectedSign = $this->createSign($params, $method, $path);
        if (!hash_equals($expectedSign, (string) $sign)) {
            return false;
        }

        // 签名合法后再原子登记 nonce：登记失败（已存在）即重放
        if ($this->nonceValidator !== null) {
            if (!($this->nonceValidator)($nonce)) {
                return false;
            }
        } elseif ($this->nonceStoreEnabled) {
            if (!$this->recordNonce($nonce)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 原子登记 nonce：仅首次成功，重复出现返回 false（重放）
     */
    protected function recordNonce(string $nonce): bool
    {
        $dao = SaToken::getDao();
        $key = 'satoken:sign:nonce:' . hash('sha256', $nonce);
        $ttl = $this->timestampGap * 2 + 60;
        return $dao->setIfNotExists($key, '1', $ttl);
    }

    public function setNonceValidator(callable $validator): static
    {
        $this->nonceValidator = $validator;
        return $this;
    }

    public function setSignAlg(string $alg): static
    {
        if (!in_array($alg, self::ALLOWED_ALGORITHMS, true)) {
            throw new SaTokenException('不支持的签名算法：' . $alg);
        }
        $this->signAlg = $alg;
        return $this;
    }

    /**
     * 计算签名：参数按字典序经 URL 规范化拼接后使用 HMAC-SHA256
     * （密钥后缀拼接 + 单向 hash 的结构不符合 HMAC 规范，已废弃）
     *
     * @param array<string, string|int> $params
     */
    protected function createSign(array $params, ?string $method = null, ?string $path = null): string
    {
        unset($params['sign']);
        ksort($params);
        // 空值参数同样参与规范化，防止攻击者注入空值参数影响目标应用逻辑而不破坏签名
        $queryString = http_build_query($params);
        $signStr = ($method !== null ? strtoupper($method) . '&' : '')
            . ($path !== null ? $path . '?' : '')
            . $queryString
            . '&key=' . $this->key;

        return hash_hmac($this->signAlg, $signStr, $this->key);
    }
}
