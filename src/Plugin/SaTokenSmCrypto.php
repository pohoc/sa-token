<?php

declare(strict_types=1);

namespace SaToken\Plugin;

use CryptoSm\SM2\Sm2;
use CryptoSm\SM3\HmacSm3;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use SaToken\Exception\SaTokenException;

/**
 * 国密插件
 *
 * 基于 pohoc/crypto-sm 提供 SM2 签名验签、SM3 哈希、SM4 加解密
 *
 * SM4 加密采用 crypto-sm 的自包含 GCM 格式，提供认证加密。
 * 升级前由本插件生成的 SMT1 格式（CBC + HMAC-SM3）仍可读取。
 *
 * 使用示例：
 *   $crypto = new SaTokenSmCrypto($config);
 *   $sign = $crypto->sm2Sign('data');
 *   $hash = $crypto->sm3Hash('data');
 *   $encrypted = $crypto->sm4Encrypt('data');
 */
class SaTokenSmCrypto
{
    private const SM4_LEGACY_AUTHENTICATED_MAGIC = 'SMT1';
    private const SM4_GCM_MAGIC_PREFIX = '534d3447434d'; // Hex-encoded "SM4GCM" prefix

    /**
     * SM2 私钥（64 位 hex 字符串）
     */
    protected string $sm2PrivateKey = '';

    /**
     * SM2 公钥（128 位 hex 字符串，非压缩格式不含 04 前缀）
     */
    protected string $sm2PublicKey = '';

    /**
     * SM4 密钥（32 位 hex 字符串，即 128 位）
     */
    protected string $sm4Key = '';

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [])
    {
        $sm2PrivateKey = $config['sm2PrivateKey'] ?? '';
        $this->sm2PrivateKey = is_string($sm2PrivateKey) ? $sm2PrivateKey : '';
        $sm2PublicKey = $config['sm2PublicKey'] ?? '';
        $this->sm2PublicKey = is_string($sm2PublicKey) ? $sm2PublicKey : '';
        $sm4Key = $config['sm4Key'] ?? '';
        $this->sm4Key = is_string($sm4Key) ? $sm4Key : '';
    }

    /**
     * SM2 签名
     *
     * @param  string           $data 待签名数据
     * @return string           十六进制签名（128 位，r || s 拼接）
     * @throws SaTokenException
     */
    public function sm2Sign(string $data): string
    {
        if ($this->sm2PrivateKey === '') {
            throw new SaTokenException('SM2 私钥未配置');
        }

        try {
            return Sm2::sign($data, $this->sm2PrivateKey);
        } catch (\Throwable $e) {
            throw new SaTokenException('SM2 签名失败：' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * SM2 验签
     *
     * @param  string $data 原始数据
     * @param  string $sign 十六进制签名
     * @return bool
     */
    public function sm2Verify(string $data, string $sign): bool
    {
        if ($this->sm2PublicKey === '') {
            return false;
        }

        try {
            return Sm2::verify($data, $sign, $this->sm2PublicKey);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * SM3 哈希
     *
     * @param  string           $data 待哈希数据
     * @return string           64 位十六进制哈希值
     * @throws SaTokenException
     */
    public function sm3Hash(string $data): string
    {
        try {
            return Sm3::sm3($data);
        } catch (\Throwable $e) {
            throw new SaTokenException('SM3 哈希失败：' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * SM4-GCM 认证加密，使用 crypto-sm 自包含密文格式。
     *
     * @param  string           $data 明文
     * @param  string|null      $key  32 位 hex 密钥，null 使用配置密钥
     * @return string           十六进制编码的自包含认证密文
     * @throws SaTokenException
     */
    public function sm4Encrypt(string $data, ?string $key = null): string
    {
        $key = $key ?? $this->sm4Key;
        if ($key === '') {
            throw new SaTokenException('SM4 密钥未配置');
        }

        try {
            return Sm4::encrypt($data, $key);
        } catch (\Throwable $e) {
            throw new SaTokenException('SM4 加密失败：' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 插件 SM4 的 MAC 独立密钥（与加密密钥分离）
     */
    protected function deriveSm4MacKey(string $key): string
    {
        return hash('sha256', $key . ':sa-token-sm4-plugin-mac');
    }

    /**
     * 解密 crypto-sm 自包含 GCM 密文或升级前本插件生成的 SMT1 CBC+HMAC 密文。
     * 未认证的历史 CBC 密文仍必须通过 sm4DecryptLegacy() 显式迁移。
     *
     * @param  string           $data 自包含 GCM 密文或旧版 SMT1 密文
     * @param  string|null      $key  32 位 hex 密钥，null 使用配置密钥
     * @return string           明文
     * @throws SaTokenException
     */
    public function sm4Decrypt(string $data, ?string $key = null): string
    {
        $key = $key ?? $this->sm4Key;
        if ($key === '') {
            throw new SaTokenException('SM4 密钥未配置');
        }

        try {
            $magicLength = strlen(self::SM4_LEGACY_AUTHENTICATED_MAGIC);
            if (str_starts_with($data, self::SM4_LEGACY_AUTHENTICATED_MAGIC)) {
                // 旧格式：MAGIC(4) + HMAC-SM3(64hex) + IV(32hex) + 密文(hex)
                $mac = substr($data, $magicLength, 64);
                $iv = substr($data, $magicLength + 64, 32);
                $ciphertext = substr($data, $magicLength + 96);

                $expectedMac = HmacSm3::hmac($this->deriveSm4MacKey($key), $iv . $ciphertext);
                if (!hash_equals($expectedMac, $mac)) {
                    throw new SaTokenException('SM4 解密失败：密文完整性校验未通过（可能被篡改）');
                }
                $options = (new Sm4Options())->setIv($iv);
                return Sm4::decrypt($ciphertext, $key, $options);
            }

            // 新格式由上游库完成 GCM tag 验证；非自包含格式不会被当作 CBC 接受。
            return Sm4::decrypt($data, $key);
        } catch (\Throwable $e) {
            throw new SaTokenException('SM4 解密失败：' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 解密未认证的历史 SM4-CBC 密文，仅用于受控的数据迁移。
     *
     * 历史格式不含 MAC，无法检测密文篡改；不要在请求处理或任何不可信输入路径中调用。
     * 迁移后应立即用 sm4Encrypt() 重新加密，并删除旧密文。
     *
     * @throws SaTokenException
     */
    public function sm4DecryptLegacy(string $data, ?string $key = null): string
    {
        $key = $key ?? $this->sm4Key;
        if ($key === '') {
            throw new SaTokenException('SM4 密钥未配置');
        }
        if (str_starts_with($data, self::SM4_LEGACY_AUTHENTICATED_MAGIC)
            || str_starts_with(strtolower($data), self::SM4_GCM_MAGIC_PREFIX)) {
            throw new SaTokenException('SM4 解密失败：认证格式不得使用旧版解密器');
        }

        try {
            $iv = substr($data, 0, 32);
            $ciphertext = substr($data, 32);
            $options = (new Sm4Options())->setIv($iv);
            return Sm4::decrypt($ciphertext, $key, $options);
        } catch (\Throwable $e) {
            throw new SaTokenException('SM4 解密失败：' . $e->getMessage(), 0, $e);
        }
    }
}
