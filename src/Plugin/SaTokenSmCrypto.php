<?php

declare(strict_types=1);

namespace SaToken\Plugin;

use CryptoSm\SM2\Sm2;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use SaToken\Exception\SaTokenException;

/**
 * 国密插件
 *
 * 基于 pohoc/crypto-sm 提供 SM2 签名验签、SM3 哈希、SM4 加解密
 *
 * SM4 加密采用 CBC 模式，加密时随机生成 IV 并拼接到密文前（前 32 hex 字符为 IV），
 * 解密时自动从密文前提取 IV。
 *
 * 使用示例：
 *   $crypto = new SaTokenSmCrypto($config);
 *   $sign = $crypto->sm2Sign('data');
 *   $hash = $crypto->sm3Hash('data');
 *   $encrypted = $crypto->sm4Encrypt('data');
 */
class SaTokenSmCrypto
{
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
     * @param array $config 配置数组（sm2PrivateKey/sm2PublicKey/sm4Key）
     */
    public function __construct(array $config = [])
    {
        $this->sm2PrivateKey = $config['sm2PrivateKey'] ?? '';
        $this->sm2PublicKey = $config['sm2PublicKey'] ?? '';
        $this->sm4Key = $config['sm4Key'] ?? '';
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
     * SM4 加密（CBC 模式，PKCS5 填充）
     *
     * 加密时随机生成 IV，并将 IV（32 位 hex）拼接到密文前面。
     * 最终输出格式：IV(32hex) + Ciphertext(hex)
     *
     * @param  string           $data 明文
     * @param  string|null      $key  32 位 hex 密钥，null 使用配置密钥
     * @return string           十六进制编码的密文（含前缀 IV）
     * @throws SaTokenException
     */
    public function sm4Encrypt(string $data, ?string $key = null): string
    {
        $key = $key ?? $this->sm4Key;
        if ($key === '') {
            throw new SaTokenException('SM4 密钥未配置');
        }

        try {
            $options = new Sm4Options(); // 构造时自动生成随机 IV
            $ciphertext = Sm4::encrypt($data, $key, $options);
            return $options->getIv() . $ciphertext;
        } catch (\Throwable $e) {
            throw new SaTokenException('SM4 加密失败：' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * SM4 解密（CBC 模式，PKCS5 填充）
     *
     * 自动从密文前 32 位 hex 字符提取 IV，剩余部分为实际密文。
     *
     * @param  string           $data 十六进制编码的密文（含前缀 IV）
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
            // 前 32 hex 字符为 IV，其余为密文
            $iv = substr($data, 0, 32);
            $ciphertext = substr($data, 32);

            $options = (new Sm4Options())->setIv($iv);
            return Sm4::decrypt($ciphertext, $key, $options);
        } catch (\Throwable $e) {
            throw new SaTokenException('SM4 解密失败：' . $e->getMessage(), 0, $e);
        }
    }
}
