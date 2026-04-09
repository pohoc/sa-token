<?php

declare(strict_types=1);

namespace SaToken\Plugin;

use SaToken\Exception\SaTokenException;

/**
 * 国际加密插件
 *
 * 基于 OpenSSL 扩展提供 AES 加解密、RSA 签名验签、HMAC-SHA256 签名验签
 *
 * 使用示例：
 *   $crypto = new SaTokenCrypto($config);
 *   $encrypted = $crypto->aesEncrypt('hello');
 *   $decrypted = $crypto->aesDecrypt($encrypted);
 *   $sign = $crypto->hmacSign('data');
 */
class SaTokenCrypto
{
    /**
     * AES 密钥
     */
    protected string $aesKey = '';

    /**
     * RSA 私钥
     */
    protected string $rsaPrivateKey = '';

    /**
     * RSA 公钥
     */
    protected string $rsaPublicKey = '';

    /**
     * HMAC 密钥
     */
    protected string $hmacKey = '';

    /**
     * @param  array            $config 配置数组（aesKey/rsaPrivateKey/rsaPublicKey/hmacKey）
     * @throws SaTokenException OpenSSL 不可用时
     */
    public function __construct(array $config = [])
    {
        if (!extension_loaded('openssl')) {
            throw new SaTokenException('国际加密插件需要 OpenSSL 扩展');
        }

        $this->aesKey = $config['aesKey'] ?? '';
        $this->rsaPrivateKey = $config['rsaPrivateKey'] ?? '';
        $this->rsaPublicKey = $config['rsaPublicKey'] ?? '';
        $this->hmacKey = $config['hmacKey'] ?? '';
    }

    /**
     * AES 加密
     *
     * @param  string           $data 明文
     * @param  string|null      $key  密钥，null 使用配置密钥
     * @return string           Base64 编码的密文
     * @throws SaTokenException
     */
    public function aesEncrypt(string $data, ?string $key = null): string
    {
        $key = $key ?? $this->aesKey;
        if ($key === '') {
            throw new SaTokenException('AES 密钥未配置');
        }

        $iv = random_bytes(openssl_cipher_iv_length('AES-256-CBC') ?: 16);
        $paddedKey = $this->padAesKey($key);

        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $paddedKey, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new SaTokenException('AES 加密失败');
        }

        return base64_encode($iv . $encrypted);
    }

    /**
     * AES 解密
     *
     * @param  string           $data Base64 编码的密文
     * @param  string|null      $key  密钥，null 使用配置密钥
     * @return string           明文
     * @throws SaTokenException
     */
    public function aesDecrypt(string $data, ?string $key = null): string
    {
        $key = $key ?? $this->aesKey;
        if ($key === '') {
            throw new SaTokenException('AES 密钥未配置');
        }

        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            throw new SaTokenException('AES 解密失败：无效的 Base64 数据');
        }

        $ivLength = openssl_cipher_iv_length('AES-256-CBC') ?: 16;
        $iv = substr($decoded, 0, $ivLength);
        $encrypted = substr($decoded, $ivLength);

        $paddedKey = $this->padAesKey($key);

        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $paddedKey, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new SaTokenException('AES 解密失败');
        }

        return $decrypted;
    }

    /**
     * RSA 签名
     *
     * @param  string           $data       待签名数据
     * @param  string|null      $privateKey 私钥，null 使用配置私钥
     * @return string           Base64 编码的签名
     * @throws SaTokenException
     */
    public function rsaSign(string $data, ?string $privateKey = null): string
    {
        $privateKey = $privateKey ?? $this->rsaPrivateKey;
        if ($privateKey === '') {
            throw new SaTokenException('RSA 私钥未配置');
        }

        $key = $this->loadRsaPrivateKey($privateKey);
        if ($key === false) {
            throw new SaTokenException('RSA 私钥加载失败');
        }

        $result = openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);
        if (!$result) {
            throw new SaTokenException('RSA 签名失败');
        }

        return base64_encode($signature);
    }

    /**
     * RSA 验签
     *
     * @param  string      $data      原始数据
     * @param  string      $sign      Base64 编码的签名
     * @param  string|null $publicKey 公钥，null 使用配置公钥
     * @return bool        验签是否通过
     */
    public function rsaVerify(string $data, string $sign, ?string $publicKey = null): bool
    {
        $publicKey = $publicKey ?? $this->rsaPublicKey;
        if ($publicKey === '') {
            return false;
        }

        $key = $this->loadRsaPublicKey($publicKey);
        if ($key === false) {
            return false;
        }

        $signature = base64_decode($sign, true);
        if ($signature === false) {
            return false;
        }

        $result = openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA256);
        return $result === 1;
    }

    /**
     * HMAC-SHA256 签名
     *
     * @param  string           $data 待签名数据
     * @param  string|null      $key  密钥，null 使用配置密钥
     * @return string           十六进制签名
     * @throws SaTokenException
     */
    public function hmacSign(string $data, ?string $key = null): string
    {
        $key = $key ?? $this->hmacKey;
        if ($key === '') {
            throw new SaTokenException('HMAC 密钥未配置');
        }

        return hash_hmac('sha256', $data, $key);
    }

    /**
     * HMAC-SHA256 验签
     *
     * @param  string      $data 原始数据
     * @param  string      $sign 十六进制签名
     * @param  string|null $key  密钥，null 使用配置密钥
     * @return bool
     */
    public function hmacVerify(string $data, string $sign, ?string $key = null): bool
    {
        $expected = $this->hmacSign($data, $key);
        return hash_equals($expected, $sign);
    }

    /**
     * 对 AES 密钥进行补位
     *
     * @param  string $key 原始密钥
     * @return string 32 字节密钥
     */
    protected function padAesKey(string $key): string
    {
        $len = strlen($key);
        if ($len >= 32) {
            return substr($key, 0, 32);
        }
        if ($len >= 24) {
            return substr($key, 0, 24);
        }
        if ($len >= 16) {
            return substr($key, 0, 16);
        }
        // 密钥不足 16 字节时，使用 HKDF-like 方式派生
        // 用 SHA-256 哈希后截取，比零填充更安全
        $derived = hash('sha256', $key . 'sa-token-aes-key', true);
        return substr($derived, 0, 16);
    }

    /**
     * 加载 RSA 私钥
     *
     * @param  string                      $privateKey PEM 格式私钥或文件路径
     * @return \OpenSSLAsymmetricKey|false
     */
    protected function loadRsaPrivateKey(string $privateKey): \OpenSSLAsymmetricKey|false
    {
        if (file_exists($privateKey)) {
            $privateKey = file_get_contents($privateKey);
        }
        return openssl_pkey_get_private($privateKey);
    }

    /**
     * 加载 RSA 公钥
     *
     * @param  string                      $publicKey PEM 格式公钥或文件路径
     * @return \OpenSSLAsymmetricKey|false
     */
    protected function loadRsaPublicKey(string $publicKey): \OpenSSLAsymmetricKey|false
    {
        if (file_exists($publicKey)) {
            $publicKey = file_get_contents($publicKey);
        }
        return openssl_pkey_get_public($publicKey);
    }
}
