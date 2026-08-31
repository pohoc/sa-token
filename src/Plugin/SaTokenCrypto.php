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
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [])
    {
        if (!extension_loaded('openssl')) {
            throw new SaTokenException('国际加密插件需要 OpenSSL 扩展');
        }

        $aesKey = $config['aesKey'] ?? '';
        $this->aesKey = is_string($aesKey) ? $aesKey : '';
        $rsaPrivateKey = $config['rsaPrivateKey'] ?? '';
        $this->rsaPrivateKey = is_string($rsaPrivateKey) ? $rsaPrivateKey : '';
        $rsaPublicKey = $config['rsaPublicKey'] ?? '';
        $this->rsaPublicKey = is_string($rsaPublicKey) ? $rsaPublicKey : '';
        $hmacKey = $config['hmacKey'] ?? '';
        $this->hmacKey = is_string($hmacKey) ? $hmacKey : '';
    }

    private const AEAD_MAGIC = 'SAT1';

    /**
     * AES 加密（Encrypt-then-MAC）
     *
     * CBC 模式本身不提供完整性：无 MAC 的密文可被篡改（比特翻转），
     * 且解密失败的差异可被用作 padding oracle。新格式为
     * MAGIC(4) + HMAC-SHA256(32, 独立派生密钥) + IV + 密文
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

        $ivLength = openssl_cipher_iv_length('AES-256-CBC') ?: 16;
        if ($ivLength <= 0) {
            throw new SaTokenException('AES 加密失败：无法获取 IV 长度');
        }
        $iv = random_bytes($ivLength);
        $paddedKey = $this->padAesKey($key);

        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $paddedKey, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new SaTokenException('AES 加密失败');
        }

        $mac = hash_hmac('sha256', $iv . $encrypted, $this->deriveAesMacKey($paddedKey), true);

        return base64_encode(self::AEAD_MAGIC . $mac . $iv . $encrypted);
    }

    /**
     * AES 解密
     *
     * 新格式先验证 MAC（失败直接抛异常，不尝试解密）；
     * 旧格式（无 MAGIC 前缀的历史密文）按原逻辑解密以保持兼容
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
        $paddedKey = $this->padAesKey($key);

        $macLength = strlen(self::AEAD_MAGIC) + 32;
        if (str_starts_with($decoded, self::AEAD_MAGIC) && strlen($decoded) >= $macLength + $ivLength) {
            $mac = substr($decoded, 4, 32);
            $iv = substr($decoded, $macLength, $ivLength);
            $encrypted = substr($decoded, $macLength + $ivLength);

            $expectedMac = hash_hmac('sha256', $iv . $encrypted, $this->deriveAesMacKey($paddedKey), true);
            if (!hash_equals($expectedMac, $mac)) {
                // 旧格式随机 IV 的前 4 字节恰好是 'SAT1' 的概率约 2^-32，
                // 命中后 MAC 必然不符——回退旧格式分支尝试解密而非直接判损
                $legacyIv = substr($decoded, 0, $ivLength);
                $legacyEncrypted = substr($decoded, $ivLength);
                $legacyPlaintext = openssl_decrypt($legacyEncrypted, 'AES-256-CBC', $paddedKey, OPENSSL_RAW_DATA, $legacyIv);
                if ($legacyPlaintext !== false) {
                    return $legacyPlaintext;
                }
                throw new SaTokenException('AES 解密失败：密文完整性校验未通过（可能被篡改）');
            }
        } else {
            $iv = substr($decoded, 0, $ivLength);
            $encrypted = substr($decoded, $ivLength);
        }

        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $paddedKey, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new SaTokenException('AES 解密失败');
        }

        return $decrypted;
    }

    /**
     * 插件 AES 的 MAC 独立密钥（与加密密钥分离）
     */
    protected function deriveAesMacKey(string $paddedKey): string
    {
        return hash_hkdf('sha256', $paddedKey, 32, 'sa-token-aes-plugin-mac', '');
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

        return base64_encode(is_string($signature) ? $signature : '');
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

    public static function md5(string $data): string
    {
        return hash('md5', $data);
    }

    public static function sha1(string $data): string
    {
        return hash('sha1', $data);
    }

    public static function sha256(string $data): string
    {
        return hash('sha256', $data);
    }

    public static function hmacSha256(string $data, string $key): string
    {
        return hash_hmac('sha256', $data, $key);
    }

    public static function hmacSha1(string $data, string $key): string
    {
        return hash_hmac('sha1', $data, $key);
    }

    public static function bcryptVerify(string $data, string $hash): bool
    {
        return password_verify($data, $hash);
    }

    public static function bcryptHash(string $data, int $cost = 10): string
    {
        return password_hash($data, PASSWORD_BCRYPT, ['cost' => $cost]);
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
        return hash_hkdf('sha256', $key, 16, 'sa-token-aes-key', '');
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
            $content = file_get_contents($privateKey);
            if ($content === false) {
                return false;
            }
            $privateKey = $content;
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
            $content = file_get_contents($publicKey);
            if ($content === false) {
                return false;
            }
            $publicKey = $content;
        }
        return openssl_pkey_get_public($publicKey);
    }
}
