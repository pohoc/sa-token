<?php

declare(strict_types=1);

namespace SaToken\Util;

use CryptoSm\SM3\HmacSm3;
use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use SaToken\Exception\SaTokenException;

class SaTokenEncryptor
{
    protected string $key;

    protected string $macKey;

    protected bool $enabled;

    protected bool $useSm;

    public function __construct(bool $enabled, string $key, string $cryptoType = 'intl')
    {
        $this->enabled = $enabled;
        $this->useSm = ($cryptoType === 'sm');

        if ($this->useSm) {
            $this->key = $this->deriveSm4Key($key);
            $this->macKey = substr(bin2hex(hash_hkdf('sha256', $this->key, 32, 'sa-token-sm4-mac', '')), 0, 32);
        } else {
            $this->key = $this->deriveAesKey($key);
            $this->macKey = substr(hash_hkdf('sha256', $this->key, 32, 'sa-token-aes-mac', ''), 0, 32);
        }
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function isSmMode(): bool
    {
        return $this->useSm;
    }

    public function encrypt(string $plaintext): string
    {
        if (!$this->enabled) {
            return $plaintext;
        }

        return $this->useSm ? $this->sm4Encrypt($plaintext) : $this->aesEncrypt($plaintext);
    }

    public function decrypt(string $data): string
    {
        if (!$this->enabled) {
            return $data;
        }

        return $this->useSm ? $this->sm4Decrypt($data) : $this->aesDecrypt($data);
    }

    protected function aesEncrypt(string $plaintext): string
    {
        $iv = random_bytes(16);
        $ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new SaTokenException('Token 内容加密失败（AES）');
        }

        // Encrypt-then-MAC，MAC 使用独立派生的密钥（与加密密钥分离）
        $hmac = hash_hmac('sha256', $iv . $ciphertext, $this->macKey, true);

        return base64_encode($hmac . $iv . $ciphertext);
    }

    protected function aesDecrypt(string $data): string
    {
        $decoded = base64_decode($data, true);
        if ($decoded === false || strlen($decoded) < 48) {
            return $data;
        }

        $hmac = substr($decoded, 0, 32);
        $iv = substr($decoded, 32, 16);
        $ciphertext = substr($decoded, 48);

        // 兼容历史格式：先验独立 MAC 密钥，再回退旧版（与加密密钥相同）格式
        $expectedHmac = hash_hmac('sha256', $iv . $ciphertext, $this->macKey, true);
        if (!hash_equals($hmac, $expectedHmac)) {
            $legacyHmac = hash_hmac('sha256', $iv . $ciphertext, $this->key, true);
            if (!hash_equals($hmac, $legacyHmac)) {
                return $data;
            }
        }

        $plaintext = openssl_decrypt($ciphertext, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) {
            return $data;
        }

        return $plaintext;
    }

    protected function sm4Encrypt(string $plaintext): string
    {
        try {
            $options = new Sm4Options();
            $iv = $options->getIv();
            $ciphertext = Sm4::encrypt($plaintext, $this->key, $options);

            // 完整性必须使用带密钥的 HMAC-SM3：无密钥的 SM3 无法防御存储层篡改
            $hmac = HmacSm3::hmac($this->macKey, $iv . $ciphertext);

            return base64_encode(hex2bin($hmac) . hex2bin($iv) . hex2bin($ciphertext));
        } catch (\Throwable $e) {
            throw new SaTokenException('Token 内容加密失败（SM4）：' . $e->getMessage(), 0, $e);
        }
    }

    protected function sm4Decrypt(string $data): string
    {
        $decoded = base64_decode($data, true);
        if ($decoded === false || strlen($decoded) < 64) {
            return $data;
        }

        $hmac = bin2hex(substr($decoded, 0, 32));
        $iv = bin2hex(substr($decoded, 32, 16));
        $ciphertext = bin2hex(substr($decoded, 48));

        // 兼容历史格式：先验 HMAC-SM3（独立密钥），再回退旧版无密钥 SM3 格式
        $expectedHmac = HmacSm3::hmac($this->macKey, $iv . $ciphertext);
        if (!hash_equals($expectedHmac, $hmac)) {
            $legacyHmac = Sm3::sm3($iv . $ciphertext);
            if (!hash_equals($legacyHmac, $hmac)) {
                return $data;
            }
        }

        try {
            $options = (new Sm4Options())->setIv($iv);
            return Sm4::decrypt($ciphertext, $this->key, $options);
        } catch (\Throwable) {
            return $data;
        }
    }

    /**
     * 解密并校验完整性，失败时返回 null（区别于"数据不存在"）。
     * decrypt() 出于兼容存量明文/迁移场景会静默返回原文，无法感知篡改；
     * 对安全敏感的读取路径建议使用本方法。
     */
    public function decryptChecked(string $data): ?string
    {
        if (!$this->enabled) {
            return $data;
        }

        $plaintext = $this->decrypt($data);
        if ($plaintext === $data && $this->isCiphertext($data)) {
            return null;
        }
        return $plaintext;
    }

    /**
     * 判断输入是否符合本加密器的密文格式（base64 解码后长度足够且含 MAC 结构）
     */
    public function isCiphertext(string $data): bool
    {
        if (!$this->enabled) {
            return false;
        }
        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            return false;
        }
        return $this->useSm ? strlen($decoded) >= 64 : strlen($decoded) >= 48;
    }

    protected function deriveAesKey(string $key): string
    {
        if ($key === '') {
            $isTest = defined('PHPUNIT_COMPOSER_INSTALL') || getenv('PHPUNIT_TESTING') !== false;
            if ($isTest) {
                return hash_hkdf('sha256', 'sa-token-default-encrypt-key', 32, 'token-encrypt', '');
            }
            throw new SaTokenException('Sa-Token: 未配置加密密钥，请在生产环境中配置 aesKey 或 tokenEncryptKey');
        }
        if (strlen($key) >= 32) {
            return substr($key, 0, 32);
        }
        return hash_hkdf('sha256', $key, 32, 'sa-token-encrypt', '');
    }

    protected function deriveSm4Key(string $key): string
    {
        if ($key === '') {
            $isTest = defined('PHPUNIT_COMPOSER_INSTALL') || getenv('PHPUNIT_TESTING') !== false;
            if ($isTest) {
                return substr(bin2hex(hash_hkdf('sha256', 'sa-token-default-sm4-key', 32, 'token-encrypt-sm4', '')), 0, 32);
            }
            throw new SaTokenException('Sa-Token: 未配置 SM4 加密密钥，请在生产环境中配置 sm4Key 或 tokenEncryptKey');
        }
        if (strlen($key) >= 32 && ctype_xdigit($key)) {
            return substr($key, 0, 32);
        }
        return substr(bin2hex(hash_hkdf('sha256', $key, 32, 'sa-token-sm4-encrypt', '')), 0, 32);
    }
}
