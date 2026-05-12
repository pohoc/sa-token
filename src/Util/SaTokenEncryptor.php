<?php

declare(strict_types=1);

namespace SaToken\Util;

use CryptoSm\SM3\Sm3;
use CryptoSm\SM4\Sm4;
use CryptoSm\SM4\Sm4Options;
use SaToken\Exception\SaTokenException;

class SaTokenEncryptor
{
    protected string $key;

    protected bool $enabled;

    protected bool $useSm;

    public function __construct(bool $enabled, string $key, string $cryptoType = 'intl')
    {
        $this->enabled = $enabled;
        $this->useSm = ($cryptoType === 'sm');

        if ($this->useSm) {
            $this->key = $this->deriveSm4Key($key);
        } else {
            $this->key = $this->deriveAesKey($key);
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

        $hmac = hash_hmac('sha256', $iv . $ciphertext, $this->key, true);

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

        $expectedHmac = hash_hmac('sha256', $iv . $ciphertext, $this->key, true);
        if (!hash_equals($hmac, $expectedHmac)) {
            return $data;
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

            $hmac = Sm3::sm3($iv . $ciphertext);

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

        $expectedHmac = Sm3::sm3($iv . $ciphertext);
        if (!hash_equals($expectedHmac, $hmac)) {
            return $data;
        }

        try {
            $options = (new Sm4Options())->setIv($iv);
            return Sm4::decrypt($ciphertext, $this->key, $options);
        } catch (\Throwable) {
            return $data;
        }
    }

    protected function deriveAesKey(string $key): string
    {
        if ($key === '') {
            return hash_hkdf('sha256', 'sa-token-default-encrypt-key', 32, 'token-encrypt', '');
        }
        if (strlen($key) >= 32) {
            return substr($key, 0, 32);
        }
        return hash_hkdf('sha256', $key, 32, 'sa-token-encrypt', '');
    }

    protected function deriveSm4Key(string $key): string
    {
        if ($key === '') {
            return substr(bin2hex(hash_hkdf('sha256', 'sa-token-default-sm4-key', 32, 'token-encrypt-sm4', '')), 0, 32);
        }
        if (strlen($key) >= 32 && ctype_xdigit($key)) {
            return substr($key, 0, 32);
        }
        return substr(bin2hex(hash_hkdf('sha256', $key, 32, 'sa-token-sm4-encrypt', '')), 0, 32);
    }
}
