<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Exception\SaTokenException;
use SaToken\Plugin\SaTokenCrypto;

class SaTokenCryptoTest extends TestCase
{
    protected SaTokenCrypto $crypto;

    protected function setUp(): void
    {
        $aesKey = getenv('TEST_AES_KEY_32') ?: 'test-key-placeholder-32-bytes-lo';
        $hmacKey = getenv('TEST_HMAC_KEY') ?: 'test-key-placeholder-32-bytes-lo';
        $this->crypto = new SaTokenCrypto([
            'aesKey'  => $aesKey,
            'hmacKey' => $hmacKey,
        ]);
    }

    public function testBcryptRejectsPasswordsLongerThanIts72ByteInputLimit(): void
    {
        $prefix = str_repeat('a', 72);
        $hash = SaTokenCrypto::bcryptHash($prefix, 10);

        self::assertTrue(SaTokenCrypto::bcryptVerify($prefix, $hash));
        self::assertFalse(SaTokenCrypto::bcryptVerify($prefix . 'suffix', $hash));

        try {
            SaTokenCrypto::bcryptHash($prefix . 'suffix', 10);
            self::fail('bcrypt must reject passwords that would be silently truncated');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('72 字节', $exception->getMessage());
        }
    }

    public function testBcryptHashRejectsUnsafeCostValues(): void
    {
        foreach ([9, 32] as $cost) {
            try {
                SaTokenCrypto::bcryptHash('password', $cost);
                self::fail('bcrypt cost ' . $cost . ' must be rejected');
            } catch (SaTokenException $exception) {
                self::assertStringContainsString('10 到 31', $exception->getMessage());
            }
        }
    }

    // ---- AES ----

    public function testAesEncryptAndDecrypt(): void
    {
        $plaintext = 'Hello, World! 你好世界';
        $encrypted = $this->crypto->aesEncrypt($plaintext);
        $decrypted = $this->crypto->aesDecrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testAesEncryptReturnsBase64(): void
    {
        $encrypted = $this->crypto->aesEncrypt('test');
        $this->assertTrue(base64_decode($encrypted, true) !== false);
    }

    public function testAesDifferentInputsProduceDifferentCiphertexts(): void
    {
        $enc1 = $this->crypto->aesEncrypt('data1');
        $enc2 = $this->crypto->aesEncrypt('data2');
        $this->assertNotEquals($enc1, $enc2);
    }

    public function testAesSameInputDifferentIv(): void
    {
        $enc1 = $this->crypto->aesEncrypt('same-data');
        $enc2 = $this->crypto->aesEncrypt('same-data');
        // IV 不同，密文应不同
        $this->assertNotEquals($enc1, $enc2);
        // 但都能正确解密
        $this->assertEquals('same-data', $this->crypto->aesDecrypt($enc1));
        $this->assertEquals('same-data', $this->crypto->aesDecrypt($enc2));
    }

    public function testAesWithCustomKey(): void
    {
        $customKey = 'custom-key-at-least-32-bytes-long';
        $encrypted = $this->crypto->aesEncrypt('test', $customKey);
        $decrypted = $this->crypto->aesDecrypt($encrypted, $customKey);
        $this->assertEquals('test', $decrypted);
    }

    public function testAesRejectsShortKeysForAuthenticatedEncryptionAndDecryption(): void
    {
        $this->expectException(SaTokenException::class);
        $this->crypto->aesEncrypt('test', 'short');
    }

    public function testAesDecryptRejectsShortKeys(): void
    {
        $this->expectException(SaTokenException::class);
        $this->crypto->aesDecrypt('not-used', 'short');
    }

    public function testAesEncryptEmptyString(): void
    {
        $encrypted = $this->crypto->aesEncrypt('');
        $decrypted = $this->crypto->aesDecrypt($encrypted);
        $this->assertEquals('', $decrypted);
    }

    public function testAesEncryptLongData(): void
    {
        $data = str_repeat('A', 10000);
        $encrypted = $this->crypto->aesEncrypt($data);
        $decrypted = $this->crypto->aesDecrypt($encrypted);
        $this->assertEquals($data, $decrypted);
    }

    public function testAesDecryptInvalidBase64(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('AES 解密失败');
        $this->crypto->aesDecrypt('!!!invalid-base64!!!');
    }

    public function testAesDecryptInvalidCiphertext(): void
    {
        $this->expectException(SaTokenException::class);
        @$this->crypto->aesDecrypt(base64_encode('garbage-data'));
    }

    public function testAesDecryptRejectsLegacyCiphertextWhoseIvMatchesAeadMarker(): void
    {
        $key = str_repeat('k', 32);
        $iv = 'SAT1' . str_repeat("\0", 12);
        foreach (['short legacy plaintext', str_repeat('legacy plaintext ', 4)] as $plaintext) {
            $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
            $this->assertNotFalse($encrypted);

            try {
                $this->crypto->aesDecrypt(base64_encode($iv . $encrypted), $key);
                self::fail('密文标记命中后不得回退到旧格式解密');
            } catch (SaTokenException $exception) {
                $this->assertStringContainsString('完整性校验未通过', $exception->getMessage());
            }
        }
    }

    public function testAesDecryptRejectsUnauthenticatedLegacyCiphertext(): void
    {
        $key = str_repeat('k', 32);
        $iv = random_bytes(16);
        $plaintext = 'isAdmin=0;hello!';
        $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        $this->assertNotFalse($encrypted);

        // 旧版没有 MAC：翻转 IV 中对应字节会在解密后把 0 改为 1，且 CBC padding 不变。
        $tamperedIv = $iv;
        $tamperedIv[8] = chr((ord($tamperedIv[8]) ^ (ord('0') ^ ord('1'))) & 0xff);
        $tamperedLegacyCiphertext = base64_encode($tamperedIv . $encrypted);

        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('拒绝未认证的旧版 AES-CBC 密文');
        $this->crypto->aesDecrypt($tamperedLegacyCiphertext, $key);
    }

    public function testLegacyCiphertextCanOnlyBeReadThroughExplicitMigrationMethod(): void
    {
        $key = str_repeat('k', 32);
        $iv = random_bytes(16);
        $plaintext = 'legacy plaintext';
        $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        $this->assertNotFalse($encrypted);
        $legacyCiphertext = base64_encode($iv . $encrypted);

        $this->assertSame($plaintext, $this->crypto->aesDecryptLegacy($legacyCiphertext, $key));
    }

    public function testAesNoKeyConfigured(): void
    {
        $crypto = new SaTokenCrypto([]);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('AES 密钥未配置');
        $crypto->aesEncrypt('test');
    }

    public function testAesDecryptNoKeyConfigured(): void
    {
        $crypto = new SaTokenCrypto([]);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('AES 密钥未配置');
        $crypto->aesDecrypt('dGVzdA==');
    }

    // ---- RSA ----

    public function testRsaSignAndVerify(): void
    {
        $keyPair = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($keyPair);
        openssl_pkey_export($keyPair, $privateKey);
        $this->assertNotFalse($privateKey);
        $details = openssl_pkey_get_details($keyPair);
        $this->assertNotFalse($details);
        $this->assertArrayHasKey('key', $details);
        $publicKey = $details['key'];

        $crypto = new SaTokenCrypto([
            'rsaPrivateKey' => $privateKey,
            'rsaPublicKey'  => $publicKey,
        ]);

        $data = 'Hello, RSA! 你好RSA';
        $sign = $crypto->rsaSign($data);

        $this->assertNotEmpty($sign);
        $this->assertTrue($crypto->rsaVerify($data, $sign));
    }

    public function testRsaVerifyFailsWithWrongData(): void
    {
        $keyPair = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($keyPair);
        openssl_pkey_export($keyPair, $privateKey);
        $this->assertNotFalse($privateKey);
        $details = openssl_pkey_get_details($keyPair);
        $this->assertNotFalse($details);
        $this->assertArrayHasKey('key', $details);
        $publicKey = $details['key'];

        $crypto = new SaTokenCrypto([
            'rsaPrivateKey' => $privateKey,
            'rsaPublicKey'  => $publicKey,
        ]);

        $sign = $crypto->rsaSign('original-data');
        $this->assertFalse($crypto->rsaVerify('tampered-data', $sign));
    }

    public function testRsaVerifyRejectsNonCanonicalBase64Signature(): void
    {
        $keyPair = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($keyPair);
        self::assertTrue(openssl_pkey_export($keyPair, $privateKey));
        $details = openssl_pkey_get_details($keyPair);
        self::assertIsArray($details);

        $crypto = new SaTokenCrypto([
            'rsaPrivateKey' => $privateKey,
            'rsaPublicKey' => $details['key'],
        ]);
        $signature = $crypto->rsaSign('signed payload');
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        $padBitsPosition = strlen($signature) - 3;
        $canonicalValue = strpos($alphabet, $signature[$padBitsPosition]);
        self::assertIsInt($canonicalValue);
        $alias = $signature;
        $alias[$padBitsPosition] = $alphabet[($canonicalValue & 48) | (($canonicalValue + 1) & 15)];

        self::assertSame(base64_decode($signature, true), base64_decode($alias, true));
        self::assertTrue($crypto->rsaVerify('signed payload', $signature));
        self::assertFalse($crypto->rsaVerify('signed payload', $alias));
    }

    public function testRsaRejectsKeysShorterThan2048Bits(): void
    {
        $keyPair = openssl_pkey_new([
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($keyPair);
        $this->assertTrue(openssl_pkey_export($keyPair, $privateKey));
        $details = openssl_pkey_get_details($keyPair);
        $this->assertIsArray($details);

        $crypto = new SaTokenCrypto([
            'rsaPrivateKey' => $privateKey,
            'rsaPublicKey' => $details['key'],
        ]);

        try {
            $crypto->rsaSign('data');
            $this->fail('1024 位 RSA 密钥不应签名');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('不足 2048 位', $e->getMessage());
        }

        $this->assertFalse($crypto->rsaVerify('data', base64_encode('invalid')));
    }

    public function testRsaMethodsRejectNonRsaKeys(): void
    {
        $keyPair = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $this->assertNotFalse($keyPair);
        $this->assertTrue(openssl_pkey_export($keyPair, $privateKey));
        $details = openssl_pkey_get_details($keyPair);
        $this->assertIsArray($details);

        $crypto = new SaTokenCrypto([
            'rsaPrivateKey' => $privateKey,
            'rsaPublicKey' => $details['key'],
        ]);

        try {
            $crypto->rsaSign('data');
            $this->fail('EC 密钥不应被 RSA 签名方法接受');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('类型无效', $e->getMessage());
        }

        $this->assertFalse($crypto->rsaVerify('data', base64_encode('invalid')));
    }

    public function testRsaSignNoPrivateKey(): void
    {
        $crypto = new SaTokenCrypto([]);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('RSA 私钥未配置');
        $crypto->rsaSign('test');
    }

    public function testRsaVerifyNoPublicKey(): void
    {
        $crypto = new SaTokenCrypto([]);
        $this->assertFalse($crypto->rsaVerify('data', 'sign'));
    }

    public function testRsaVerifyInvalidSignature(): void
    {
        $keyPair = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $this->assertNotFalse($keyPair);
        $details = openssl_pkey_get_details($keyPair);
        $this->assertNotFalse($details);
        $this->assertArrayHasKey('key', $details);
        $publicKey = $details['key'];

        $crypto = new SaTokenCrypto(['rsaPublicKey' => $publicKey]);
        $this->assertFalse($crypto->rsaVerify('data', base64_encode('invalid-signature')));
    }

    // ---- HMAC ----

    public function testHmacSignAndVerify(): void
    {
        $data = 'Hello, HMAC!';
        $sign = $this->crypto->hmacSign($data);

        $this->assertNotEmpty($sign);
        $this->assertEquals(64, strlen($sign)); // SHA-256 hex 长度
        $this->assertTrue($this->crypto->hmacVerify($data, $sign));
    }

    public function testHmacVerifyFailsWithWrongSign(): void
    {
        $sign = $this->crypto->hmacSign('original');
        $this->assertFalse($this->crypto->hmacVerify('tampered', $sign));
    }

    public function testHmacSignWithCustomKey(): void
    {
        $sign1 = $this->crypto->hmacSign('data');
        $sign2 = $this->crypto->hmacSign('data', str_repeat('different-key', 3));
        $this->assertNotEquals($sign1, $sign2);
    }

    public function testHmacSignRejectsKeysShorterThan32Bytes(): void
    {
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('至少需要 32 字节');
        $this->crypto->hmacSign('data', 'short-key');
    }

    public function testStaticHmacHelpersRejectKeysShorterThan32Bytes(): void
    {
        try {
            SaTokenCrypto::hmacSha256('data', 'short-key');
            self::fail('hmacSha256 must reject weak keys');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('至少需要 32 字节', $exception->getMessage());
        }

        try {
            SaTokenCrypto::hmacSha1('data', 'short-key');
            self::fail('hmacSha1 must reject weak keys');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('至少需要 32 字节', $exception->getMessage());
        }
    }

    public function testHmacNoKeyConfigured(): void
    {
        $crypto = new SaTokenCrypto([]);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('HMAC 密钥未配置');
        $crypto->hmacSign('test');
    }

    public function testHmacVerifyNoKeyConfigured(): void
    {
        $crypto = new SaTokenCrypto([]);
        $this->expectException(SaTokenException::class);
        $crypto->hmacVerify('data', 'sign');
    }

    public function testHmacDeterministic(): void
    {
        $sign1 = $this->crypto->hmacSign('same-data');
        $sign2 = $this->crypto->hmacSign('same-data');
        $this->assertEquals($sign1, $sign2);
    }
}
