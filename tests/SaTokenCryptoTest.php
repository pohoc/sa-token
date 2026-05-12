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
        $customKey = 'custom-key-16byt';
        $encrypted = $this->crypto->aesEncrypt('test', $customKey);
        $decrypted = $this->crypto->aesDecrypt($encrypted, $customKey);
        $this->assertEquals('test', $decrypted);
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
        $sign2 = $this->crypto->hmacSign('data', 'different-key');
        $this->assertNotEquals($sign1, $sign2);
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
