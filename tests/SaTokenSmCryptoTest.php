<?php

declare(strict_types=1);

namespace SaToken\Tests;

use CryptoSm\SM2\Sm2;
use CryptoSm\SM4\Sm4;
use PHPUnit\Framework\TestCase;
use SaToken\Exception\SaTokenException;
use SaToken\Plugin\SaTokenSmCrypto;

/**
 * 国密插件测试
 *
 * 覆盖：SM2 签名验签、SM3 哈希、SM4 加解密、配置校验
 */
class SaTokenSmCryptoTest extends TestCase
{
    private bool $smAvailable = false;

    protected function setUp(): void
    {
        // 检查 CryptoSm 扩展是否可用（需要 ext-gmp + ext-openssl + OpenSSL SM4 支持）
        $this->smAvailable = class_exists(Sm2::class);
    }

    private function skipIfSmUnavailable(): void
    {
        if (!$this->smAvailable) {
            $this->markTestSkipped('pohoc/crypto-sm 扩展不可用，跳过国密测试');
        }
    }

    // ======== 构造与配置 ========

    public function testConstructorWithEmptyConfig(): void
    {
        $crypto = new SaTokenSmCrypto();
        $this->assertInstanceOf(SaTokenSmCrypto::class, $crypto);
    }

    public function testConstructorWithConfig(): void
    {
        $crypto = new SaTokenSmCrypto([
            'sm2PrivateKey' => str_repeat('ab', 32),
            'sm2PublicKey'  => str_repeat('cd', 64),
            'sm4Key'        => str_repeat('ef', 16),
        ]);
        $this->assertInstanceOf(SaTokenSmCrypto::class, $crypto);
    }

    // ======== SM2 签名 ========

    public function testSm2SignWithoutPrivateKey(): void
    {
        $crypto = new SaTokenSmCrypto();
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('SM2 私钥未配置');
        $crypto->sm2Sign('test data');
    }

    public function testSm2VerifyWithoutPublicKey(): void
    {
        $crypto = new SaTokenSmCrypto();
        $this->assertFalse($crypto->sm2Verify('test data', 'fake-sign'));
    }

    public function testSm2SignAndVerify(): void
    {
        $this->skipIfSmUnavailable();

        // 动态生成真实密钥对
        $keypair = Sm2::generateKeyPairHex();
        $privateKey = $keypair->getPrivateKey();
        $publicKey = $keypair->getPublicKey();

        $crypto = new SaTokenSmCrypto([
            'sm2PrivateKey' => $privateKey,
            'sm2PublicKey'  => $publicKey,
        ]);

        $data = 'Hello, SM2 签名验签测试！';
        $sign = $crypto->sm2Sign($data);
        $this->assertNotEmpty($sign);

        // 验签应通过
        $result = $crypto->sm2Verify($data, $sign);
        $this->assertTrue($result);
    }

    public function testSm2VerifyWithWrongData(): void
    {
        $this->skipIfSmUnavailable();

        $keypair = Sm2::generateKeyPairHex();
        $crypto = new SaTokenSmCrypto([
            'sm2PrivateKey' => $keypair->getPrivateKey(),
            'sm2PublicKey'  => $keypair->getPublicKey(),
        ]);

        $sign = $crypto->sm2Sign('original data');
        // 用错误的数据验签应失败
        $result = $crypto->sm2Verify('wrong data', $sign);
        $this->assertFalse($result);
    }

    public function testSm2VerifyWithWrongSignature(): void
    {
        $this->skipIfSmUnavailable();

        $keypair = Sm2::generateKeyPairHex();
        $crypto = new SaTokenSmCrypto([
            'sm2PublicKey' => $keypair->getPublicKey(),
        ]);

        // 用伪造签名验签应失败
        $result = $crypto->sm2Verify('test data', str_repeat('ff', 128));
        $this->assertFalse($result);
    }

    // ======== SM3 哈希 ========

    public function testSm3Hash(): void
    {
        $this->skipIfSmUnavailable();

        $crypto = new SaTokenSmCrypto();

        $hash1 = $crypto->sm3Hash('test data');
        $this->assertNotEmpty($hash1);
        $this->assertEquals(64, strlen($hash1)); // 256 位 = 64 hex chars

        // 相同输入相同输出
        $hash2 = $crypto->sm3Hash('test data');
        $this->assertEquals($hash1, $hash2);

        // 不同输入不同输出
        $hash3 = $crypto->sm3Hash('other data');
        $this->assertNotEquals($hash1, $hash3);
    }

    public function testSm3HashEmptyString(): void
    {
        $this->skipIfSmUnavailable();

        $crypto = new SaTokenSmCrypto();
        $hash = $crypto->sm3Hash('');
        $this->assertNotEmpty($hash);
        $this->assertEquals(64, strlen($hash));
    }

    public function testSm3HashChineseData(): void
    {
        $this->skipIfSmUnavailable();

        $crypto = new SaTokenSmCrypto();
        $hash = $crypto->sm3Hash('国密 SM3 哈希测试');
        $this->assertNotEmpty($hash);
        $this->assertEquals(64, strlen($hash));
    }

    // ======== SM4 加解密 ========

    public function testSm4EncryptWithoutKey(): void
    {
        $crypto = new SaTokenSmCrypto();
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('SM4 密钥未配置');
        $crypto->sm4Encrypt('test data');
    }

    public function testSm4DecryptWithoutKey(): void
    {
        $crypto = new SaTokenSmCrypto();
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('SM4 密钥未配置');
        $crypto->sm4Decrypt('encrypted data');
    }

    public function testSm4EncryptAndDecrypt(): void
    {
        $this->skipIfSmUnavailable();

        // SM4 密钥：32 位 hex（128 位）
        $sm4Key = 'aa112233445566778899aabbccddeeff';

        $crypto = new SaTokenSmCrypto(['sm4Key' => $sm4Key]);

        $plaintext = 'Hello, SM4 加密测试！';
        $encrypted = $crypto->sm4Encrypt($plaintext);
        $this->assertNotEmpty($encrypted);
        $this->assertNotEquals($plaintext, $encrypted);

        $decrypted = $crypto->sm4Decrypt($encrypted);
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testSm4EncryptWithCustomKey(): void
    {
        $this->skipIfSmUnavailable();

        $crypto = new SaTokenSmCrypto();

        $sm4Key = 'aa112233445566778899aabbccddeeff';
        $plaintext = 'Custom key test';
        $encrypted = $crypto->sm4Encrypt($plaintext, $sm4Key);
        $decrypted = $crypto->sm4Decrypt($encrypted, $sm4Key);
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testSm4DecryptWithWrongKey(): void
    {
        $this->skipIfSmUnavailable();

        $sm4Key = 'aa112233445566778899aabbccddeeff';
        $wrongKey = 'fedcba9876543210fedcba9876543210';

        $crypto = new SaTokenSmCrypto(['sm4Key' => $sm4Key]);
        $encrypted = $crypto->sm4Encrypt('test data');

        // 用错误的密钥解密应失败
        $this->expectException(SaTokenException::class);
        $crypto->sm4Decrypt($encrypted, $wrongKey);
    }

    public function testSm4EncryptEmptyString(): void
    {
        $this->skipIfSmUnavailable();

        $sm4Key = 'aa112233445566778899aabbccddeeff';
        $crypto = new SaTokenSmCrypto(['sm4Key' => $sm4Key]);

        $encrypted = $crypto->sm4Encrypt('');
        $decrypted = $crypto->sm4Decrypt($encrypted);
        $this->assertEquals('', $decrypted);
    }

    public function testSm4EncryptLongData(): void
    {
        $this->skipIfSmUnavailable();

        $sm4Key = 'aa112233445566778899aabbccddeeff';
        $crypto = new SaTokenSmCrypto(['sm4Key' => $sm4Key]);

        $plaintext = str_repeat('A long string that spans multiple blocks. ', 100);
        $encrypted = $crypto->sm4Encrypt($plaintext);
        $decrypted = $crypto->sm4Decrypt($encrypted);
        $this->assertEquals($plaintext, $decrypted);
    }

    public function testSm4DecryptInvalidHex(): void
    {
        $this->skipIfSmUnavailable();

        $sm4Key = 'aa112233445566778899aabbccddeeff';
        $crypto = new SaTokenSmCrypto(['sm4Key' => $sm4Key]);

        $this->expectException(SaTokenException::class);
        $crypto->sm4Decrypt('not-valid-hex!@#');
    }
}
