<?php

declare(strict_types=1);

namespace SaToken\Tests;

use CryptoSm\SM4\Sm4;
use PHPUnit\Framework\TestCase;
use SaToken\Util\SaTokenEncryptor;

class SaTokenEncryptorTest extends TestCase
{
    private function createAesEncryptor(bool $enabled = true, string $key = 'PLACEHOLDER_AES_KEY'): SaTokenEncryptor
    {
        return new SaTokenEncryptor($enabled, $key, 'intl');
    }

    private function createSm4Encryptor(bool $enabled = true, string $key = 'PLACEHOLDER_SM4_KEY'): SaTokenEncryptor
    {
        return new SaTokenEncryptor($enabled, $key, 'sm');
    }

    private function getDerivedKey(SaTokenEncryptor $encryptor): string
    {
        $ref = new \ReflectionClass($encryptor);
        $prop = $ref->getProperty('key');
        return $prop->getValue($encryptor);
    }

    public function testAesEncryptDecryptRoundTrip(): void
    {
        $encryptor = $this->createAesEncryptor();
        $plaintext = 'Hello, World!';
        $encrypted = $encryptor->encrypt($plaintext);
        $this->assertNotEquals($plaintext, $encrypted);
        $this->assertEquals($plaintext, $encryptor->decrypt($encrypted));
    }

    public function testAesEncryptProducesBase64(): void
    {
        $encryptor = $this->createAesEncryptor();
        $encrypted = $encryptor->encrypt('test');
        $this->assertNotFalse(base64_decode($encrypted, true));
    }

    public function testAesSameInputDifferentCiphertext(): void
    {
        $encryptor = $this->createAesEncryptor();
        $enc1 = $encryptor->encrypt('same-data');
        $enc2 = $encryptor->encrypt('same-data');
        $this->assertNotEquals($enc1, $enc2);
        $this->assertEquals('same-data', $encryptor->decrypt($enc1));
        $this->assertEquals('same-data', $encryptor->decrypt($enc2));
    }

    public function testAesHmacIntegrityCheck(): void
    {
        $encryptor = $this->createAesEncryptor();
        $encrypted = $encryptor->encrypt('test-data');
        $decoded = base64_decode($encrypted, true);
        $this->assertNotFalse($decoded);
        $this->assertGreaterThanOrEqual(48, strlen($decoded));
        $hmac = substr($decoded, 0, 32);
        $iv = substr($decoded, 32, 16);
        $ciphertext = substr($decoded, 48);
        $key = $this->getDerivedKey($encryptor);
        $expectedHmac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
        $this->assertTrue(hash_equals($hmac, $expectedHmac));
    }

    public function testAesTamperDetection(): void
    {
        $encryptor = $this->createAesEncryptor();
        $encrypted = $encryptor->encrypt('important-data');
        $decoded = base64_decode($encrypted, true);
        $tampered = substr($decoded, 0, 40) . chr(ord($decoded[40]) ^ 0xFF) . substr($decoded, 41);
        $tamperedEncoded = base64_encode($tampered);
        $this->assertEquals($tamperedEncoded, $encryptor->decrypt($tamperedEncoded));
    }

    public function testAesTamperHmacDetection(): void
    {
        $encryptor = $this->createAesEncryptor();
        $encrypted = $encryptor->encrypt('important-data');
        $decoded = base64_decode($encrypted, true);
        $tampered = chr(ord($decoded[0]) ^ 0xFF) . substr($decoded, 1);
        $tamperedEncoded = base64_encode($tampered);
        $this->assertEquals($tamperedEncoded, $encryptor->decrypt($tamperedEncoded));
    }

    public function testAesDisabledPassthrough(): void
    {
        $encryptor = $this->createAesEncryptor(false);
        $data = 'passthrough-data';
        $this->assertEquals($data, $encryptor->encrypt($data));
        $this->assertEquals($data, $encryptor->decrypt($data));
    }

    public function testAesDisabledEncryptReturnsIdenticalReference(): void
    {
        $encryptor = $this->createAesEncryptor(false);
        $data = 'test';
        $this->assertSame($data, $encryptor->encrypt($data));
    }

    public function testAesDisabledDecryptReturnsIdenticalReference(): void
    {
        $encryptor = $this->createAesEncryptor(false);
        $data = 'test';
        $this->assertSame($data, $encryptor->decrypt($data));
    }

    public function testAesKeyDerivationEmptyKey(): void
    {
        $e1 = new SaTokenEncryptor(true, '', 'intl');
        $e2 = new SaTokenEncryptor(true, '', 'intl');
        $this->assertEquals($this->getDerivedKey($e1), $this->getDerivedKey($e2));
        $this->assertEquals(32, strlen($this->getDerivedKey($e1)));
        $encrypted = $e1->encrypt('test');
        $this->assertEquals('test', $e2->decrypt($encrypted));
    }

    public function testAesKeyDerivationShortKey(): void
    {
        $e1 = new SaTokenEncryptor(true, 'short', 'intl');
        $e2 = new SaTokenEncryptor(true, 'short', 'intl');
        $this->assertEquals($this->getDerivedKey($e1), $this->getDerivedKey($e2));
        $this->assertEquals(32, strlen($this->getDerivedKey($e1)));
        $encrypted = $e1->encrypt('test');
        $this->assertEquals('test', $e2->decrypt($encrypted));
    }

    public function testAesKeyDerivationLongKey(): void
    {
        $longKey = str_repeat('a', 64);
        $encryptor = new SaTokenEncryptor(true, $longKey, 'intl');
        $this->assertEquals(substr($longKey, 0, 32), $this->getDerivedKey($encryptor));
    }

    public function testAesKeyDerivationExact32Key(): void
    {
        $key32 = str_repeat('k', 32);
        $encryptor = new SaTokenEncryptor(true, $key32, 'intl');
        $this->assertEquals($key32, $this->getDerivedKey($encryptor));
    }

    public function testAesDifferentKeysCannotDecrypt(): void
    {
        $e1 = new SaTokenEncryptor(true, 'PLACEHOLDER_KEY_ONE', 'intl');
        $e2 = new SaTokenEncryptor(true, 'PLACEHOLDER_KEY_TWO', 'intl');
        $encrypted = $e1->encrypt('secret');
        $decrypted = $e2->decrypt($encrypted);
        $this->assertNotEquals('secret', $decrypted);
    }

    public function testAesDecryptInvalidBase64(): void
    {
        $encryptor = $this->createAesEncryptor();
        $this->assertEquals('!!!invalid-base64!!!', $encryptor->decrypt('!!!invalid-base64!!!'));
    }

    public function testAesDecryptTooShort(): void
    {
        $encryptor = $this->createAesEncryptor();
        $short = base64_encode('short');
        $this->assertEquals($short, $encryptor->decrypt($short));
    }

    public function testSm4EncryptDecryptRoundTrip(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $plaintext = 'Hello, SM4!';
        $encrypted = $encryptor->encrypt($plaintext);
        $this->assertNotEquals($plaintext, $encrypted);
        $this->assertEquals($plaintext, $encryptor->decrypt($encrypted));
    }

    public function testSm4EncryptProducesBase64(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $encrypted = $encryptor->encrypt('test');
        $this->assertNotFalse(base64_decode($encrypted, true));
    }

    public function testSm4SameInputDifferentCiphertext(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $enc1 = $encryptor->encrypt('same-data');
        $enc2 = $encryptor->encrypt('same-data');
        $this->assertNotEquals($enc1, $enc2);
        $this->assertEquals('same-data', $encryptor->decrypt($enc1));
        $this->assertEquals('same-data', $encryptor->decrypt($enc2));
    }

    public function testSm4HmacIntegrityCheck(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $encrypted = $encryptor->encrypt('test-data');
        $decoded = base64_decode($encrypted, true);
        $this->assertNotFalse($decoded);
        $this->assertGreaterThanOrEqual(64, strlen($decoded));
        $decrypted = $encryptor->decrypt($encrypted);
        $this->assertEquals('test-data', $decrypted);
    }

    public function testSm4TamperDetection(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $encrypted = $encryptor->encrypt('important-data');
        $decoded = base64_decode($encrypted, true);
        $tampered = substr($decoded, 0, 40) . chr(ord($decoded[40]) ^ 0xFF) . substr($decoded, 41);
        $tamperedEncoded = base64_encode($tampered);
        $this->assertEquals($tamperedEncoded, $encryptor->decrypt($tamperedEncoded));
    }

    public function testSm4TamperHmacDetection(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $encrypted = $encryptor->encrypt('important-data');
        $decoded = base64_decode($encrypted, true);
        $tampered = chr(ord($decoded[0]) ^ 0xFF) . substr($decoded, 1);
        $tamperedEncoded = base64_encode($tampered);
        $this->assertEquals($tamperedEncoded, $encryptor->decrypt($tamperedEncoded));
    }

    public function testSm4DisabledPassthrough(): void
    {
        $encryptor = $this->createSm4Encryptor(false);
        $data = 'passthrough-data';
        $this->assertEquals($data, $encryptor->encrypt($data));
        $this->assertEquals($data, $encryptor->decrypt($data));
    }

    public function testSm4KeyDerivationEmptyKey(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $e1 = new SaTokenEncryptor(true, '', 'sm');
        $e2 = new SaTokenEncryptor(true, '', 'sm');
        $this->assertEquals($this->getDerivedKey($e1), $this->getDerivedKey($e2));
        $this->assertEquals(32, strlen($this->getDerivedKey($e1)));
    }

    public function testSm4KeyDerivationEmptyKeyThrowsOnEncrypt(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = new SaTokenEncryptor(true, '', 'sm');
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $encryptor->encrypt('test');
    }

    public function testSm4KeyDerivationShortKey(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $e1 = new SaTokenEncryptor(true, 'short', 'sm');
        $e2 = new SaTokenEncryptor(true, 'short', 'sm');
        $this->assertEquals($this->getDerivedKey($e1), $this->getDerivedKey($e2));
        $this->assertEquals(32, strlen($this->getDerivedKey($e1)));
    }

    public function testSm4KeyDerivationShortKeyThrowsOnEncrypt(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = new SaTokenEncryptor(true, 'short', 'sm');
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $encryptor->encrypt('test');
    }

    public function testSm4KeyDerivationLongHexKey(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $longHexKey = 'PLACEHOLDER_SM4_KEYPLACEHOLDER_SM4_KEY';
        $encryptor = new SaTokenEncryptor(true, $longHexKey, 'sm');
        $this->assertEquals(substr($longHexKey, 0, 32), $this->getDerivedKey($encryptor));
        $encrypted = $encryptor->encrypt('test');
        $this->assertEquals('test', $encryptor->decrypt($encrypted));
    }

    public function testSm4KeyDerivationLongNonHexKey(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $longNonHexKey = str_repeat('z', 64);
        $e1 = new SaTokenEncryptor(true, $longNonHexKey, 'sm');
        $e2 = new SaTokenEncryptor(true, $longNonHexKey, 'sm');
        $this->assertEquals($this->getDerivedKey($e1), $this->getDerivedKey($e2));
        $this->assertEquals(32, strlen($this->getDerivedKey($e1)));
    }

    public function testSm4KeyDerivationLongNonHexKeyThrowsOnEncrypt(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $longNonHexKey = str_repeat('z', 64);
        $encryptor = new SaTokenEncryptor(true, $longNonHexKey, 'sm');
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $encryptor->encrypt('test');
    }

    public function testSm4DifferentKeysCannotDecrypt(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $e1 = new SaTokenEncryptor(true, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'sm');
        $e2 = new SaTokenEncryptor(true, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'sm');
        $encrypted = $e1->encrypt('secret');
        $decrypted = $e2->decrypt($encrypted);
        $this->assertNotEquals('secret', $decrypted);
    }

    public function testSm4DecryptInvalidBase64(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $this->assertEquals('!!!invalid-base64!!!', $encryptor->decrypt('!!!invalid-base64!!!'));
    }

    public function testSm4DecryptTooShort(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $short = base64_encode('short-data-that-is-not-enough');
        $this->assertEquals($short, $encryptor->decrypt($short));
    }

    public function testIsEnabledTrue(): void
    {
        $encryptor = $this->createAesEncryptor(true);
        $this->assertTrue($encryptor->isEnabled());
    }

    public function testIsEnabledFalse(): void
    {
        $encryptor = $this->createAesEncryptor(false);
        $this->assertFalse($encryptor->isEnabled());
    }

    public function testIsSmModeTrue(): void
    {
        $encryptor = $this->createSm4Encryptor();
        $this->assertTrue($encryptor->isSmMode());
    }

    public function testIsSmModeFalse(): void
    {
        $encryptor = $this->createAesEncryptor();
        $this->assertFalse($encryptor->isSmMode());
    }

    public function testIsSmModeDefault(): void
    {
        $encryptor = new SaTokenEncryptor(true, 'key');
        $this->assertFalse($encryptor->isSmMode());
    }

    public function testAesEmptyString(): void
    {
        $encryptor = $this->createAesEncryptor();
        $encrypted = $encryptor->encrypt('');
        $this->assertEquals('', $encryptor->decrypt($encrypted));
    }

    public function testAesLongData(): void
    {
        $encryptor = $this->createAesEncryptor();
        $data = str_repeat('A', 10000);
        $encrypted = $encryptor->encrypt($data);
        $this->assertEquals($data, $encryptor->decrypt($encrypted));
    }

    public function testAesSpecialCharacters(): void
    {
        $encryptor = $this->createAesEncryptor();
        $data = "!@#\$%^&*()_+-=[]{}|;':\",./<>?\n\t\r";
        $encrypted = $encryptor->encrypt($data);
        $this->assertEquals($data, $encryptor->decrypt($encrypted));
    }

    public function testAesChineseCharacters(): void
    {
        $encryptor = $this->createAesEncryptor();
        $data = '你好世界こんにちは안녕하세요';
        $encrypted = $encryptor->encrypt($data);
        $this->assertEquals($data, $encryptor->decrypt($encrypted));
    }

    public function testAesUnicodeEmoji(): void
    {
        $encryptor = $this->createAesEncryptor();
        $data = '🎉🚀💻🔐';
        $encrypted = $encryptor->encrypt($data);
        $this->assertEquals($data, $encryptor->decrypt($encrypted));
    }

    public function testSm4EmptyString(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $encrypted = $encryptor->encrypt('');
        $this->assertEquals('', $encryptor->decrypt($encrypted));
    }

    public function testSm4LongData(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $data = str_repeat('A', 10000);
        $encrypted = $encryptor->encrypt($data);
        $this->assertEquals($data, $encryptor->decrypt($encrypted));
    }

    public function testSm4SpecialCharacters(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $data = "!@#\$%^&*()_+-=[]{}|;':\",./<>?\n\t\r";
        $encrypted = $encryptor->encrypt($data);
        $this->assertEquals($data, $encryptor->decrypt($encrypted));
    }

    public function testSm4ChineseCharacters(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $data = '你好世界こんにちは안녕하세요';
        $encrypted = $encryptor->encrypt($data);
        $this->assertEquals($data, $encryptor->decrypt($encrypted));
    }

    public function testSm4UnicodeEmoji(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $encryptor = $this->createSm4Encryptor();
        $data = '🎉🚀💻🔐';
        $encrypted = $encryptor->encrypt($data);
        $this->assertEquals($data, $encryptor->decrypt($encrypted));
    }

    public function testAesEncryptedCannotBeDecryptedBySm4(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $aes = $this->createAesEncryptor();
        $sm4 = $this->createSm4Encryptor();
        $encrypted = $aes->encrypt('cross-mode-test');
        $decrypted = $sm4->decrypt($encrypted);
        $this->assertNotEquals('cross-mode-test', $decrypted);
    }

    public function testSm4EncryptedCannotBeDecryptedByAes(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $aes = $this->createAesEncryptor();
        $sm4 = $this->createSm4Encryptor();
        $encrypted = $sm4->encrypt('cross-mode-test');
        $decrypted = $aes->decrypt($encrypted);
        $this->assertNotEquals('cross-mode-test', $decrypted);
    }

    public function testCrossModeAesReturnsRawDataOnSm4Decrypt(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $aes = $this->createAesEncryptor();
        $sm4 = $this->createSm4Encryptor();
        $encrypted = $aes->encrypt('cross-mode-test');
        $decrypted = $sm4->decrypt($encrypted);
        $this->assertEquals($encrypted, $decrypted);
    }

    public function testCrossModeSm4ReturnsRawDataOnAesDecrypt(): void
    {
        if (!class_exists(Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }
        $aes = $this->createAesEncryptor();
        $sm4 = $this->createSm4Encryptor();
        $encrypted = $sm4->encrypt('cross-mode-test');
        $decrypted = $aes->decrypt($encrypted);
        $this->assertEquals($encrypted, $decrypted);
    }
}
