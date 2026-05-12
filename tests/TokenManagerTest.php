<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\TokenManager;
use SaToken\Util\SaTokenEncryptor;

class TokenManagerTest extends TestCase
{
    protected TokenManager $manager;
    protected SaTokenDaoMemory $dao;

    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'tokenStyle'      => 'uuid',
        ]));
        $this->dao = new SaTokenDaoMemory();
        SaToken::setDao($this->dao);

        $this->manager = new TokenManager();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testCreateTokenValue(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->assertNotEmpty($token);
        $this->assertEquals(36, strlen($token)); // UUID v4 长度
    }

    public function testCreateSimpleRandomToken(): void
    {
        SaToken::getConfig()->setTokenStyle('simple-random');
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->assertNotEmpty($token);
        $this->assertEquals(32, strlen($token));
    }

    public function testSaveAndGetToken(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $loginId = $this->manager->getLoginIdByToken($token);
        $this->assertEquals('10001', $loginId);
    }

    public function testDeleteToken(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $this->manager->deleteToken($token, 10001, 'login');
        $this->assertNull($this->manager->getLoginIdByToken($token));
    }

    public function testDeleteAllTokenByLoginId(): void
    {
        $token1 = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token1, 10001, 'login', 'PC');

        $token2 = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token2, 10001, 'login', 'APP');

        $deleted = $this->manager->deleteAllTokenByLoginId(10001, 'login');
        $this->assertCount(2, $deleted);

        $this->assertNull($this->manager->getLoginIdByToken($token1));
        $this->assertNull($this->manager->getLoginIdByToken($token2));
    }

    public function testTokenTimeout(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $timeout = $this->manager->getTokenTimeout($token);
        $this->assertGreaterThan(0, $timeout);
        $this->assertLessThanOrEqual(3600, $timeout);
    }

    public function testRenewTimeout(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $this->manager->renewTimeout($token, 7200);
        $timeout = $this->manager->getTokenTimeout($token);
        $this->assertGreaterThan(3600, $timeout);
    }

    public function testIsTokenValid(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->assertFalse($this->manager->isTokenValid($token));

        $this->manager->saveToken($token, 10001, 'login', 'PC');
        $this->assertTrue($this->manager->isTokenValid($token));
    }

    public function testDisable(): void
    {
        $this->manager->disable(10001, 'comment', 1, 3600, 'login');
        $this->assertTrue($this->manager->isDisable(10001, 'comment', 'login'));
        $this->assertEquals(1, $this->manager->getDisableLevel(10001, 'comment', 'login'));
    }

    public function testUntieDisable(): void
    {
        $this->manager->disable(10001, 'comment', 1, 3600, 'login');
        $this->manager->untieDisable(10001, 'comment', 'login');
        $this->assertFalse($this->manager->isDisable(10001, 'comment', 'login'));
    }

    public function testSafeAuth(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        $this->assertFalse($this->manager->isSafe($token, 'transfer', 'login'));

        $this->manager->openSafe($token, 'transfer', 120, 'login');
        $this->assertTrue($this->manager->isSafe($token, 'transfer', 'login'));

        $this->manager->closeSafe($token, 'transfer', 'login');
        $this->assertFalse($this->manager->isSafe($token, 'transfer', 'login'));
    }

    public function testSwitchTo(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC');

        $this->assertNull($this->manager->getSwitchTo($token, 'login'));

        $this->manager->setSwitchTo($token, 20001, 'login');
        $this->assertEquals('20001', $this->manager->getSwitchTo($token, 'login'));

        $this->manager->clearSwitch($token, 'login');
        $this->assertNull($this->manager->getSwitchTo($token, 'login'));
    }

    public function testTokenEncryptDisabledByDefault(): void
    {
        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $rawValue = $this->dao->get('satoken:login:token:' . $token);
        $this->assertEquals('10001', $rawValue);
    }

    public function testTokenEncryptEnabled(): void
    {
        $encryptKey = getenv('TEST_ENCRYPT_KEY') ?: 'test-key-placeholder-32-bytes-lo';
        SaToken::getConfig()->setTokenEncrypt(true)->setTokenEncryptKey($encryptKey);
        $this->manager->resetEncryptor();

        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $rawValue = $this->dao->get('satoken:login:token:' . $token);
        $this->assertNotEquals('10001', $rawValue);
        $this->assertNotEquals('', $rawValue);

        $loginId = $this->manager->getLoginIdByToken($token);
        $this->assertEquals('10001', $loginId);
    }

    public function testTokenEncryptPreservesAllOperations(): void
    {
        $aesKey = getenv('TEST_AES_KEY_FOR_TOKEN') ?: 'test-key-placeholder-32-bytes-lo';
        SaToken::getConfig()->setTokenEncrypt(true)->setAesKey($aesKey);
        $this->manager->resetEncryptor();

        $token = $this->manager->createTokenValue(10001, 'login');
        $this->manager->saveToken($token, 10001, 'login', 'PC', 3600);

        $this->assertTrue($this->manager->isTokenValid($token));
        $this->assertEquals('10001', $this->manager->getLoginIdByToken($token));

        $tokens = $this->manager->getTokenListByLoginId(10001, 'login');
        $this->assertCount(1, $tokens);
        $this->assertEquals($token, $tokens[0]['tokenValue']);

        $this->manager->setSwitchTo($token, 20001, 'login');
        $this->assertEquals('20001', $this->manager->getSwitchTo($token, 'login'));

        $this->manager->openSafe($token, 'transfer', 120, 'login');
        $this->assertTrue($this->manager->isSafe($token, 'transfer', 'login'));

        $this->manager->disable(10001, 'comment', 2, 3600, 'login');
        $this->assertTrue($this->manager->isDisable(10001, 'comment', 'login'));
        $this->assertEquals(2, $this->manager->getDisableLevel(10001, 'comment', 'login'));

        $this->manager->deleteToken($token, 10001, 'login');
        $this->assertNull($this->manager->getLoginIdByToken($token));
    }

    public function testEncryptorDecryptRoundTrip(): void
    {
        $encryptor = new SaTokenEncryptor(true, 'test-key');
        $original = 'sensitive-login-id-10001';
        $encrypted = $encryptor->encrypt($original);
        $this->assertNotEquals($original, $encrypted);
        $decrypted = $encryptor->decrypt($encrypted);
        $this->assertEquals($original, $decrypted);
    }

    public function testEncryptorDisabledPassthrough(): void
    {
        $encryptor = new SaTokenEncryptor(false, 'test-key');
        $original = 'plain-value';
        $result = $encryptor->encrypt($original);
        $this->assertEquals($original, $result);
        $result = $encryptor->decrypt($original);
        $this->assertEquals($original, $result);
    }

    public function testEncryptorTamperDetection(): void
    {
        $encryptor = new SaTokenEncryptor(true, 'test-key');
        $original = 'secret-data';
        $encrypted = $encryptor->encrypt($original);

        $tampered = substr($encrypted, 0, -4) . base64_encode('XXXX');
        $result = $encryptor->decrypt($tampered);
        $this->assertEquals($tampered, $result);
    }
}
