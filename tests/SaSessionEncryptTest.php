<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaSession;
use SaToken\SaToken;

class SaSessionEncryptTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig());
        SaToken::setDao(new SaTokenDaoMemory());
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testSessionWithTimeoutPersistsAfterReload(): void
    {
        $session = new SaSession('encrypt-session-1', false, 3600);
        $session->set('user', 'alice');
        $session->set('role', 'admin');

        $loaded = SaSession::getBySessionId('encrypt-session-1');
        $this->assertNotNull($loaded);
        $this->assertEquals('alice', $loaded->get('user'));
        $this->assertEquals('admin', $loaded->get('role'));
    }

    public function testTokenEncryptEncryptsDataInDao(): void
    {
        $encryptKey = getenv('TEST_ENCRYPT_KEY_SESSION') ?: 'test-key-placeholder-32-bytes-lo';
        $config = new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => $encryptKey,
        ]);
        SaToken::setConfig($config);

        $dao = new SaTokenDaoMemory();
        SaToken::setDao($dao);

        $session = new SaSession('encrypt-session-2');
        $session->set('secret', 'hidden-value');

        $raw = $dao->get('encrypt-session-2');
        $this->assertNotNull($raw);
        $this->assertStringNotContainsString('"secret"', $raw);
        $this->assertStringNotContainsString('hidden-value', $raw);
    }

    public function testEncryptedSessionCanBeReadBack(): void
    {
        $encryptKey = getenv('TEST_ENCRYPT_KEY_SESSION') ?: 'test-key-placeholder-32-bytes-lo';
        $config = new SaTokenConfig([
            'tokenEncrypt' => true,
            'tokenEncryptKey' => $encryptKey,
        ]);
        SaToken::setConfig($config);

        $dao = new SaTokenDaoMemory();
        SaToken::setDao($dao);

        $session = new SaSession('encrypt-session-3');
        $session->set('name', 'bob');
        $session->set('level', 42);

        $loaded = SaSession::getBySessionId('encrypt-session-3');
        $this->assertNotNull($loaded);
        $this->assertEquals('bob', $loaded->get('name'));
        $this->assertEquals(42, $loaded->get('level'));
    }

    public function testSessionWithTokenEncryptAndSmCryptoType(): void
    {
        if (!class_exists(\CryptoSm\SM4\Sm4::class)) {
            $this->markTestSkipped('CryptoSm SM4 extension not available');
        }

        $encryptKey = getenv('TEST_SM4_ENCRYPT_KEY') ?: 'test-key-placeholder-32-bytes-lo';
        $config = new SaTokenConfig([
            'tokenEncrypt' => true,
            'cryptoType' => 'sm',
            'tokenEncryptKey' => $encryptKey,
        ]);
        SaToken::setConfig($config);

        $dao = new SaTokenDaoMemory();
        SaToken::setDao($dao);

        $session = new SaSession('encrypt-session-sm-1');
        $session->set('data', 'sm-encrypted-value');

        $raw = $dao->get('encrypt-session-sm-1');
        $this->assertNotNull($raw);
        $this->assertStringNotContainsString('sm-encrypted-value', $raw);

        $loaded = SaSession::getBySessionId('encrypt-session-sm-1');
        $this->assertNotNull($loaded);
        $this->assertEquals('sm-encrypted-value', $loaded->get('data'));
    }
}
