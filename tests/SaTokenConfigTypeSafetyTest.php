<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\SaToken;

class SaTokenConfigTypeSafetyTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testInitFromArrayWithValidKeysGoesThroughSetters(): void
    {
        $config = new SaTokenConfig();
        $config->initFromArray([
            'tokenName' => 'custom-token',
            'timeout' => 7200,
            'cryptoType' => 'sm',
        ]);

        $this->assertEquals('custom-token', $config->getTokenName());
        $this->assertEquals(7200, $config->getTimeout());
        $this->assertEquals('sm', $config->getCryptoType());
    }

    public function testInitFromArrayWithUnknownKeysIsSilentlyIgnored(): void
    {
        $config = new SaTokenConfig();
        $config->initFromArray([
            'nonexistentProperty' => 'should-be-ignored',
            'fakeKey' => 12345,
            'tokenName' => 'valid-name',
        ]);

        $this->assertEquals('valid-name', $config->getTokenName());
    }

    public function testTokenEncryptGetterAndSetter(): void
    {
        $config = new SaTokenConfig();
        $this->assertFalse($config->isTokenEncrypt());

        $config->setTokenEncrypt(true);
        $this->assertTrue($config->isTokenEncrypt());

        $config->setTokenEncrypt(false);
        $this->assertFalse($config->isTokenEncrypt());
    }

    public function testTokenEncryptKeyGetterAndSetter(): void
    {
        $config = new SaTokenConfig();
        $this->assertEquals('', $config->getTokenEncryptKey());

        $config->setTokenEncryptKey('my-encrypt-key');
        $this->assertEquals('my-encrypt-key', $config->getTokenEncryptKey());
    }

    public function testCryptoTypeWithIntl(): void
    {
        $config = new SaTokenConfig();
        $config->setCryptoType('intl');
        $this->assertEquals('intl', $config->getCryptoType());
    }

    public function testCryptoTypeWithSm(): void
    {
        $config = new SaTokenConfig();
        $config->setCryptoType('sm');
        $this->assertEquals('sm', $config->getCryptoType());
    }

    public function testToArrayIncludesTokenEncrypt(): void
    {
        $config = new SaTokenConfig(['tokenEncrypt' => true]);
        $array = $config->toArray();

        $this->assertArrayHasKey('tokenEncrypt', $array);
        $this->assertTrue($array['tokenEncrypt']);
    }

    public function testToArrayIncludesTokenEncryptKey(): void
    {
        $config = new SaTokenConfig(['tokenEncryptKey' => 'secret-key']);
        $array = $config->toArray();

        $this->assertArrayHasKey('tokenEncryptKey', $array);
        $this->assertEquals('secret-key', $array['tokenEncryptKey']);
    }
}
