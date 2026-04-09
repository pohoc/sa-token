<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;

class SaTokenConfigTest extends TestCase
{
    public function testDefaultConfig(): void
    {
        $config = new SaTokenConfig();

        $this->assertEquals('satoken', $config->getTokenName());
        $this->assertEquals(86400, $config->getTimeout());
        $this->assertEquals(-1, $config->getActivityTimeout());
        $this->assertTrue($config->isConcurrent());
        $this->assertTrue($config->isShare());
        $this->assertEquals(12, $config->getMaxLoginCount());
        $this->assertTrue($config->isReadHeader());
        $this->assertTrue($config->isReadCookie());
        $this->assertFalse($config->isReadBody());
        $this->assertTrue($config->isWriteCookie());
        $this->assertFalse($config->isWriteHeader());
        $this->assertEquals('intl', $config->getCryptoType());
    }

    public function testArrayInit(): void
    {
        $config = new SaTokenConfig([
            'tokenName'    => 'my-token',
            'timeout'      => 7200,
            'isReadCookie' => false,
            'cryptoType'   => 'sm',
        ]);

        $this->assertEquals('my-token', $config->getTokenName());
        $this->assertEquals(7200, $config->getTimeout());
        $this->assertFalse($config->isReadCookie());
        $this->assertEquals('sm', $config->getCryptoType());
    }

    public function testChainSetting(): void
    {
        $config = new SaTokenConfig();
        $config->setTokenName('chain-token')
            ->setTimeout(3600)
            ->setIsReadHeader(false);

        $this->assertEquals('chain-token', $config->getTokenName());
        $this->assertEquals(3600, $config->getTimeout());
        $this->assertFalse($config->isReadHeader());
    }

    public function testToArray(): void
    {
        $config = new SaTokenConfig(['tokenName' => 'test']);
        $array = $config->toArray();

        $this->assertArrayHasKey('tokenName', $array);
        $this->assertArrayHasKey('timeout', $array);
        $this->assertArrayHasKey('isReadHeader', $array);
        $this->assertArrayHasKey('cookieDomain', $array);
        $this->assertArrayHasKey('sso', $array);
        $this->assertArrayHasKey('oauth2', $array);
        $this->assertEquals('test', $array['tokenName']);
    }

    public function testCookieConfig(): void
    {
        $config = new SaTokenConfig([
            'cookieDomain'   => '.example.com',
            'cookiePath'     => '/api',
            'cookieSecure'   => true,
            'cookieHttpOnly' => true,
            'cookieSameSite' => 'Strict',
        ]);

        $this->assertEquals('.example.com', $config->getCookieDomain());
        $this->assertEquals('/api', $config->getCookiePath());
        $this->assertTrue($config->isCookieSecure());
        $this->assertTrue($config->isCookieHttpOnly());
        $this->assertEquals('Strict', $config->getCookieSameSite());
    }

    public function testSsoConfig(): void
    {
        $config = new SaTokenConfig([
            'sso' => [
                'loginUrl' => 'https://auth.example.com/login',
                'mode'     => 'cross-domain',
            ],
        ]);

        $this->assertEquals('https://auth.example.com/login', $config->getSso()['loginUrl']);
        $this->assertEquals('cross-domain', $config->getSso()['mode']);
    }

    public function testOauth2Config(): void
    {
        $config = new SaTokenConfig([
            'oauth2' => [
                'grantTypes' => ['authorization_code', 'password'],
                'codeTimeout' => 120,
            ],
        ]);

        $this->assertEquals(['authorization_code', 'password'], $config->getOauth2()['grantTypes']);
        $this->assertEquals(120, $config->getOauth2()['codeTimeout']);
    }
}
