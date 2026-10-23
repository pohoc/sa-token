<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Exception\SaTokenException;

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

    public function testTokenTimeoutMustBePositiveOrExplicitlyPermanent(): void
    {
        foreach ([0, -2] as $timeout) {
            try {
                (new SaTokenConfig())->setTimeout($timeout);
                $this->fail('仅 -1 可表示永不过期');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('有效期', $e->getMessage());
            }
        }
    }

    public function testActivityTimeoutMustBePositiveOrExplicitlyUnlimited(): void
    {
        foreach ([0, -2] as $timeout) {
            try {
                (new SaTokenConfig())->setActivityTimeout($timeout);
                $this->fail('仅 -1 可表示不限制活动超时');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('活动超时', $e->getMessage());
            }
        }
    }

    public function testMaxLoginCountMustBePositiveOrExplicitlyUnlimited(): void
    {
        foreach ([0, -2] as $count) {
            try {
                (new SaTokenConfig())->setMaxLoginCount($count);
                $this->fail('仅 -1 可表示不限制登录数');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('最大登录数', $e->getMessage());
            }
        }
    }

    public function testRefreshTokenTimeoutMustBePositiveOrExplicitlyPermanent(): void
    {
        foreach ([0, -2, PHP_INT_MAX] as $timeout) {
            try {
                (new SaTokenConfig())->setRefreshTokenTimeout($timeout);
                $this->fail('Refresh Token 有效期必须为正数或 -1');
            } catch (SaTokenException $e) {
                $this->assertStringContainsString('有效期', $e->getMessage());
            }
        }

        $config = new SaTokenConfig(['refreshTokenTimeout' => -1]);
        $this->assertSame(-1, $config->getRefreshTokenTimeout());
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

    public function testPublishedConfigKeepsSecureCookieDefaults(): void
    {
        $publishedConfig = require dirname(__DIR__) . '/config/sa_token.php';
        if (!is_array($publishedConfig)) {
            $this->fail('Published config must return an array.');
        }
        $configData = [];
        foreach ($publishedConfig as $key => $value) {
            if (!is_string($key)) {
                $this->fail('Published config keys must be strings.');
            }
            $configData[$key] = $value;
        }
        $config = new SaTokenConfig($configData);

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
