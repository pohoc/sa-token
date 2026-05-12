<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfigBuilder;
use SaToken\SaToken;

/**
 * SaTokenConfigBuilder 测试
 */
class ConfigBuilderTest extends TestCase
{
    public function testBuilderBasics(): void
    {
        $config = SaTokenConfigBuilder::create()
            ->tokenName('my-token')
            ->timeout(7200)
            ->tokenStyle('simple-random')
            ->concurrent(true)
            ->maxLoginCount(5)
            ->build();

        $this->assertSame('my-token', $config->getTokenName());
        $this->assertSame(7200, $config->getTimeout());
        $this->assertSame('simple-random', $config->getTokenStyle());
        $this->assertTrue($config->isConcurrent());
        $this->assertSame(5, $config->getMaxLoginCount());
    }

    public function testCookieConfig(): void
    {
        $config = SaTokenConfigBuilder::create()
            ->cookieDomain('.example.com')
            ->cookiePath('/api')
            ->cookieSecure(true)
            ->cookieHttpOnly(true)
            ->cookieSameSite('Strict')
            ->build();

        $this->assertSame('.example.com', $config->getCookieDomain());
        $this->assertSame('/api', $config->getCookiePath());
        $this->assertTrue($config->isCookieSecure());
        $this->assertTrue($config->isCookieHttpOnly());
        $this->assertSame('Strict', $config->getCookieSameSite());
    }

    public function testSecurityConfig(): void
    {
        $config = SaTokenConfigBuilder::create()
            ->aesKey('test-aes-key-32-bytes-long!')
            ->signKey('test-sign-key')
            ->signAlg('sha256')
            ->tokenEncrypt(true)
            ->tokenFingerprint(true)
            ->build();

        $this->assertSame('test-aes-key-32-bytes-long!', $config->getAesKey());
        $this->assertSame('test-sign-key', $config->getSignKey());
        $this->assertSame('sha256', $config->getSignAlg());
        $this->assertTrue($config->isTokenEncrypt());
        $this->assertTrue($config->isTokenFingerprint());
    }

    public function testJwtConfig(): void
    {
        $config = SaTokenConfigBuilder::create()
            ->jwtSecretKey('jwt-secret')
            ->jwtStateless(true)
            ->jwtMode('mixed')
            ->build();

        $this->assertSame('jwt-secret', $config->getJwtSecretKey());
        $this->assertTrue($config->isJwtStateless());
        $this->assertSame('mixed', $config->getJwtMode());
    }

    public function testAntiBruteConfig(): void
    {
        $config = SaTokenConfigBuilder::create()
            ->antiBruteMaxFailures(10)
            ->antiBruteLockDuration(1200)
            ->build();

        $this->assertSame(10, $config->getAntiBruteMaxFailures());
        $this->assertSame(1200, $config->getAntiBruteLockDuration());
    }

    public function testRefreshTokenConfig(): void
    {
        $config = SaTokenConfigBuilder::create()
            ->refreshToken(true)
            ->refreshTokenTimeout(604800)
            ->refreshTokenRotation(true)
            ->build();

        $this->assertTrue($config->isRefreshToken());
        $this->assertSame(604800, $config->getRefreshTokenTimeout());
        $this->assertTrue($config->isRefreshTokenRotation());
    }

    public function testIntegrationWithSaToken(): void
    {
        $config = SaTokenConfigBuilder::create()
            ->tokenName('builder-test-token')
            ->timeout(3600)
            ->build();

        SaToken::reset();
        SaToken::setConfig($config);

        $this->assertSame('builder-test-token', SaToken::getConfig()->getTokenName());
        $this->assertSame(3600, SaToken::getConfig()->getTimeout());
    }
}
