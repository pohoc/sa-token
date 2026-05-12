<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Sso\SaSsoConfig;
use SaToken\Sso\SaSsoHandle;
use SaToken\Sso\SaSsoManager;

/**
 * SSO 模块测试
 *
 * 覆盖：URL 构建、配置、SaSsoManager 入口、ticket 校验逻辑
 */
class SaSsoTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
        ]));
        SaToken::setDao(new SaTokenDaoMemory());
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    // ======== SaSsoConfig 测试 ========

    public function testSsoConfigDefaults(): void
    {
        $config = new SaSsoConfig();
        $this->assertEquals('', $config->getLoginUrl());
        $this->assertEquals('', $config->getAuthUrl());
        $this->assertEquals('', $config->getBackUrl());
        $this->assertEquals('', $config->getCheckTicketUrl());
        $this->assertEquals('', $config->getSloUrl());
        $this->assertEquals('same-domain', $config->getMode());
        $this->assertEquals('', $config->getClientId());
        $this->assertEquals('', $config->getClientSecret());
    }

    public function testSsoConfigFromArray(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'       => 'https://auth.example.com/login',
            'authUrl'        => 'https://auth.example.com/auth',
            'backUrl'        => 'https://app.example.com/sso/callback',
            'checkTicketUrl' => 'https://auth.example.com/checkTicket',
            'sloUrl'         => 'https://auth.example.com/slo',
            'mode'           => 'cross-domain',
            'clientId'       => 'app-1',
            'clientSecret'   => 'secret-1',
        ]);

        $this->assertEquals('https://auth.example.com/login', $config->getLoginUrl());
        $this->assertEquals('https://auth.example.com/auth', $config->getAuthUrl());
        $this->assertEquals('https://app.example.com/sso/callback', $config->getBackUrl());
        $this->assertEquals('https://auth.example.com/checkTicket', $config->getCheckTicketUrl());
        $this->assertEquals('https://auth.example.com/slo', $config->getSloUrl());
        $this->assertEquals('cross-domain', $config->getMode());
        $this->assertEquals('app-1', $config->getClientId());
        $this->assertEquals('secret-1', $config->getClientSecret());
    }

    // ======== buildLoginUrl 测试 ========

    public function testBuildLoginUrlWithRedirect(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildLoginUrl('https://app.example.com/dashboard');

        $this->assertStringContainsString('https://auth.example.com/login', $url);
        $this->assertStringContainsString('redirect=', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testBuildLoginUrlWithoutRedirect(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'backUrl'      => 'https://app.example.com/callback',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildLoginUrl();

        $this->assertStringContainsString('redirect=', $url);
        $this->assertStringContainsString(rawurlencode('https://app.example.com/callback'), $url);
    }

    public function testBuildLoginUrlWithExistingQueryParams(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login?theme=dark',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildLoginUrl('https://app.example.com/home');

        $this->assertStringContainsString('&', $url);
        $this->assertStringContainsString('theme=dark', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testBuildLoginUrlWithoutClientId(): void
    {
        $config = new SaSsoConfig([
            'loginUrl'     => 'https://auth.example.com/login',
            'allowDomains' => ['app.example.com'],
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildLoginUrl('https://app.example.com/home');

        $this->assertStringNotContainsString('client_id', $url);
    }

    // ======== buildSloUrl 测试 ========

    public function testBuildSloUrlWithRedirect(): void
    {
        $config = new SaSsoConfig([
            'sloUrl'   => 'https://auth.example.com/slo',
            'clientId' => 'app-1',
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildSloUrl('https://app.example.com/home');

        $this->assertStringContainsString('https://auth.example.com/slo', $url);
        $this->assertStringContainsString('redirect=', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testBuildSloUrlWithoutRedirect(): void
    {
        $config = new SaSsoConfig([
            'sloUrl'   => 'https://auth.example.com/slo',
            'clientId' => 'app-1',
        ]);

        $handle = new SaSsoHandle($config);
        $url = $handle->buildSloUrl();

        $this->assertStringNotContainsString('redirect=', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    // ======== doLoginCallback 错误场景 ========

    public function testDoLoginCallbackWithEmptyTicket(): void
    {
        $config = new SaSsoConfig([
            'checkTicketUrl' => 'https://auth.example.com/checkTicket',
        ]);

        $handle = new SaSsoHandle($config);
        $this->expectException(SaTokenException::class);
        $this->expectExceptionMessage('SSO ticket 不能为空');
        $handle->doLoginCallback('');
    }

    public function testDoLoginCallbackWithMissingCheckTicketUrl(): void
    {
        $config = new SaSsoConfig();
        $handle = new SaSsoHandle($config);

        // 内部会抛出 checkTicketUrl 未配置异常
        try {
            $handle->doLoginCallback('some-ticket');
            $this->fail('Expected SaTokenException');
        } catch (SaTokenException $e) {
            // 网络请求可能失败，但校验地址未配置也会触发
            $this->assertTrue(true);
        }
    }

    // ======== getConfig ========

    public function testHandleGetConfig(): void
    {
        $config = new SaSsoConfig(['loginUrl' => 'https://auth.example.com/login']);
        $handle = new SaSsoHandle($config);
        $this->assertSame($config, $handle->getConfig());
    }

    // ======== SaSsoManager 测试 ========

    public function testManagerWithArrayConfig(): void
    {
        $manager = new SaSsoManager([
            'loginUrl' => 'https://auth.example.com/login',
            'mode'     => 'cross-domain',
        ]);

        $this->assertEquals('https://auth.example.com/login', $manager->getConfig()->getLoginUrl());
        $this->assertEquals('cross-domain', $manager->getConfig()->getMode());
        $this->assertNotNull($manager->getHandle());
    }

    public function testManagerWithConfigObject(): void
    {
        $config = new SaSsoConfig(['loginUrl' => 'https://auth.example.com/login']);
        $manager = new SaSsoManager($config);
        $this->assertSame($config, $manager->getConfig());
    }

    public function testManagerBuildLoginUrl(): void
    {
        $manager = new SaSsoManager([
            'loginUrl'     => 'https://auth.example.com/login',
            'clientId'     => 'app-1',
            'allowDomains' => ['app.example.com'],
        ]);

        $url = $manager->buildLoginUrl('https://app.example.com/home');
        $this->assertStringContainsString('https://auth.example.com/login', $url);
        $this->assertStringContainsString('client_id=app-1', $url);
    }

    public function testManagerBuildSloUrl(): void
    {
        $manager = new SaSsoManager([
            'sloUrl'   => 'https://auth.example.com/slo',
            'clientId' => 'app-1',
        ]);

        $url = $manager->buildSloUrl();
        $this->assertStringContainsString('https://auth.example.com/slo', $url);
    }
}
