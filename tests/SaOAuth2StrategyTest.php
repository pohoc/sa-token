<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\SaOAuth2Config;
use SaToken\OAuth2\SaOAuth2Handle;
use SaToken\OAuth2\Strategy\AuthorizationCodeStrategy;
use SaToken\OAuth2\Strategy\ClientCredentialsStrategy;
use SaToken\OAuth2\Strategy\PasswordStrategy;
use SaToken\OAuth2\Strategy\RefreshTokenStrategy;

class SaOAuth2StrategyTest extends TestCase
{
    protected SaOAuth2Handle $handle;

    protected function setUp(): void
    {
        $config = new SaOAuth2Config();
        $this->handle = new SaOAuth2Handle($config);

        // 注册测试客户端
        $this->handle->registerClient(new SaOAuth2Client([
            'clientId' => 'test-client',
            'clientSecret' => 'test-secret',
            'redirectUris' => ['http://localhost/callback'],
            'grantTypes' => ['authorization_code', 'password', 'client_credentials', 'refresh_token'],
            'scopes' => ['read', 'write'],
        ]));
    }

    public function testAuthorizationCodeStrategy(): void
    {
        $strategy = new AuthorizationCodeStrategy($this->handle);

        $this->assertEquals('authorization_code', $strategy->getGrantType());

        // 测试验证请求参数
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $strategy->validateRequest(['client_id' => 'test-client']);
    }

    public function testPasswordStrategy(): void
    {
        $strategy = new PasswordStrategy($this->handle);

        $this->assertEquals('password', $strategy->getGrantType());

        // 测试验证请求参数
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $strategy->validateRequest(['client_id' => 'test-client']);
    }

    public function testClientCredentialsStrategy(): void
    {
        $strategy = new ClientCredentialsStrategy($this->handle);

        $this->assertEquals('client_credentials', $strategy->getGrantType());

        // 测试验证请求参数
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $strategy->validateRequest(['client_id' => 'test-client']);
    }

    public function testRefreshTokenStrategy(): void
    {
        $strategy = new RefreshTokenStrategy($this->handle);

        $this->assertEquals('refresh_token', $strategy->getGrantType());

        // 测试验证请求参数
        $this->expectException(\SaToken\Exception\SaTokenException::class);
        $strategy->validateRequest(['client_id' => 'test-client']);
    }

    public function testStrategyIntegration(): void
    {
        // 测试完整的授权码流程
        $authCodeStrategy = new AuthorizationCodeStrategy($this->handle);

        // 生成授权码
        $code = $authCodeStrategy->generateAuthorizationCode(
            'test-client',
            1001,
            'http://localhost/callback',
            'read write'
        );

        $this->assertNotNull($code->getCode());
        $this->assertEquals('test-client', $code->getClientId());
        $this->assertEquals(1001, $code->getLoginId());
    }
}
