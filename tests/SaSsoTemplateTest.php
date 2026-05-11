<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\Sso\SaSsoTemplate;

class SaSsoTemplateTest extends TestCase
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

    public function testSignParamsWithIntlMode(): void
    {
        $template = new SaSsoTemplate('intl');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = 'my-client-secret';

        $signed = $template->signParams($params, $clientSecret);

        $this->assertArrayHasKey('sign', $signed);
        $this->assertEquals(64, strlen($signed['sign']));
    }

    public function testSignParamsWithSmMode(): void
    {
        if (!class_exists(\CryptoSm\SM3\Sm3::class)) {
            $this->markTestSkipped('CryptoSm SM3 extension not available');
        }

        $template = new SaSsoTemplate('sm');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = 'my-client-secret';

        $signed = $template->signParams($params, $clientSecret);

        $this->assertArrayHasKey('sign', $signed);
        $this->assertEquals(64, strlen($signed['sign']));
    }

    public function testVerifySignWithIntlMode(): void
    {
        $template = new SaSsoTemplate('intl');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = 'my-client-secret';

        $signed = $template->signParams($params, $clientSecret);
        $result = $template->verifySign($signed, $clientSecret);

        $this->assertTrue($result);
    }

    public function testVerifySignWithSmMode(): void
    {
        if (!class_exists(\CryptoSm\SM3\Sm3::class)) {
            $this->markTestSkipped('CryptoSm SM3 extension not available');
        }

        $template = new SaSsoTemplate('sm');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = 'my-client-secret';

        $signed = $template->signParams($params, $clientSecret);
        $result = $template->verifySign($signed, $clientSecret);

        $this->assertTrue($result);
    }

    public function testVerifySignWithTamperedDataReturnsFalse(): void
    {
        $template = new SaSsoTemplate('intl');
        $params = ['appId' => 'app-1', 'timestamp' => '1700000000', 'nonce' => 'abc123'];
        $clientSecret = 'my-client-secret';

        $signed = $template->signParams($params, $clientSecret);
        $signed['appId'] = 'tampered-app';

        $result = $template->verifySign($signed, $clientSecret);

        $this->assertFalse($result);
    }
}
