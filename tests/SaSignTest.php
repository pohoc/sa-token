<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Sign\SaSign;

class SaSignTest extends TestCase
{
    protected SaSign $sign;

    protected function setUp(): void
    {
        $signKey = getenv('TEST_SIGN_KEY') ?: 'test-key-placeholder-32-bytes-lo';
        $this->sign = new SaSign(['key' => $signKey]);
    }

    public function testSignParamsAddsTimestampNonceAndSign(): void
    {
        $params = $this->sign->signParams(['foo' => 'bar']);

        $this->assertArrayHasKey('timestamp', $params);
        $this->assertArrayHasKey('nonce', $params);
        $this->assertArrayHasKey('sign', $params);
        $this->assertEquals('bar', $params['foo']);
    }

    public function testSignParamsPreservesExistingTimestamp(): void
    {
        $ts = '1700000000';
        $params = $this->sign->signParams(['foo' => 'bar', 'timestamp' => $ts]);

        $this->assertEquals($ts, $params['timestamp']);
    }

    public function testVerifySignReturnsTrueForValidSign(): void
    {
        $params = $this->sign->signParams(['foo' => 'bar']);

        $this->assertTrue($this->sign->verifySign($params));
    }

    public function testVerifySignReturnsFalseForMissingSign(): void
    {
        $this->assertFalse($this->sign->verifySign(['foo' => 'bar']));
    }

    public function testVerifySignReturnsFalseForTamperedValue(): void
    {
        $params = $this->sign->signParams(['foo' => 'bar']);
        $params['foo'] = 'baz';

        $this->assertFalse($this->sign->verifySign($params));
    }

    public function testVerifySignReturnsFalseForExpiredTimestamp(): void
    {
        $signKey = getenv('TEST_SIGN_KEY') ?: 'test-key-placeholder-32-bytes-lo';
        $sign = new SaSign(['key' => $signKey, 'timestampGap' => 100]);
        $params = $sign->signParams(['foo' => 'bar', 'timestamp' => (string) (time() - 1000)]);

        $this->assertFalse($sign->verifySign($params));
    }

    public function testVerifySignWithNonceValidator(): void
    {
        $this->sign->setNonceValidator(fn (string $nonce) => false);
        $params = $this->sign->signParams(['foo' => 'bar']);

        $this->assertFalse($this->sign->verifySign($params));
    }

    public function testVerifySignWithNonceValidatorAccepts(): void
    {
        $this->sign->setNonceValidator(fn (string $nonce) => true);
        $params = $this->sign->signParams(['foo' => 'bar']);

        $this->assertTrue($this->sign->verifySign($params));
    }

    public function testSha256Algorithm(): void
    {
        $this->sign->setSignAlg('sha256');
        $params = $this->sign->signParams(['foo' => 'bar']);

        $this->assertTrue($this->sign->verifySign($params));
    }

    public function testEmptyValuesSkipped(): void
    {
        $params = $this->sign->signParams(['foo' => 'bar', 'empty' => '', 'nil' => 'null']);

        $this->assertTrue($this->sign->verifySign($params));
    }

    public function testKeyUsedInSign(): void
    {
        $sign1 = new SaSign(['key' => 'key-a']);
        $sign2 = new SaSign(['key' => 'key-b']);

        $params1 = $sign1->signParams(['foo' => 'bar']);
        $params2 = $sign2->signParams(['foo' => 'bar', 'timestamp' => $params1['timestamp'], 'nonce' => $params1['nonce']]);

        $this->assertNotEquals($params1['sign'], $params2['sign']);
    }
}
