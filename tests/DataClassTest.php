<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\SaLoginParameter;
use SaToken\SaTerminalInfo;
use SaToken\SaTokenInfo;

class DataClassTest extends TestCase
{
    // ---- SaTokenInfo ----

    public function testSaTokenInfoDefaults(): void
    {
        $info = new SaTokenInfo();
        $this->assertEquals('', $info->getTokenName());
        $this->assertEquals('', $info->getTokenValue());
        $this->assertNull($info->getLoginId());
        $this->assertEquals('', $info->getLoginType());
        $this->assertEquals(0, $info->getCreateTime());
        $this->assertEquals(-1, $info->getTimeout());
        $this->assertEquals(-1, $info->getActivityTimeout());
        $this->assertEquals('', $info->getDeviceType());
        $this->assertFalse($info->isTokenSession());
    }

    public function testSaTokenInfoArrayInit(): void
    {
        $info = new SaTokenInfo([
            'tokenName'       => 'satoken',
            'tokenValue'      => 'abc-123',
            'loginId'         => 10001,
            'loginType'       => 'login',
            'timeout'         => 7200,
            'activityTimeout' => 1800,
        ]);
        $this->assertEquals('satoken', $info->getTokenName());
        $this->assertEquals('abc-123', $info->getTokenValue());
        $this->assertEquals(10001, $info->getLoginId());
        $this->assertEquals('login', $info->getLoginType());
        $this->assertEquals(7200, $info->getTimeout());
        $this->assertEquals(1800, $info->getActivityTimeout());
    }

    public function testSaTokenInfoChainSetting(): void
    {
        $info = (new SaTokenInfo())
            ->setTokenName('my-token')
            ->setTokenValue('xxx')
            ->setLoginId(20001)
            ->setLoginType('admin')
            ->setCreateTime(1000000)
            ->setTimeout(3600)
            ->setActivityTimeout(600)
            ->setDeviceType('PC')
            ->setTokenSession(true);

        $this->assertEquals('my-token', $info->getTokenName());
        $this->assertEquals('xxx', $info->getTokenValue());
        $this->assertEquals(20001, $info->getLoginId());
        $this->assertEquals('admin', $info->getLoginType());
        $this->assertEquals(1000000, $info->getCreateTime());
        $this->assertEquals(3600, $info->getTimeout());
        $this->assertEquals(600, $info->getActivityTimeout());
        $this->assertEquals('PC', $info->getDeviceType());
        $this->assertTrue($info->isTokenSession());
    }

    public function testSaTokenInfoToArray(): void
    {
        $info = new SaTokenInfo(['tokenName' => 'test', 'loginId' => 100]);
        $arr = $info->toArray();

        $this->assertArrayHasKey('tokenName', $arr);
        $this->assertArrayHasKey('tokenValue', $arr);
        $this->assertArrayHasKey('loginId', $arr);
        $this->assertArrayHasKey('loginType', $arr);
        $this->assertArrayHasKey('createTime', $arr);
        $this->assertArrayHasKey('timeout', $arr);
        $this->assertArrayHasKey('activityTimeout', $arr);
        $this->assertArrayHasKey('deviceType', $arr);
        $this->assertArrayHasKey('tokenSession', $arr);
        $this->assertEquals('test', $arr['tokenName']);
        $this->assertEquals(100, $arr['loginId']);
    }

    // ---- SaLoginParameter ----

    public function testSaLoginParameterDefaults(): void
    {
        $param = new SaLoginParameter();
        $this->assertEquals('', $param->getDeviceType());
        $this->assertTrue($param->isLastingCookie());
        $this->assertNull($param->getTimeout());
        $this->assertNull($param->getIsShare());
        $this->assertNull($param->getMaxLoginCount());
    }

    public function testSaLoginParameterChainSetting(): void
    {
        $param = (new SaLoginParameter())
            ->setDeviceType('APP')
            ->setIsLastingCookie(false)
            ->setTimeout(1800)
            ->setIsShare(false)
            ->setMaxLoginCount(3);

        $this->assertEquals('APP', $param->getDeviceType());
        $this->assertFalse($param->isLastingCookie());
        $this->assertEquals(1800, $param->getTimeout());
        $this->assertFalse($param->getIsShare());
        $this->assertEquals(3, $param->getMaxLoginCount());
    }

    // ---- SaTerminalInfo ----

    public function testSaTerminalInfoDefaults(): void
    {
        $info = new SaTerminalInfo();
        $this->assertEquals('', $info->getDeviceType());
        $this->assertEquals('', $info->getTokenValue());
        $this->assertEquals(0, $info->getLoginTime());
        $this->assertEquals(0, $info->getCreateTime());
    }

    public function testSaTerminalInfoArrayInit(): void
    {
        $info = new SaTerminalInfo([
            'deviceType' => 'PC',
            'tokenValue' => 'token-abc',
            'createTime' => 1000000,
        ]);
        $this->assertEquals('PC', $info->getDeviceType());
        $this->assertEquals('token-abc', $info->getTokenValue());
        $this->assertEquals(1000000, $info->getCreateTime());
    }

    public function testSaTerminalInfoChainSetting(): void
    {
        $info = (new SaTerminalInfo())
            ->setDeviceType('MINI')
            ->setTokenValue('token-xyz')
            ->setLoginTime(999)
            ->setCreateTime(888);

        $this->assertEquals('MINI', $info->getDeviceType());
        $this->assertEquals('token-xyz', $info->getTokenValue());
        $this->assertEquals(999, $info->getLoginTime());
        $this->assertEquals(888, $info->getCreateTime());
    }

    public function testSaTerminalInfoToArray(): void
    {
        $info = new SaTerminalInfo(['deviceType' => 'PC', 'tokenValue' => 'abc']);
        $arr = $info->toArray();

        $this->assertArrayHasKey('deviceType', $arr);
        $this->assertArrayHasKey('tokenValue', $arr);
        $this->assertArrayHasKey('loginTime', $arr);
        $this->assertArrayHasKey('createTime', $arr);
        $this->assertEquals('PC', $arr['deviceType']);
        $this->assertEquals('abc', $arr['tokenValue']);
    }
}
