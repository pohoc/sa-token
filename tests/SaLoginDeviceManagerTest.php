<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Data\SaLoginDevice;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\Security\SaLoginDeviceManager;
use SaToken\StpLogic;

class SaLoginDeviceManagerTest extends TestCase
{
    protected StpLogic $logic;
    protected SaTokenDaoMemory $dao;

    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'       => 'satoken',
            'timeout'         => 86400,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
            'isReadHeader'    => false,
            'isReadCookie'    => false,
            'isReadBody'      => false,
            'isWriteCookie'   => false,
            'isWriteHeader'   => false,
            'deviceManagement' => true,
        ]));
        $this->dao = new SaTokenDaoMemory();
        SaToken::setDao($this->dao);

        $this->logic = new StpLogic('login');
        SaLoginDeviceManager::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaLoginDeviceManager::reset();
    }

    public function testDeviceRegistration(): void
    {
        $device = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'Chrome Browser',
            'ip' => '192.168.1.100',
        ]);

        $param = new SaLoginParameter();
        $param->setDevice($device);

        $loginResult = $this->logic->login(10001, $param);
        $token = $loginResult->getAccessToken();

        $devices = $this->logic->getDeviceList(10001);
        $this->assertCount(1, $devices);

        $savedDevice = $devices[0];
        $this->assertEquals('pc', $savedDevice->getDeviceType());
        $this->assertEquals('Chrome Browser', $savedDevice->getDeviceName());
        $this->assertEquals('192.168.1.100', $savedDevice->getIp());
        $this->assertEquals($token, $savedDevice->getTokenValue());
    }

    public function testMultipleDeviceLogin(): void
    {
        $this->logic->login(10001);
        $this->logic->login(10002);
        $this->logic->login(10003);

        $this->assertEquals(1, $this->logic->getDeviceCount(10001));
        $this->assertEquals(1, $this->logic->getDeviceCount(10002));
        $this->assertEquals(1, $this->logic->getDeviceCount(10003));
    }

    public function testFindDevice(): void
    {
        $device = new SaLoginDevice([
            'deviceType' => 'mobile',
            'deviceName' => 'iPhone',
            'ip' => '10.0.0.1',
        ]);

        $param = new SaLoginParameter();
        $param->setDevice($device);

        $this->logic->login(10001, $param);

        $devices = $this->logic->getDeviceList(10001);
        $this->assertCount(1, $devices);

        $deviceId = $devices[0]->getDeviceId();
        $foundDevice = $this->logic->findDevice(10001, $deviceId);

        $this->assertNotNull($foundDevice);
        $this->assertEquals('mobile', $foundDevice->getDeviceType());
        $this->assertEquals('iPhone', $foundDevice->getDeviceName());
    }

    public function testFindNonExistentDevice(): void
    {
        $foundDevice = $this->logic->findDevice(10001, 'non-existent-device-id');
        $this->assertNull($foundDevice);
    }

    public function testKickoutDevice(): void
    {
        $device1 = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'Desktop',
            'ip' => '192.168.1.1',
        ]);
        $device2 = new SaLoginDevice([
            'deviceType' => 'mobile',
            'deviceName' => 'Phone',
            'ip' => '192.168.1.2',
        ]);

        $this->logic->login(10001, (new SaLoginParameter())->setDevice($device1));
        $this->logic->login(10001, (new SaLoginParameter())->setDevice($device2));

        $this->assertEquals(2, $this->logic->getDeviceCount(10001));

        $devices = $this->logic->getDeviceList(10001);
        $deviceIdToKick = $devices[0]->getDeviceId();

        $this->logic->kickoutDevice(10001, $deviceIdToKick);

        $this->assertEquals(1, $this->logic->getDeviceCount(10001));
    }

    public function testKickoutAllDevices(): void
    {
        $device1 = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'PC1',
            'ip' => '192.168.1.1',
        ]);
        $device2 = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'PC2',
            'ip' => '192.168.1.2',
        ]);
        $device3 = new SaLoginDevice([
            'deviceType' => 'mobile',
            'deviceName' => 'Phone',
            'ip' => '192.168.1.3',
        ]);

        $this->logic->login(10001, (new SaLoginParameter())->setDevice($device1));
        $this->logic->login(10001, (new SaLoginParameter())->setDevice($device2));
        $this->logic->login(10001, (new SaLoginParameter())->setDevice($device3));

        $this->assertEquals(3, $this->logic->getDeviceCount(10001));

        $count = $this->logic->kickoutAllDevices(10001);

        $this->assertEquals(3, $count);
        $this->assertEquals(0, $this->logic->getDeviceCount(10001));
    }

    public function testKickoutAllDevicesExceptToken(): void
    {
        SaToken::getConfig()->setIsShare(false);

        $device1 = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'PC1',
            'ip' => '192.168.1.10',
        ]);
        $device2 = new SaLoginDevice([
            'deviceType' => 'tablet',
            'deviceName' => 'iPad',
            'ip' => '192.168.1.11',
        ]);

        $loginResult1 = $this->logic->login(10001, (new SaLoginParameter())->setDevice($device1));
        $tokenToKeep = $loginResult1->getAccessToken();
        $loginResult2 = $this->logic->login(10001, (new SaLoginParameter())->setDevice($device2));
        $tokenToRemove = $loginResult2->getAccessToken();

        $this->assertNotEquals($tokenToKeep, $tokenToRemove);

        $devicesBefore = $this->logic->getDeviceList(10001);
        $this->assertGreaterThanOrEqual(2, count($devicesBefore));

        $count = $this->logic->kickoutAllDevices(10001, $tokenToKeep);

        $this->assertEquals(1, $count);
        $this->assertEquals(1, $this->logic->getDeviceCount(10001));

        $devices = $this->logic->getDeviceList(10001);
        $this->assertCount(1, $devices);
        $this->assertEquals($tokenToKeep, $devices[0]->getTokenValue());
    }

    public function testDeviceIdUniqueness(): void
    {
        $device1 = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'Chrome',
            'ip' => '192.168.1.1',
        ]);
        $device2 = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'Chrome',
            'ip' => '192.168.1.1',
        ]);
        $device3 = new SaLoginDevice([
            'deviceType' => 'mobile',
            'deviceName' => 'Chrome',
            'ip' => '192.168.1.1',
        ]);

        $this->assertEquals($device1->getDeviceId(), $device2->getDeviceId());
        $this->assertNotEquals($device1->getDeviceId(), $device3->getDeviceId());
    }

    public function testDeviceToArray(): void
    {
        $device = new SaLoginDevice([
            'tokenValue' => 'test-token',
            'deviceType' => 'tablet',
            'deviceName' => 'iPad',
            'ip' => '10.0.0.50',
            'os' => 'iOS',
            'browser' => 'Safari',
            'loginTime' => 1234567890,
            'loginType' => 'login',
        ]);

        $array = $device->toArray();

        $this->assertEquals('test-token', $array['tokenValue']);
        $this->assertEquals('tablet', $array['deviceType']);
        $this->assertEquals('iPad', $array['deviceName']);
        $this->assertEquals('10.0.0.50', $array['ip']);
        $this->assertEquals('iOS', $array['os']);
        $this->assertEquals('Safari', $array['browser']);
        $this->assertEquals(1234567890, $array['loginTime']);
        $this->assertEquals('login', $array['loginType']);
    }

    public function testLoginWithoutDeviceWhenDisabled(): void
    {
        SaToken::getConfig()->setDeviceManagement(false);
        SaLoginDeviceManager::reset();

        $loginResult = $this->logic->login(10001);
        $token = $loginResult->getAccessToken();

        $this->assertEquals(0, $this->logic->getDeviceCount(10001));
    }

    public function testUpdateLastActive(): void
    {
        $device = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'TestPC',
            'ip' => '127.0.0.1',
        ]);

        $this->logic->login(10001, (new SaLoginParameter())->setDevice($device));

        $devices = $this->logic->getDeviceList(10001);
        $deviceId = $devices[0]->getDeviceId();

        $this->assertNull($devices[0]->getLastActiveTime());

        SaLoginDeviceManager::updateLastActive(10001, $deviceId, 'login');

        $updatedDevice = $this->logic->findDevice(10001, $deviceId);
        $this->assertNotNull($updatedDevice);
        $this->assertNotNull($updatedDevice->getLastActiveTime());
        $this->assertGreaterThanOrEqual(time() - 5, $updatedDevice->getLastActiveTime());
    }
}
