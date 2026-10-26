<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Dao\SaTokenDaoPsr16;
use SaToken\Data\SaLoginDevice;
use SaToken\Exception\SaTokenException;
use SaToken\Listener\SaTokenListenerInterface;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\Security\SaLoginDeviceManager;
use SaToken\StpLogic;

class SaLoginDevicePausingDao extends SaTokenDaoMemory
{
    public ?string $pauseUpdateKey = null;

    public function update(string $key, string $value): void
    {
        if ($key === $this->pauseUpdateKey) {
            $this->pauseUpdateKey = null;
            \Fiber::suspend();
        }

        parent::update($key, $value);
    }
}

class SaLoginDeviceFailingDao extends SaTokenDaoMemory
{
    public bool $failDeviceRecordWrite = false;

    public function set(string $key, string $value, ?int $timeout = null): void
    {
        if ($this->failDeviceRecordWrite && str_starts_with($key, SaLoginDeviceManager::getKey('failed-login', 'login') . ':')) {
            $this->failDeviceRecordWrite = false;
            throw new \RuntimeException('simulated device storage failure');
        }

        parent::set($key, $value, $timeout);
    }
}

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
        $this->assertSame('', $savedDevice->getTokenValue());
        $this->assertTrue($this->logic->getTokenManager()->isTokenValid($token));
    }

    public function testFailedDeviceRegistrationRevokesNewlyIssuedSession(): void
    {
        $this->dao = new SaLoginDeviceFailingDao();
        SaToken::setDao($this->dao);
        $this->dao->failDeviceRecordWrite = true;

        try {
            $this->logic->login('failed-login');
            self::fail('设备记录写入失败时登录应失败');
        } catch (\RuntimeException $exception) {
            self::assertSame('simulated device storage failure', $exception->getMessage());
        }

        self::assertSame([], $this->logic->getTokenManager()->getTokenListByLoginId('failed-login', 'login'));
        self::assertSame(0, SaLoginDeviceManager::getDeviceCount('failed-login', 'login'));
    }

    public function testKickoutAllDevicesDispatchesEventsAfterAccountLockRelease(): void
    {
        $loginId = 'device-kickout-event-lock';
        $this->logic->login($loginId, (new SaLoginParameter())->setDeviceType('desktop'));
        $this->logic->login($loginId, (new SaLoginParameter())->setDeviceType('mobile'));
        $lockKey = \SaToken\TokenManager::LOCK_PREFIX . 'login:login:' . hash('sha256', $loginId);

        $listener = $this->createMock(SaTokenListenerInterface::class);
        $listener->expects(self::exactly(2))
            ->method('onKickout')
            ->willReturnCallback(function () use ($lockKey): void {
                self::assertNull($this->dao->get($lockKey));
            });
        SaToken::addListener($listener);

        self::assertSame(2, $this->logic->kickoutAllDevices($loginId));
    }

    public function testDeviceListDoesNotCrossNestedLoginTypePrefixes(): void
    {
        $parentLoginId = 'device-owner';
        $childLoginType = 'login:' . md5($parentLoginId);
        $childLogic = new StpLogic($childLoginType);
        $childLogic->login('child-account', (new SaLoginParameter())->setDevice(new SaLoginDevice([
            'deviceType' => 'private',
            'deviceName' => 'Internal admin workstation',
            'ip'         => '203.0.113.42',
        ])));

        $devices = SaLoginDeviceManager::getDeviceList($parentLoginId, 'login');
        self::assertCount(0, $devices);
        self::assertCount(1, SaLoginDeviceManager::getDeviceList('child-account', $childLoginType));
    }

    public function testKickoutDeviceCannotDeleteNestedLoginTypeDeviceRecord(): void
    {
        $parentLoginId = 'device-owner';
        $childLoginType = 'login:' . md5($parentLoginId);
        $childLoginId = 'child-account';
        $childLogic = new StpLogic($childLoginType);
        $device = new SaLoginDevice([
            'deviceType' => 'private',
            'deviceName' => 'Internal admin workstation',
            'ip'         => '203.0.113.42',
        ]);
        $token = $childLogic->login($childLoginId, (new SaLoginParameter())->setDevice($device))->getAccessToken();
        $foreignDeviceId = md5($childLoginId) . ':' . $device->getDeviceId();

        $this->logic->kickoutDevice($parentLoginId, $foreignDeviceId);

        self::assertTrue($childLogic->getTokenManager()->isTokenValid($token));
        self::assertCount(1, SaLoginDeviceManager::getDeviceList($childLoginId, $childLoginType));
    }

    public function testDeviceRecordDoesNotExposeTokenWhenTokenEncryptionIsEnabled(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'        => 'satoken',
            'timeout'          => 86400,
            'isReadHeader'     => false,
            'isReadCookie'     => false,
            'isReadBody'       => false,
            'isWriteCookie'    => false,
            'isWriteHeader'    => false,
            'deviceManagement' => true,
            'tokenEncrypt'     => true,
            'tokenEncryptKey'  => 'device-record-test-encryption-key-32-bytes',
        ]));

        $token = $this->logic->login(10001, (new SaLoginParameter())->setDevice(new SaLoginDevice()))->getAccessToken();
        $devices = $this->logic->getDeviceList(10001);
        $key = SaLoginDeviceManager::getKey(10001, 'login') . ':' . $devices[0]->getDeviceId();
        $storedRecord = $this->dao->get($key);

        $this->assertNotNull($storedRecord);
        $this->assertStringNotContainsString($token, $storedRecord);

        $this->logic->kickoutDevice(10001, $devices[0]->getDeviceId());
        $this->assertNull($this->logic->getTokenManager()->getLoginIdByToken($token));
    }

    public function testKickoutAllDevicesPreservesExceptTokenWhenTokenEncryptionIsEnabled(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'        => 'satoken',
            'timeout'          => 86400,
            'isReadHeader'     => false,
            'isReadCookie'     => false,
            'isReadBody'       => false,
            'isWriteCookie'    => false,
            'isWriteHeader'    => false,
            'deviceManagement' => true,
            'tokenEncrypt'     => true,
            'tokenEncryptKey'  => 'device-record-test-encryption-key-32-bytes',
        ]));

        $keepToken = $this->logic->login(10001, (new SaLoginParameter())->setDeviceType('pc')->setDevice(new SaLoginDevice(['deviceType' => 'pc'])))->getAccessToken();
        $removeToken = $this->logic->login(10001, (new SaLoginParameter())->setDeviceType('mobile')->setDevice(new SaLoginDevice(['deviceType' => 'mobile'])))->getAccessToken();

        $this->assertCount(2, $this->logic->getDeviceList(10001));
        $this->assertSame('10001', $this->logic->getTokenManager()->getLoginIdByToken($keepToken));
        $this->assertSame('10001', $this->logic->getTokenManager()->getLoginIdByToken($removeToken));
        $this->assertSame(1, $this->logic->kickoutAllDevices(10001, $keepToken));
        $this->assertSame('10001', $this->logic->getTokenManager()->getLoginIdByToken($keepToken));
        $this->assertNull($this->logic->getTokenManager()->getLoginIdByToken($removeToken));
    }

    public function testStatelessKickoutAllDevicesPreservesOnlyExceptTokenOnSharedDevice(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'        => 'satoken',
            'timeout'          => 86400,
            'activityTimeout'  => -1,
            'isReadHeader'     => false,
            'isReadCookie'     => false,
            'isWriteCookie'    => false,
            'isWriteHeader'    => false,
            'deviceManagement' => true,
            'jwtStateless'     => true,
            'jwtSecretKey'     => 'test-stateless-device-secret-32-bytes-long',
        ]));

        $loginId = 'stateless-device-account';
        $firstToken = $this->logic->loginStateless($loginId);
        $secondToken = $this->logic->loginStateless($loginId);
        $deviceData = [
            'deviceType' => 'pc',
            'deviceName' => 'Shared workstation',
            'ip'         => '192.0.2.45',
        ];
        $firstDevice = new SaLoginDevice($deviceData);
        $secondDevice = new SaLoginDevice($deviceData);
        SaLoginDeviceManager::registerDevice($loginId, 'login', $firstDevice, $firstToken, $this->logic);
        SaLoginDeviceManager::registerDevice($loginId, 'login', $secondDevice, $secondToken, $this->logic);

        self::assertSame($firstDevice->getDeviceId(), $secondDevice->getDeviceId());
        self::assertSame($loginId, $this->logic->getLoginIdByToken($firstToken));
        self::assertSame($loginId, $this->logic->getLoginIdByToken($secondToken));

        $this->logic->kickoutAllDevices($loginId, $secondToken);

        self::assertNull($this->logic->getLoginIdByToken($firstToken));
        self::assertSame($loginId, $this->logic->getLoginIdByToken($secondToken));
    }

    public function testStatelessKickoutAllDevicesRemovesDeviceRecords(): void
    {
        SaToken::setConfig(new SaTokenConfig([
            'tokenName'        => 'satoken',
            'timeout'          => 86400,
            'activityTimeout'  => -1,
            'isReadHeader'     => false,
            'isReadCookie'     => false,
            'isWriteCookie'    => false,
            'isWriteHeader'    => false,
            'deviceManagement' => true,
            'jwtStateless'     => true,
            'jwtSecretKey'     => 'test-stateless-device-secret-32-bytes-long',
        ]));

        $loginId = 'stateless-device-cleanup-account';
        $token = $this->logic->loginStateless($loginId);
        $device = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'Old workstation',
        ]);
        SaLoginDeviceManager::registerDevice($loginId, 'login', $device, $token, $this->logic);

        self::assertSame(1, $this->logic->kickoutAllDevices($loginId));
        self::assertNull($this->logic->getLoginIdByToken($token));
        self::assertSame([], $this->logic->getDeviceList($loginId));
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
        $this->assertSame('', $foundDevice->getTokenValue());
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

    public function testKickoutDeviceRevokesEverySessionRegisteredForThatDevice(): void
    {
        SaToken::getConfig()
            ->setTokenEncrypt(true)
            ->setTokenEncryptKey('device-session-list-encryption-key-32-bytes');

        $device = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'Shared workstation',
            'ip' => '192.0.2.88',
        ]);
        $parameter = (new SaLoginParameter())
            ->setDeviceType('pc')
            ->setIsShare(false)
            ->setDevice($device);

        $firstToken = $this->logic->login(10001, $parameter)->getAccessToken();
        $secondToken = $this->logic->login(10001, $parameter)->getAccessToken();
        $devices = $this->logic->getDeviceList(10001);
        $this->assertCount(1, $devices);
        $this->assertSame('10001', $this->logic->getTokenManager()->getLoginIdByToken($firstToken));
        $this->assertSame('10001', $this->logic->getTokenManager()->getLoginIdByToken($secondToken));
        $deviceKey = SaLoginDeviceManager::getKey(10001, 'login') . ':' . $devices[0]->getDeviceId();
        $storedDevice = $this->dao->get($deviceKey);
        $this->assertNotNull($storedDevice);
        $this->assertStringNotContainsString($firstToken, $storedDevice);
        $this->assertStringNotContainsString($secondToken, $storedDevice);

        $this->logic->kickoutDevice(10001, $devices[0]->getDeviceId());

        $this->assertNull($this->logic->getTokenManager()->getLoginIdByToken($firstToken));
        $this->assertNull($this->logic->getTokenManager()->getLoginIdByToken($secondToken));
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

    public function testKickoutAllDevicesDoesNotLeaveSessionsPastFirstHundredRecords(): void
    {
        $loginId = 'large-device-account';
        $tokens = [];

        for ($i = 0; $i < 101; $i++) {
            $device = new SaLoginDevice([
                'deviceType' => 'pc',
                'deviceName' => 'Device ' . $i,
                'ip' => '192.0.2.' . ($i + 1),
            ]);
            $parameter = (new SaLoginParameter())
                ->setDeviceType('device-' . $i)
                ->setDevice($device)
                ->setIsShare(false)
                ->setMaxLoginCount(-1);
            $tokens[] = $this->logic->login($loginId, $parameter)->getAccessToken();
        }

        $this->assertSame(101, $this->logic->kickoutAllDevices($loginId));

        $remaining = array_filter(
            $tokens,
            fn (string $token): bool => $this->logic->getTokenManager()->getLoginIdByToken($token) !== null
        );
        $this->assertCount(0, $remaining);
    }

    public function testKickoutAllDevicesUsesSessionIndexWhenDaoCannotSearchKeys(): void
    {
        SaToken::setDao(new SaTokenDaoPsr16(new ArrayPsr16Cache()));
        $device = new SaLoginDevice([
            'deviceType' => 'pc',
            'deviceName' => 'PSR-16 device',
            'ip' => '192.0.2.201',
        ]);
        $token = $this->logic->login(
            'psr16-device-account',
            (new SaLoginParameter())->setDeviceType('psr16-device-a')->setDevice($device)->setIsShare(false)
        )->getAccessToken();
        $keepToken = $this->logic->login(
            'psr16-device-account',
            (new SaLoginParameter())
                ->setDeviceType('psr16-device-b')
                ->setDevice(new SaLoginDevice(['deviceName' => 'PSR-16 second device', 'ip' => '192.0.2.202']))
                ->setIsShare(false)
        )->getAccessToken();

        $this->assertSame(1, $this->logic->kickoutAllDevices('psr16-device-account', $keepToken));
        $this->assertNull($this->logic->getTokenManager()->getLoginIdByToken($token));
        $this->assertSame('psr16-device-account', $this->logic->getTokenManager()->getLoginIdByToken($keepToken));
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
        $this->assertSame('', $devices[0]->getTokenValue());
        $this->assertSame('10001', $this->logic->getTokenManager()->getLoginIdByToken($tokenToKeep));
        $this->assertNull($this->logic->getTokenManager()->getLoginIdByToken($tokenToRemove));
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
        $deviceKey = SaLoginDeviceManager::getKey(10001, 'login') . ':' . $deviceId;

        $this->assertNull($devices[0]->getLastActiveTime());
        $this->assertGreaterThan(0, $this->dao->getTimeout($deviceKey));

        SaLoginDeviceManager::updateLastActive(10001, $deviceId, 'login');

        $this->assertGreaterThan(0, $this->dao->getTimeout($deviceKey), '更新设备活跃时间不能清除设备记录 TTL');
        $updatedDevice = $this->logic->findDevice(10001, $deviceId);
        $this->assertNotNull($updatedDevice);
        $this->assertNotNull($updatedDevice->getLastActiveTime());
        $this->assertGreaterThanOrEqual(time() - 5, $updatedDevice->getLastActiveTime());
    }

    public function testUpdateLastActiveSerializesWithDeviceRegistration(): void
    {
        $this->dao = new SaLoginDevicePausingDao();
        SaToken::setDao($this->dao);
        $device = new SaLoginDevice(['deviceType' => 'pc']);
        $firstToken = $this->logic->login(10001, (new SaLoginParameter())->setDevice($device))->getAccessToken();
        $deviceId = $device->getDeviceId();
        $deviceKey = SaLoginDeviceManager::getKey(10001, 'login') . ':' . $deviceId;
        $this->dao->pauseUpdateKey = $deviceKey;

        $update = new \Fiber(static fn () => SaLoginDeviceManager::updateLastActive(10001, $deviceId, 'login'));
        $update->start();
        $this->assertTrue($update->isSuspended());

        try {
            $this->logic->login(10001, (new SaLoginParameter())->setDevice($device)->setIsShare(false));
            $this->fail('设备活跃时间更新持有账号锁时，同账号注册应等待并发操作完成');
        } catch (SaTokenException $exception) {
            $this->assertStringContainsString('同账号登录正在处理中', $exception->getMessage());
        }

        $update->resume();
        $this->assertFalse($update->isSuspended());
        $secondToken = $this->logic->login(10001, (new SaLoginParameter())->setDevice($device)->setIsShare(false))->getAccessToken();

        $this->logic->kickoutDevice(10001, $deviceId);
        $this->assertFalse($this->logic->getTokenManager()->isTokenValid($firstToken));
        $this->assertFalse($this->logic->getTokenManager()->isTokenValid($secondToken));
    }

    public function testDeviceManagerCannotAssociateOrKickoutAnotherAccountsToken(): void
    {
        $victimToken = $this->logic->login('victim-account')->getAccessToken();
        $attackerId = 'attacker-account';
        $device = new SaLoginDevice(['deviceType' => 'pc', 'deviceName' => 'Attacker device']);

        try {
            SaLoginDeviceManager::registerDevice($attackerId, 'login', $device, $victimToken, $this->logic);
            $this->fail('设备记录不能关联其他账号的 Token');
        } catch (SaTokenException $exception) {
            $this->assertStringContainsString('设备 Token 与账号不匹配', $exception->getMessage());
        }

        // 防御旧版或被外部写入的错误设备记录，踢出操作也必须重新核实 Token 属主。
        $device->setLoginType('login')->setLoginTime(time());
        $record = $device->toArray();
        $record['managedTokenValues'] = [$victimToken];
        $record['managedTokenValuesEncrypted'] = false;
        $deviceKey = SaLoginDeviceManager::getKey($attackerId, 'login') . ':' . $device->getDeviceId();
        $this->dao->set($deviceKey, json_encode($record, JSON_THROW_ON_ERROR), 3600);

        SaLoginDeviceManager::kickoutDevice($attackerId, $device->getDeviceId(), 'login', $this->logic);

        $this->assertTrue($this->logic->getTokenManager()->isTokenValid($victimToken));
    }

    public function testDeviceManagerRejectsLogicInstanceForAnotherLoginType(): void
    {
        $loginId = 'same-id-across-login-types';
        $adminLogic = new StpLogic('admin');
        $adminToken = $adminLogic->login($loginId)->getAccessToken();
        $device = new SaLoginDevice(['deviceType' => 'pc', 'deviceName' => 'Mismatched logic']);

        try {
            SaLoginDeviceManager::registerDevice($loginId, 'user', $device, $adminToken, $adminLogic);
            $this->fail('设备注册不得用 admin 逻辑操作 user 类型的记录');
        } catch (SaTokenException $exception) {
            $this->assertStringContainsString('loginType 与 StpLogic 实例不匹配', $exception->getMessage());
        }

        $device->setLoginType('user')->setLoginTime(time());
        $record = $device->toArray();
        $record['managedTokenValues'] = [$adminToken];
        $record['managedTokenValuesEncrypted'] = false;
        $deviceKey = SaLoginDeviceManager::getKey($loginId, 'user') . ':' . $device->getDeviceId();
        $this->dao->set($deviceKey, json_encode($record, JSON_THROW_ON_ERROR), 3600);

        try {
            SaLoginDeviceManager::kickoutDevice($loginId, $device->getDeviceId(), 'user', $adminLogic);
            $this->fail('踢出操作不得用 admin 逻辑解析 user 类型的设备凭据');
        } catch (SaTokenException $exception) {
            $this->assertStringContainsString('loginType 与 StpLogic 实例不匹配', $exception->getMessage());
        }

        $this->assertTrue($adminLogic->getTokenManager()->isTokenValid($adminToken));
        $this->assertNotNull($this->dao->get($deviceKey));
    }
}
