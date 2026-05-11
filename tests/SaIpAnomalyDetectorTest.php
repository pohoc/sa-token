<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\Security\SaIpAnomalyDetector;

class SaIpAnomalyDetectorTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setDao(new SaTokenDaoMemory());
        SaIpAnomalyDetector::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaIpAnomalyDetector::reset();
    }

    public function testGetAnomalyCountReturnsZeroInitially(): void
    {
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount('testuser'));
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount('admin'));
    }

    public function testRecordLoginIpWithSameIpDoesNotIncreaseAnomalyCount(): void
    {
        $loginId = 'testuser';
        $ip = '192.168.1.100';

        SaIpAnomalyDetector::recordLoginIp($loginId, $ip);
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount($loginId));

        SaIpAnomalyDetector::recordLoginIp($loginId, $ip);
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount($loginId));
    }

    public function testDifferentRegionTriggersAnomaly(): void
    {
        $config = SaToken::getConfig();
        $config->setIpAnomalyDetection(true);

        $loginId = 'testuser';

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.100');
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount($loginId));

        SaIpAnomalyDetector::recordLoginIp($loginId, '10.0.0.50');
        $this->assertEquals(1, SaIpAnomalyDetector::getAnomalyCount($loginId));
    }

    public function testSensitivityPreventsFalsePositives(): void
    {
        $config = SaToken::getConfig();
        $config->setIpAnomalyDetection(true);
        $config->setIpAnomalySensitivity(2);

        $loginId = 'testuser';

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.100');
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount($loginId));

        SaIpAnomalyDetector::recordLoginIp($loginId, '10.0.0.50');
        $this->assertEquals(1, SaIpAnomalyDetector::getAnomalyCount($loginId));

        SaIpAnomalyDetector::recordLoginIp($loginId, '10.0.0.60');
        $this->assertEquals(1, SaIpAnomalyDetector::getAnomalyCount($loginId));
    }

    public function testIpHistoryIsRecorded(): void
    {
        $loginId = 'testuser';

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.100');
        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.101');
        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.102');

        $history = SaIpAnomalyDetector::getIpHistory($loginId);
        $this->assertCount(3, $history);
        $this->assertEquals('192.168.1.100', $history[0]['ip']);
        $this->assertEquals('192.168.1.101', $history[1]['ip']);
        $this->assertEquals('192.168.1.102', $history[2]['ip']);
    }

    public function testHistoryIsLimitedToTwentyEntries(): void
    {
        $loginId = 'testuser';

        for ($i = 1; $i <= 25; $i++) {
            SaIpAnomalyDetector::recordLoginIp($loginId, "192.168.1.$i");
        }

        $history = SaIpAnomalyDetector::getIpHistory($loginId);
        $this->assertCount(20, $history);
        $this->assertEquals('192.168.1.6', $history[0]['ip']);
        $this->assertEquals('192.168.1.25', $history[19]['ip']);
    }

    public function testGetLoginInfoReturnsCorrectData(): void
    {
        $loginId = 'testuser';

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.100');
        $info = SaIpAnomalyDetector::getLoginInfo($loginId);

        $this->assertEquals('192.168.1.100', $info['currentIp']);
        $this->assertNull($info['lastLoginIp']);
        $this->assertNotNull($info['lastLoginTime']);
        $this->assertEquals(0, $info['anomalyCount']);
    }

    public function testGetCurrentIpReturnsCorrectValue(): void
    {
        $loginId = 'testuser';

        $this->assertNull(SaIpAnomalyDetector::getCurrentIp($loginId));

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.100');
        $this->assertEquals('192.168.1.100', SaIpAnomalyDetector::getCurrentIp($loginId));

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.200');
        $this->assertEquals('192.168.1.200', SaIpAnomalyDetector::getCurrentIp($loginId));
    }

    public function testClearHistoryRemovesAllData(): void
    {
        $loginId = 'testuser';

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.100');
        $this->assertNotNull(SaIpAnomalyDetector::getCurrentIp($loginId));
        $this->assertNotEmpty(SaIpAnomalyDetector::getIpHistory($loginId));

        SaIpAnomalyDetector::clearHistory($loginId);
        $this->assertNull(SaIpAnomalyDetector::getCurrentIp($loginId));
        $this->assertEmpty(SaIpAnomalyDetector::getIpHistory($loginId));
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount($loginId));
    }

    public function testDifferentLoginTypesAreIndependent(): void
    {
        $loginId = 'testuser';

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.100', 'login');
        SaIpAnomalyDetector::recordLoginIp($loginId, '10.0.0.50', 'admin');

        $this->assertEquals('192.168.1.100', SaIpAnomalyDetector::getCurrentIp($loginId, 'login'));
        $this->assertEquals('10.0.0.50', SaIpAnomalyDetector::getCurrentIp($loginId, 'admin'));

        $this->assertCount(1, SaIpAnomalyDetector::getIpHistory($loginId, 'login'));
        $this->assertCount(1, SaIpAnomalyDetector::getIpHistory($loginId, 'admin'));
    }

    public function testIsSameRegionForIdenticalIps(): void
    {
        $this->assertTrue(SaIpAnomalyDetector::isSameRegion('192.168.1.100', '192.168.1.100'));
        $this->assertTrue(SaIpAnomalyDetector::isSameRegion('10.0.0.1', '10.0.0.1'));
    }

    public function testIsSameRegionForDifferentFirstOctet(): void
    {
        $this->assertFalse(SaIpAnomalyDetector::isSameRegion('1.2.3.4', '2.3.4.5'));
        $this->assertFalse(SaIpAnomalyDetector::isSameRegion('202.96.128.86', '203.96.134.1'));
        $this->assertFalse(SaIpAnomalyDetector::isSameRegion('8.8.8.8', '114.114.114.114'));
    }

    public function testIsSameRegionForPrivateNetworkRanges(): void
    {
        $this->assertTrue(SaIpAnomalyDetector::isSameRegion('127.0.0.1', '127.0.0.2'));
        $this->assertTrue(SaIpAnomalyDetector::isSameRegion('192.168.1.1', '192.168.2.1'));
        $this->assertTrue(SaIpAnomalyDetector::isSameRegion('10.0.0.1', '10.1.0.1'));
        $this->assertTrue(SaIpAnomalyDetector::isSameRegion('192.168.0.1', '10.0.0.1'));
        $this->assertTrue(SaIpAnomalyDetector::isSameRegion('172.20.0.1', '172.31.255.255'));
        $this->assertTrue(SaIpAnomalyDetector::isSameRegion('172.15.0.1', '172.32.0.1'));
        $this->assertFalse(SaIpAnomalyDetector::isSameRegion('127.0.0.1', '8.8.8.8'));
    }

    public function testCustomKeyPrefix(): void
    {
        SaIpAnomalyDetector::setKeyPrefix('custom:prefix:');
        $key = SaIpAnomalyDetector::getKey('testuser', 'login');
        $this->assertStringStartsWith('custom:prefix:', $key);
    }

    public function testAnomalyDetectionDisabledDoesNotTrack(): void
    {
        $config = SaToken::getConfig();
        $config->setIpAnomalyDetection(false);

        $loginId = 'testuser';

        SaIpAnomalyDetector::recordLoginIp($loginId, '192.168.1.100');
        SaIpAnomalyDetector::recordLoginIp($loginId, '10.0.0.50');

        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount($loginId));
    }

    public function testMultipleAccountsAreIndependent(): void
    {
        $loginIdA = 'user_a';
        $loginIdB = 'user_b';

        SaIpAnomalyDetector::recordLoginIp($loginIdA, '192.168.1.100');
        SaIpAnomalyDetector::recordLoginIp($loginIdB, '10.0.0.50');

        $this->assertEquals('192.168.1.100', SaIpAnomalyDetector::getCurrentIp($loginIdA));
        $this->assertEquals('10.0.0.50', SaIpAnomalyDetector::getCurrentIp($loginIdB));
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount($loginIdA));
        $this->assertEquals(0, SaIpAnomalyDetector::getAnomalyCount($loginIdB));
    }
}
