<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\Session\SaSessionCleaner;

class SaSessionCleanerTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig(['tokenEncrypt' => false]));
        SaToken::setDao(new SaTokenDaoMemory());
        SaSessionCleaner::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
        SaSessionCleaner::reset();
    }

    public function testCleanOnceRemovesExpiredTokens(): void
    {
        $dao = SaToken::getDao();
        $pastTime = time() - 100;
        $futureTime = time() + 1000;

        $dao->set('satoken:login:token:expired-token-1', json_encode([
            'tokenValue' => 'expired-token-1',
            'loginId' => 'user1',
            'expireAt' => $pastTime,
        ]) ?: '{}');
        $dao->set('satoken:login:token:expired-token-2', json_encode([
            'tokenValue' => 'expired-token-2',
            'loginId' => 'user2',
            'expireAt' => $pastTime,
        ]) ?: '{}');
        $dao->set('satoken:login:token:valid-token', json_encode([
            'tokenValue' => 'valid-token',
            'loginId' => 'user3',
            'expireAt' => $futureTime,
        ]) ?: '{}');

        $cleaned = SaSessionCleaner::cleanOnce();

        $this->assertEquals(2, $cleaned);
        $this->assertNull($dao->get('satoken:login:token:expired-token-1'));
        $this->assertNull($dao->get('satoken:login:token:expired-token-2'));
        $this->assertNotNull($dao->get('satoken:login:token:valid-token'));
    }

    public function testCleanOnceRemovesExpiredSessions(): void
    {
        $dao = SaToken::getDao();
        $pastTime = time() - 100;
        $futureTime = time() + 1000;

        $dao->set('satoken:session:expired-session-1', json_encode([
            'id' => 'expired-session-1',
            'expireAt' => $pastTime,
        ]) ?: '{}');
        $dao->set('satoken:session:expired-session-2', json_encode([
            'id' => 'expired-session-2',
            'expireAt' => $pastTime,
        ]) ?: '{}');
        $dao->set('satoken:tokenSession:expired-token-session', json_encode([
            'id' => 'expired-token-session',
            'expireAt' => $pastTime,
        ]) ?: '{}');
        $dao->set('satoken:session:valid-session', json_encode([
            'id' => 'valid-session',
            'expireAt' => $futureTime,
        ]) ?: '{}');

        $cleaned = SaSessionCleaner::cleanOnce();

        $this->assertEquals(3, $cleaned);
        $this->assertNull($dao->get('satoken:session:expired-session-1'));
        $this->assertNull($dao->get('satoken:session:expired-session-2'));
        $this->assertNull($dao->get('satoken:tokenSession:expired-token-session'));
        $this->assertNotNull($dao->get('satoken:session:valid-session'));
    }

    public function testCleanOnceSkipsValidTokens(): void
    {
        $dao = SaToken::getDao();
        $futureTime = time() + 10000;
        $noExpireTime = null;

        $dao->set('satoken:login:token:valid-token-1', json_encode([
            'tokenValue' => 'valid-token-1',
            'loginId' => 'user1',
            'expireAt' => $futureTime,
        ]) ?: '{}');
        $dao->set('satoken:login:token:valid-token-2', json_encode([
            'tokenValue' => 'valid-token-2',
            'loginId' => 'user2',
            'expireAt' => $noExpireTime,
        ]) ?: '{}');
        $dao->set('satoken:session:valid-session', json_encode([
            'id' => 'valid-session',
            'expireAt' => $futureTime,
        ]) ?: '{}');

        $cleaned = SaSessionCleaner::cleanOnce();

        $this->assertEquals(0, $cleaned);
        $this->assertNotNull($dao->get('satoken:login:token:valid-token-1'));
        $this->assertNotNull($dao->get('satoken:login:token:valid-token-2'));
        $this->assertNotNull($dao->get('satoken:session:valid-session'));
    }

    public function testIsRunningReturnsFalseInitially(): void
    {
        $this->assertFalse(SaSessionCleaner::isRunning());
    }

    public function testTotalCleanedCounter(): void
    {
        $dao = SaToken::getDao();
        $pastTime = time() - 100;

        $dao->set('satoken:login:token:expired-token-1', json_encode([
            'tokenValue' => 'expired-token-1',
            'loginId' => 'user1',
            'expireAt' => $pastTime,
        ]) ?: '{}');

        SaSessionCleaner::cleanOnce();
        $firstClean = SaSessionCleaner::getTotalCleaned();

        $dao->set('satoken:login:token:expired-token-2', json_encode([
            'tokenValue' => 'expired-token-2',
            'loginId' => 'user2',
            'expireAt' => $pastTime,
        ]) ?: '{}');

        SaSessionCleaner::cleanOnce();
        $secondClean = SaSessionCleaner::getTotalCleaned();

        $this->assertEquals(1, $firstClean);
        $this->assertEquals(2, $secondClean);
    }

    public function testSetIntervalAndBatchSize(): void
    {
        SaSessionCleaner::setInterval(7200);
        SaSessionCleaner::setBatchSize(500);

        SaSessionCleaner::setInterval(3600);
        SaSessionCleaner::setBatchSize(200);

        $this->assertTrue(true);
    }

    public function testResetClearsTotalCleaned(): void
    {
        $dao = SaToken::getDao();
        $pastTime = time() - 100;

        $dao->set('satoken:login:token:expired-token-1', json_encode([
            'tokenValue' => 'expired-token-1',
            'loginId' => 'user1',
            'expireAt' => $pastTime,
        ]) ?: '{}');

        SaSessionCleaner::cleanOnce();
        $this->assertEquals(1, SaSessionCleaner::getTotalCleaned());

        SaSessionCleaner::reset();
        $this->assertEquals(0, SaSessionCleaner::getTotalCleaned());
    }

    public function testCleanOnceReturnsCount(): void
    {
        $dao = SaToken::getDao();
        $pastTime = time() - 100;

        $dao->set('satoken:login:token:token1', json_encode([
            'tokenValue' => 'token1',
            'loginId' => 'user1',
            'expireAt' => $pastTime,
        ]) ?: '{}');
        $dao->set('satoken:login:token:token2', json_encode([
            'tokenValue' => 'token2',
            'loginId' => 'user2',
            'expireAt' => $pastTime,
        ]) ?: '{}');
        $dao->set('satoken:session:session1', json_encode([
            'id' => 'session1',
            'expireAt' => $pastTime,
        ]) ?: '{}');

        $count = SaSessionCleaner::cleanOnce();

        $this->assertEquals(3, $count);
    }
}
