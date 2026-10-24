<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoRedis;
use SaToken\Data\SaLoginDevice;
use SaToken\SaLoginParameter;
use SaToken\SaToken;
use SaToken\Security\SaLoginDeviceManager;
use SaToken\StpLogic;
use SaToken\TokenManager;

class RedisDaoRealIntegrationTest extends TestCase
{
    protected \Redis $redis;
    protected SaTokenDaoRedis $dao;
    protected string $prefix = '';

    protected function setUp(): void
    {
        if (!class_exists(\Redis::class)) {
            $this->markTestSkipped('Redis extension is not installed.');
        }

        $host = $_ENV['REDIS_HOST'] ?? getenv('REDIS_HOST') ?: '';
        $port = $_ENV['REDIS_PORT'] ?? getenv('REDIS_PORT') ?: '';

        if (!is_string($host) || $host === '' || !is_scalar($port) || (int) $port <= 0) {
            $this->markTestSkipped('REDIS_HOST / REDIS_PORT not configured.');
        }

        $redis = new \Redis();
        $connected = @$redis->connect($host, (int) $port, 1.5);
        if ($connected !== true) {
            $this->markTestSkipped('Unable to connect to Redis test service.');
        }

        $this->redis = $redis;
        $this->dao = new SaTokenDaoRedis([], $redis);
        $this->prefix = 'satoken:test:' . bin2hex(random_bytes(6)) . ':';
    }

    protected function tearDown(): void
    {
        if (isset($this->redis) && $this->prefix !== '') {
            $keys = $this->redis->keys($this->prefix . '*');
            if (is_array($keys) && $keys !== []) {
                $this->redis->del($keys);
            }
        }
    }

    public function testKickoutDeviceCannotDeleteNestedLoginTypeDeviceRecordAgainstRealRedis(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'timeout'          => 60,
            'activityTimeout'  => -1,
            'concurrent'       => true,
            'isShare'          => true,
            'maxLoginCount'    => 12,
            'deviceManagement' => true,
        ]));
        SaToken::setDao($this->dao);

        $parentLoginId = 'redis-device-owner-' . bin2hex(random_bytes(6));
        $childLoginType = 'login:' . md5($parentLoginId);
        $childLoginId = 'redis-child-' . bin2hex(random_bytes(6));
        $parentLogic = new StpLogic('login');
        $childLogic = new StpLogic($childLoginType);
        $device = new SaLoginDevice([
            'deviceType' => 'private',
            'deviceName' => 'Redis integration device',
            'ip'         => '203.0.113.42',
        ]);
        $deviceKey = SaLoginDeviceManager::getKey($childLoginId, $childLoginType) . ':' . $device->getDeviceId();

        try {
            $token = $childLogic->login($childLoginId, (new SaLoginParameter())->setDevice($device))->getAccessToken();
            $foreignDeviceId = md5($childLoginId) . ':' . $device->getDeviceId();
            $parentLogic->kickoutDevice($parentLoginId, $foreignDeviceId);

            self::assertTrue($childLogic->getTokenManager()->isTokenValid($token));
            self::assertCount(1, SaLoginDeviceManager::getDeviceList($childLoginId, $childLoginType));
        } finally {
            $this->dao->delete($deviceKey);
            $childLogic->logoutByLoginId($childLoginId);
            SaToken::reset();
        }
    }

    public function testSetGetExpireAndDeleteAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'basic';
        $this->dao->set($key, 'value-1', 60);

        $this->assertSame('value-1', $this->dao->get($key));
        $this->assertTrue($this->dao->exists($key));

        $ttl = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(60, $ttl);

        $this->dao->delete($key);
        $this->assertNull($this->dao->get($key));
        $this->assertFalse($this->dao->exists($key));
    }

    public function testRefreshTokenKeepsAccountIndexAliveAgainstRealRedis(): void
    {
        SaToken::reset();
        SaToken::setDao($this->dao);
        $manager = new TokenManager();
        $loginType = 'redis-refresh-test';
        $loginId = 'user-' . bin2hex(random_bytes(8));
        $accessToken = $manager->createTokenValue($loginId, $loginType);
        $refreshToken = $manager->createTokenValue($loginId, $loginType, 'srt_');

        try {
            $manager->saveToken($accessToken, $loginId, $loginType, 'PC', 5);
            $manager->saveRefreshToken($refreshToken, $accessToken, $loginId, $loginType, 30);

            $indexKey = TokenManager::buildLoginIdKey($loginType, $loginId);
            $this->assertGreaterThan($manager->getTokenTimeout($accessToken), $this->dao->getTimeout($indexKey));

            $manager->deleteAllTokenByLoginId($loginId, $loginType);
            $this->assertFalse($manager->isRefreshTokenValid($refreshToken));
        } finally {
            $this->redis->del([
                TokenManager::TOKEN_PREFIX . $accessToken,
                TokenManager::REFRESH_TOKEN_PREFIX . $refreshToken,
                TokenManager::REFRESH_TOKEN_MAP_PREFIX . $loginType . ':' . $loginId . ':' . $accessToken,
                TokenManager::buildLoginIdKey($loginType, $loginId),
            ]);
            SaToken::reset();
        }
    }

    public function testLegacyRefreshMigrationPreservesConcurrentLoginAgainstRealRedis(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'timeout'         => 3600,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
        ]));
        $redis = $this->redis;
        $dao = new class ($redis) extends SaTokenDaoRedis {
            public ?string $triggerKey = null;
            public ?\Closure $duringRead = null;

            public function __construct(\Redis $redis)
            {
                parent::__construct([], $redis);
            }

            public function getTimeout(string $key): int
            {
                $timeout = parent::getTimeout($key);
                if ($key === $this->triggerKey && $this->duringRead !== null) {
                    $callback = $this->duringRead;
                    $this->duringRead = null;
                    $callback();
                }

                return $timeout;
            }
        };
        SaToken::setDao($dao);
        $manager = new TokenManager();
        $loginId = 'redis-legacy-race-' . bin2hex(random_bytes(6));
        $loginType = 'redis-legacy-race';
        $accessToken = $manager->createTokenValue($loginId, $loginType);
        $refreshToken = $manager->createTokenValue($loginId, $loginType, 'srt_');
        $loginIdKey = TokenManager::buildLoginIdKey($loginType, $loginId);
        $legacyKey = TokenManager::LOGIN_ID_PREFIX . $loginType . ':' . $loginId;
        $freshToken = null;

        try {
            $manager->saveToken($accessToken, $loginId, $loginType, 'PC', 3600);
            $legacyList = $manager->getTokenListByLoginId($loginId, $loginType);
            $encrypt = new \ReflectionMethod(TokenManager::class, 'encryptValue');
            $legacyValue = $encrypt->invoke($manager, json_encode($legacyList));
            self::assertIsString($legacyValue);
            $dao->delete($loginIdKey);
            $dao->set($legacyKey, $legacyValue);

            $dao->triggerKey = TokenManager::TOKEN_PREFIX . $accessToken;
            $dao->duringRead = function () use ($dao, $loginId, $loginType, &$freshToken): void {
                // Expire the first request's account lease while it scans the
                // legacy index, then let another request commit a new session.
                $dao->delete(TokenManager::LOCK_PREFIX . 'login:' . $loginType . ':' . hash('sha256', $loginId));
                $concurrentManager = new TokenManager();
                $freshToken = $concurrentManager->createTokenValue($loginId, $loginType);
                $concurrentManager->saveToken($freshToken, $loginId, $loginType, 'mobile', 3600);
            };

            $manager->saveRefreshToken($refreshToken, $accessToken, $loginId, $loginType, 7200);

            self::assertIsString($freshToken);
            self::assertContains($freshToken, array_column($manager->getTokenListByLoginId($loginId, $loginType), 'tokenValue'));
        } finally {
            $manager->deleteAllTokenByLoginId($loginId, $loginType);
            $dao->delete(TokenManager::REFRESH_TOKEN_PREFIX . $refreshToken);
            $dao->delete($legacyKey);
            SaToken::reset();
        }
    }

    public function testPercentEscapeLegacyIndexCannotAuthenticateAcrossTypesAgainstRealRedis(): void
    {
        SaToken::reset();
        SaToken::setConfig(new SaTokenConfig([
            'timeout'         => 60,
            'activityTimeout' => -1,
            'concurrent'      => true,
            'isShare'         => true,
            'maxLoginCount'   => 12,
        ]));
        SaToken::setDao($this->dao);

        $loginId = 'redis-percent-user-' . bin2hex(random_bytes(6));
        $owner = new StpLogic('redis-user%');
        $otherType = new StpLogic('redis-user%25');
        try {
            $token = $owner->login($loginId)->getAccessToken();

            self::assertSame($loginId, $owner->getLoginIdByToken($token));
            self::assertNull($otherType->getLoginIdByToken($token));
        } finally {
            $owner->kickout($loginId);
            SaToken::reset();
        }
    }

    public function testSecurityTupleKeysStayDistinctAgainstRealRedis(): void
    {
        SaToken::reset();
        SaToken::setDao($this->dao);
        $manager = new TokenManager();
        $suffix = bin2hex(random_bytes(8));
        $tokenA = 'b:c:' . $suffix;
        $tokenB = 'c:' . $suffix;
        $refreshA = 'refresh-a-' . $suffix;
        $refreshB = 'refresh-b-' . $suffix;
        $keys = [
            TokenManager::TOKEN_PREFIX . $tokenA,
            TokenManager::TOKEN_PREFIX . $tokenB,
            TokenManager::SWITCH_PREFIX . 'a:b%3A' . $suffix,
            TokenManager::SWITCH_PREFIX . 'a%3Ab:c%3A' . $suffix,
            TokenManager::REFRESH_TOKEN_PREFIX . $refreshA,
            TokenManager::REFRESH_TOKEN_PREFIX . $refreshB,
            TokenManager::REFRESH_TOKEN_MAP_PREFIX . 'a:owner-a:' . $tokenA,
            TokenManager::REFRESH_TOKEN_MAP_PREFIX . 'a%3Ab:owner-b:' . $tokenB,
            TokenManager::buildLoginIdKey('a', 'b:c'),
            TokenManager::buildLoginIdKey('a:b', 'c'),
            TokenManager::buildSessionId('a', 'b:c'),
            TokenManager::buildSessionId('a:b', 'c'),
        ];

        try {
            $manager->saveToken($tokenA, 'owner-a', 'a', 'PC');
            $manager->saveToken($tokenB, 'owner-b', 'a:b', 'PC');
            $manager->setSwitchTo($tokenA, 'switched-user', 'a');
            self::assertSame('switched-user', $manager->getSwitchTo($tokenA, 'a'));
            self::assertNull($manager->getSwitchTo($tokenB, 'a:b'));

            $manager->saveRefreshToken($refreshA, $tokenA, 'owner-a', 'a', 60);
            $manager->saveRefreshToken($refreshB, $tokenB, 'owner-b', 'a:b', 60);
            self::assertSame($refreshA, $manager->getRefreshTokenByAccessToken('owner-a', 'a', $tokenA));
            self::assertSame($refreshB, $manager->getRefreshTokenByAccessToken('owner-b', 'a:b', $tokenB));
        } finally {
            $this->redis->del($keys);
            SaToken::reset();
        }
    }

    public function testDeleteIfExpiredAgainstRealRedis(): void
    {
        $expiredKey = $this->prefix . 'expired';
        $activeKey = $this->prefix . 'active';
        $this->dao->set($expiredKey, 'old', 1);
        $this->dao->set($activeKey, 'fresh', 60);
        sleep(2);

        // Redis removes expired keys itself; the conditional delete is a no-op
        // after physical expiration and must preserve a still-active key.
        $this->assertFalse($this->dao->deleteIfExpired($expiredKey));
        $this->assertFalse($this->dao->exists($expiredKey));
        $this->assertFalse($this->dao->deleteIfExpired($activeKey));
        $this->assertSame('fresh', $this->dao->get($activeKey));
    }

    public function testUpdatePreservesTtlAgainstRealRedis(): void
    {
        $key = $this->prefix . 'update-ttl';
        $this->dao->set($key, 'before', 60);
        $ttlBefore = $this->dao->getTimeout($key);

        $this->dao->update($key, 'after');

        $this->assertSame('after', $this->dao->get($key));
        $ttlAfter = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttlAfter);
        $this->assertLessThanOrEqual($ttlBefore, $ttlAfter);
    }

    public function testGetAndDeleteAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'get-and-delete';
        $this->dao->set($key, 'value-2', 60);

        $value = $this->dao->getAndDelete($key);
        $this->assertSame('value-2', $value);
        $this->assertNull($this->dao->get($key));
    }

    public function testCompareAndDeletePreservesAReplacementLock(): void
    {
        $key = $this->prefix . 'lock';
        $this->dao->set($key, 'new-owner', 60);

        $this->assertFalse($this->dao->compareAndDelete($key, 'old-owner'));
        $this->assertSame('new-owner', $this->dao->get($key));
        $this->assertTrue($this->dao->compareAndDelete($key, 'new-owner'));
        $this->assertNull($this->dao->get($key));
    }

    public function testCompareAndExpireOnlyRenewsTheCurrentRedisLockOwner(): void
    {
        $key = $this->prefix . 'renew-lock';
        $this->dao->set($key, 'new-owner', 5);

        self::assertFalse($this->dao->compareAndExpire($key, 'old-owner', 120));
        self::assertLessThanOrEqual(5, $this->dao->getTimeout($key));
        self::assertTrue($this->dao->compareAndExpire($key, 'new-owner', 120));
        self::assertGreaterThan(0, $this->dao->getTimeout($key));
        self::assertLessThanOrEqual(120, $this->dao->getTimeout($key));
    }

    public function testCompareAndExpireNeverShortensRedisTtlAndCanMakeAKeyPermanent(): void
    {
        $key = $this->prefix . 'extend-only-ttl';
        $this->dao->set($key, 'value', 120);

        self::assertTrue($this->dao->compareAndExpire($key, 'value', 30));
        self::assertGreaterThan(30, $this->dao->getTimeout($key));
        self::assertTrue($this->dao->compareAndExpire($key, 'value', -1));
        self::assertSame(-1, $this->dao->getTimeout($key));
    }

    public function testCompareAndUpdatePreservesValueAndTtlAgainstRealRedis(): void
    {
        $key = $this->prefix . 'session-compare-update';
        $this->dao->set($key, 'old-record', 60);
        $ttl = $this->dao->getTimeout($key);
        self::assertFalse($this->dao->compareAndUpdate($key, 'stale-record', 'wrong'));
        self::assertSame('old-record', $this->dao->get($key));
        self::assertTrue($this->dao->compareAndUpdate($key, 'old-record', 'new-record'));
        self::assertSame('new-record', $this->dao->get($key));
        self::assertGreaterThan(0, $this->dao->getTimeout($key));
        self::assertLessThanOrEqual($ttl, $this->dao->getTimeout($key));
    }

    public function testGetAndExpireAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'get-and-expire';
        $this->dao->set($key, 'value-3', 10);

        $value = $this->dao->getAndExpire($key, 120);
        $this->assertSame('value-3', $value);

        $ttl = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(120, $ttl);
    }

    public function testGetAndExpireWithNonPositiveTimeoutPersistsKey(): void
    {
        $key = $this->prefix . 'get-and-expire-persist';
        $this->dao->set($key, 'value-4', 10);

        $this->assertSame('value-4', $this->dao->getAndExpire($key, 0));
        $this->assertSame(-1, $this->dao->getTimeout($key));
    }

    public function testSetIfNotExistsAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'nx';

        $this->assertTrue($this->dao->setIfNotExists($key, 'first', 30));
        $this->assertFalse($this->dao->setIfNotExists($key, 'second', 30));
        $this->assertSame('first', $this->dao->get($key));

        $ttl = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(30, $ttl);

        // 过期后可再次获取
        $this->dao->expire($key, 1);
        sleep(2);
        $this->assertTrue($this->dao->setIfNotExists($key, 'third', 30));
        $this->assertSame('third', $this->dao->get($key));
    }

    public function testRedisUrlSelectsConfiguredHostAndDatabase(): void
    {
        $host = $_ENV['REDIS_HOST'] ?? getenv('REDIS_HOST') ?: '';
        $port = $_ENV['REDIS_PORT'] ?? getenv('REDIS_PORT') ?: '';
        self::assertIsString($host);
        self::assertIsNumeric($port);

        $observer = new \Redis();
        self::assertTrue($observer->connect($host, (int) $port, 1.5));
        self::assertTrue($observer->select(1));

        $key = $this->prefix . 'url-database-check';
        $url = sprintf('redis://%s:%d/1', $host, (int) $port);
        $urlDao = new SaTokenDaoRedis($url);

        try {
            $urlDao->set($key, 'selected-db', 60);
            $this->assertSame('selected-db', $observer->get($key));
            $this->assertSame(0, $this->redis->exists($key));
        } finally {
            $observer->del([$key]);
            $observer->close();
        }
    }

    public function testSeparateRedisUsesConfiguredDatabase(): void
    {
        $host = $_ENV['REDIS_HOST'] ?? getenv('REDIS_HOST') ?: '';
        $port = $_ENV['REDIS_PORT'] ?? getenv('REDIS_PORT') ?: '';
        self::assertIsString($host);
        self::assertIsNumeric($port);

        $observer = new \Redis();
        self::assertTrue($observer->connect($host, (int) $port, 1.5));
        self::assertTrue($observer->select(1));

        $key = $this->prefix . 'separate-db-check';
        $dao = SaTokenDaoRedis::createWithSeparateRedis(
            ['host' => $host, 'port' => (int) $port, 'database' => 0],
            ['host' => $host, 'port' => (int) $port, 'db' => 1]
        );

        try {
            $dao->set($key, 'separate-db', 60);
            $this->assertSame('separate-db', $observer->get($key));
            $this->assertSame(0, $this->redis->exists($key));
        } finally {
            $observer->del([$key]);
            $observer->close();
        }
    }

    public function testIncrementAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $key = $this->prefix . 'counter';

        // 首次递增即带 TTL（Lua INCRBY + EXPIRE 原子）
        $this->assertSame(1, $this->dao->increment($key, 1, 60));
        $this->assertSame(2, $this->dao->increment($key, 1, 60));
        $this->assertSame(7, $this->dao->increment($key, 5, 60));

        $ttl = $this->dao->getTimeout($key);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(60, $ttl);

        // 负数修正
        $this->assertSame(0, $this->dao->increment($key, -7, 60));
        $this->assertSame(0, $this->dao->increment($key, -10, 60));
        $this->assertGreaterThan(0, $this->dao->getTimeout($key));

        // 无 TTL 分支
        $key2 = $this->prefix . 'counter-permanent';
        $this->assertSame(1, $this->dao->increment($key2, 1, null));
        $this->assertSame(-1, $this->dao->getTimeout($key2));
        $this->assertSame(3, $this->dao->increment($key2, 2, null));

        // A timeout applies only when increment creates the key; an existing
        // permanent counter must remain permanent when a later caller passes one.
        $this->assertSame(4, $this->dao->increment($key2, 1, 60));
        $this->assertSame(-1, $this->dao->getTimeout($key2));

        // Negative adjustments clamp at zero consistently with the memory and
        // file adapters, while retaining a permanent counter's TTL semantics.
        $this->assertSame(0, $this->dao->increment($key2, -10, null));
        $this->assertSame(-1, $this->dao->getTimeout($key2));
    }

    public function testSearchKeysAgainstRealRedis(): void
    {
        $this->assertInstanceOf(SaTokenDaoRedis::class, $this->dao);

        $this->dao->set($this->prefix . 'token:aaa', '1', 60);
        $this->dao->set($this->prefix . 'token:bbb', '2', 60);
        $this->dao->set($this->prefix . 'other:ccc', '3', 60);

        $keys = $this->dao->searchKeys($this->prefix . 'token:', '', 0, 10);
        $this->assertCount(2, $keys);
        foreach ($keys as $k) {
            $this->assertStringStartsWith($this->prefix . 'token:', $k);
        }

        // 关键字含 glob 元字符时按字面匹配（转义生效）
        $literal = $this->dao->searchKeys($this->prefix, 'token:aaa', 0, 10);
        $this->assertCount(1, $literal);
    }

    public function testSearchTreatsGlobCharactersInPrefixLiterallyAgainstRealRedis(): void
    {
        $literalPrefix = $this->prefix . 'literal*:scope:';
        $matchingKey = $literalPrefix . 'expected';
        $neighborKey = $this->prefix . 'literal-other:scope:unexpected';
        $this->dao->set($matchingKey, 'matching-value', 60);
        $this->dao->set($neighborKey, 'neighbor-value', 60);

        self::assertSame([$matchingKey], $this->dao->searchKeys($literalPrefix, '', 0, 10));
        self::assertSame(['matching-value'], $this->dao->search($literalPrefix, '', 0, 10));
    }

    public function testLoginConcurrentLockAgainstRealRedis(): void
    {
        // 全链路：真实 Redis 上登录锁 SET NX + 释放 Lua 脚本
        \SaToken\SaToken::reset();
        \SaToken\SaToken::setConfig(new \SaToken\Config\SaTokenConfig([
            'tokenName'    => 'satoken',
            'timeout'      => 300,
            'jwtSecretKey' => 'real-redis-test-jwt-secret-32-bytes',
            'aesKey'       => str_repeat('k', 32),
            'tokenEncrypt' => true,
        ]));
        \SaToken\SaToken::setDao($this->dao);

        $result1 = \SaToken\StpUtil::login(90001);
        $this->assertNotEmpty($result1->getAccessToken());
        // 同账号连续第二次登录（锁已释放）必须成功
        $result2 = \SaToken\StpUtil::login(90001);
        $this->assertNotEquals($result1->getAccessToken(), $result2->getAccessToken());

        // isShare 同端语义下第二次登录替换旧 token：新 token 有效
        $this->assertTrue(\SaToken\StpUtil::getStpLogic()->getTokenManager()->isTokenValid($result2->getAccessToken()));
        $this->assertFalse(\SaToken\StpUtil::getStpLogic()->getTokenManager()->isTokenValid($result1->getAccessToken()));

        \SaToken\SaToken::reset();
    }
}
