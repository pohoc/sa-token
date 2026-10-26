<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoFile;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\StpUtil;

class SaTokenDaoFileTest extends TestCase
{
    protected string $basePath;

    protected SaTokenDaoFile $dao;

    protected function setUp(): void
    {
        $this->basePath = sys_get_temp_dir() . '/sa-token-test-' . bin2hex(random_bytes(4));
        $this->dao = new SaTokenDaoFile(['path' => $this->basePath]);
    }

    protected function tearDown(): void
    {
        // 清理测试目录（结构固定：basePath/{data,locks} 两层）
        @unlink($this->basePath . '/set-result');
        foreach (['data', 'locks'] as $sub) {
            $dir = $this->basePath . '/' . $sub;
            if (!is_dir($dir)) {
                continue;
            }
            foreach (scandir($dir) ?: [] as $file) {
                if (is_file($dir . '/' . $file)) {
                    @unlink($dir . '/' . $file);
                }
            }
            @rmdir($dir);
        }
        @rmdir($this->basePath);
    }

    public function testSetGetDeleteRoundTrip(): void
    {
        $this->dao->set('k:basic', 'value-1', 60);
        $this->assertSame('value-1', $this->dao->get('k:basic'));
        $this->assertTrue($this->dao->exists('k:basic'));

        $ttl = $this->dao->getTimeout('k:basic');
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(60, $ttl);

        $this->dao->delete('k:basic');
        $this->assertNull($this->dao->get('k:basic'));
        $this->assertFalse($this->dao->exists('k:basic'));
        $this->assertSame(-2, $this->dao->getTimeout('k:basic'));
    }

    public function testDeleteRejectsNonRegularRecordInsteadOfReportingSuccess(): void
    {
        $dataFile = (new \ReflectionMethod(SaTokenDaoFile::class, 'dataFile'))
            ->invoke($this->dao, 'blocked-delete');
        self::assertIsString($dataFile);
        self::assertTrue(mkdir($dataFile));

        try {
            $this->expectException(SaTokenException::class);
            $this->expectExceptionMessage('不能是符号链接或非普通文件');
            $this->dao->delete('blocked-delete');
        } finally {
            rmdir($dataFile);
        }
    }

    public function testExistingStorageDirectoriesAreRestricted(): void
    {
        $path = $this->basePath;
        chmod($path . '/data', 0777);
        chmod($path . '/locks', 0777);

        new SaTokenDaoFile(['path' => $path]);

        $this->assertSame(0700, fileperms($path . '/data') & 0777);
        $this->assertSame(0700, fileperms($path . '/locks') & 0777);
    }

    public function testStorageDirectorySymlinkIsRejected(): void
    {
        $path = $this->basePath . '/linked-store';
        $target = $this->basePath . '/external-data';
        mkdir($path);
        mkdir($target);
        symlink($target, $path . '/data');

        try {
            new SaTokenDaoFile(['path' => $path]);
            $this->fail('符号链接存储目录必须拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('不能是符号链接', $e->getMessage());
        } finally {
            unlink($path . '/data');
            rmdir($target);
            rmdir($path);
        }
    }

    public function testStorageRootSymlinkIsRejected(): void
    {
        $path = $this->basePath . '/linked-root';
        $target = $this->basePath . '/external-root';
        mkdir($target . '/data', 0700, true);
        mkdir($target . '/locks', 0700, true);
        symlink($target, $path);

        try {
            new SaTokenDaoFile(['path' => $path]);
            $this->fail('存储根目录为符号链接时必须拒绝');
        } catch (SaTokenException $e) {
            $this->assertStringContainsString('不能是符号链接', $e->getMessage());
        } finally {
            unlink($path);
            rmdir($target . '/data');
            rmdir($target . '/locks');
            rmdir($target);
        }
    }

    public function testBinarySafeValues(): void
    {
        // 加密后的值可能含任意字节，必须 base64 层保证不损坏
        $binary = random_bytes(64) . "\x00\xff 中文";
        $this->dao->set('k:binary', $binary, 60);
        $this->assertSame($binary, $this->dao->get('k:binary'));
    }

    public function testStorageFilesArePrivateOnPosix(): void
    {
        if (DIRECTORY_SEPARATOR !== '/') {
            $this->markTestSkipped('POSIX file mode assertions only apply on Unix-like systems.');
        }

        $this->dao->set('k:private', 'secret', 60);
        $this->dao->setIfNotExists('k:private-lock', 'lock', 60);

        $dataFile = $this->basePath . '/data/' . hash('sha256', 'k:private') . '.dat';
        $lockFile = $this->basePath . '/locks/' . hash('sha256', 'k:private-lock') . '.lock';
        $this->assertSame(0600, fileperms($dataFile) & 0777);
        $this->assertSame(0600, fileperms($lockFile) & 0777);
    }

    public function testDataRecordSymlinkIsRejected(): void
    {
        $key = 'k:symlink-record';
        $target = $this->basePath . '/external-record';
        $payload = json_encode([
            'key' => $key,
            'v' => base64_encode('forged'),
            'e' => null,
        ]);
        self::assertIsString($payload);
        file_put_contents($target, $payload);
        $link = $this->basePath . '/data/' . hash('sha256', $key) . '.dat';
        self::assertTrue(symlink($target, $link));

        try {
            $this->dao->get($key);
            self::fail('数据记录符号链接必须拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('不能是符号链接', $exception->getMessage());
        } finally {
            @unlink($link);
            @unlink($target);
        }
    }

    public function testLockFileSymlinkIsRejectedWithoutChangingTargetPermissions(): void
    {
        if (DIRECTORY_SEPARATOR !== '/') {
            $this->markTestSkipped('Symlink lock protection test requires POSIX filesystem behavior.');
        }

        $key = 'k:symlink-lock';
        $target = $this->basePath . '/external-lock-target';
        file_put_contents($target, 'unrelated file');
        chmod($target, 0644);
        $link = $this->basePath . '/locks/' . hash('sha256', $key) . '.lock';
        self::assertTrue(symlink($target, $link));

        try {
            $this->dao->set($key, 'value');
            self::fail('锁文件符号链接必须拒绝');
        } catch (SaTokenException $exception) {
            self::assertStringContainsString('不能是符号链接', $exception->getMessage());
        } finally {
            @unlink($link);
            self::assertSame(0644, fileperms($target) & 0777);
            @unlink($target);
        }
    }

    public function testPermanentAndExpiry(): void
    {
        $this->dao->set('k:perm', 'forever', null);
        $this->assertSame(-1, $this->dao->getTimeout('k:perm'));

        $this->dao->set('k:exp', 'soon', 1);
        $this->assertGreaterThan(0, $this->dao->getTimeout('k:exp'));
        sleep(2);
        // 惰性过期：读取时删除并返回 null
        $this->assertNull($this->dao->get('k:exp'));
        $this->assertSame(-2, $this->dao->getTimeout('k:exp'));
    }

    public function testExpireAndExpireToPermanent(): void
    {
        $this->dao->set('k:e', 'v', 60);
        $this->dao->expire('k:e', 120);
        $this->assertGreaterThan(60, $this->dao->getTimeout('k:e'));

        $this->dao->expire('k:e', 0);
        $this->assertSame(-1, $this->dao->getTimeout('k:e'));
    }

    public function testExpireDoesNotReviveAnExpiredRecord(): void
    {
        $this->dao->set('k:expired-before-expire', 'stale', 1);
        sleep(2);

        $this->dao->expire('k:expired-before-expire', 120);

        $this->assertNull($this->dao->get('k:expired-before-expire'));
        $this->assertSame(-2, $this->dao->getTimeout('k:expired-before-expire'));
    }

    public function testGetAndDeleteIsAtomicUnderFlock(): void
    {
        $this->dao->set('k:gd', 'v', 60);
        $this->assertSame('v', $this->dao->getAndDelete('k:gd'));
        $this->assertNull($this->dao->get('k:gd'));
        $this->assertNull($this->dao->getAndDelete('k:gd'));
    }

    public function testGetAndDeleteFailsClosedWhenRecordCannotBeRemoved(): void
    {
        $key = 'k:gd-unlink-failure';
        $this->dao->set($key, 'one-time-credential', 60);
        $dao = new class (['path' => $this->basePath]) extends SaTokenDaoFile {
            protected function removeRecordFile(string $key): void
            {
                throw new SaTokenException('simulated unlink failure');
            }
        };

        try {
            $dao->getAndDelete($key);
            self::fail('A one-time credential must not be returned when deletion fails');
        } catch (SaTokenException $exception) {
            self::assertSame('simulated unlink failure', $exception->getMessage());
        }

        self::assertSame('one-time-credential', $this->dao->get($key));
    }

    public function testCompareAndSetDeleteFailsWhenRecordCannotBeRemoved(): void
    {
        $key = 'k:cas-delete-unlink-failure';
        $this->dao->set($key, 'active-marker', 60);
        $dao = new class (['path' => $this->basePath]) extends SaTokenDaoFile {
            protected function removeRecordFile(string $key): void
            {
                throw new SaTokenException('simulated unlink failure');
            }
        };

        try {
            $dao->compareAndSet($key, 'active-marker', null);
            self::fail('CAS deletion must not report success when unlink fails');
        } catch (SaTokenException $exception) {
            self::assertSame('simulated unlink failure', $exception->getMessage());
        }

        self::assertSame('active-marker', $this->dao->get($key));
    }

    public function testExecuteAtomicallyHoldsLockUntilCallbackReturns(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl is required for the multi-process lock test');
        }

        $signalPath = $this->basePath . '/lock-held';
        $eventsPath = $this->basePath . '/lock-events';
        $key = 'psr16-atomic:long-operation';
        $path = $this->basePath;
        $pid = pcntl_fork();
        if ($pid === -1) {
            $this->fail('Could not fork worker process');
        }

        if ($pid === 0) {
            while (!is_file($signalPath)) {
                usleep(1000);
            }
            $childDao = new SaTokenDaoFile(['path' => $path]);
            $childDao->executeAtomically($key, static function () use ($eventsPath): void {
                file_put_contents($eventsPath, "child-entered\n", FILE_APPEND | LOCK_EX);
            });
            exit(0);
        }

        $this->dao->executeAtomically($key, static function () use ($signalPath, $eventsPath): void {
            file_put_contents($eventsPath, "parent-entered\n", FILE_APPEND | LOCK_EX);
            touch($signalPath);
            usleep(250_000);
            file_put_contents($eventsPath, "parent-leaving\n", FILE_APPEND | LOCK_EX);
        });

        $status = 0;
        $this->assertSame($pid, pcntl_waitpid($pid, $status));
        if (!is_int($status)) {
            throw new \RuntimeException('Child process returned an invalid status');
        }
        $this->assertTrue(pcntl_wifexited($status));
        $this->assertSame(0, pcntl_wexitstatus($status));
        $this->assertSame("parent-entered\nparent-leaving\nchild-entered\n", file_get_contents($eventsPath));
    }

    public function testSetWaitsForAtomicReadModifyWriteLock(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl is required for the multi-process lock test');
        }

        $key = 'k:atomic-set';
        $resultPath = $this->basePath . '/set-result';
        $lockPath = $this->basePath . '/locks/' . hash('sha256', $key) . '.lock';
        $lock = fopen($lockPath, 'c');
        $this->assertNotFalse($lock);
        flock($lock, LOCK_EX);

        $dao = $this->dao;
        $pid = pcntl_fork();
        if ($pid === -1) {
            flock($lock, LOCK_UN);
            fclose($lock);
            $this->fail('Could not fork worker process');
        }
        if ($pid === 0) {
            fclose($lock);
            file_put_contents($resultPath, 'started');
            $dao->set($key, 'fresh-value');
            file_put_contents($resultPath, 'done');
            exit(0);
        }

        $deadline = microtime(true) + 1.0;
        while (!is_file($resultPath) && microtime(true) < $deadline) {
            usleep(10000);
        }
        $this->assertSame('started', file_get_contents($resultPath));
        usleep(100000);
        $this->assertSame('started', file_get_contents($resultPath), 'set must block while the key lock is held');

        flock($lock, LOCK_UN);
        fclose($lock);
        $status = 0;
        $this->assertSame($pid, pcntl_waitpid($pid, $status));
        $this->assertSame('done', file_get_contents($resultPath));
        $this->assertSame('fresh-value', $this->dao->get($key));
    }

    public function testCompareAndDeletePreservesAReplacementLock(): void
    {
        $this->dao->set('k:lock', 'new-owner', 60);

        $this->assertFalse($this->dao->compareAndDelete('k:lock', 'old-owner'));
        $this->assertSame('new-owner', $this->dao->get('k:lock'));
        $this->assertTrue($this->dao->compareAndDelete('k:lock', 'new-owner'));
        $this->assertNull($this->dao->get('k:lock'));
    }

    public function testCompareAndExpirePreservesAReplacementLock(): void
    {
        $this->dao->set('k:lock', 'new-owner', 60);

        self::assertFalse($this->dao->compareAndExpire('k:lock', 'old-owner', 120));
        self::assertSame('new-owner', $this->dao->get('k:lock'));
        self::assertTrue($this->dao->compareAndExpire('k:lock', 'new-owner', 120));
        self::assertGreaterThan(0, $this->dao->getTimeout('k:lock'));
        self::assertLessThanOrEqual(120, $this->dao->getTimeout('k:lock'));
    }

    public function testCompareAndExpireNeverShortensAndCanMakeAKeyPermanent(): void
    {
        $this->dao->set('k:session-index', 'value', 120);

        self::assertTrue($this->dao->compareAndExpire('k:session-index', 'value', 30));
        self::assertGreaterThan(30, $this->dao->getTimeout('k:session-index'));
        self::assertTrue($this->dao->compareAndExpire('k:session-index', 'value', -1));
        self::assertSame(-1, $this->dao->getTimeout('k:session-index'));
    }

    public function testCompareAndUpdatePreservesValueAndTtlOnMismatch(): void
    {
        $this->dao->set('k:session', 'old-record', 60);
        $ttl = $this->dao->getTimeout('k:session');
        self::assertFalse($this->dao->compareAndUpdate('k:session', 'stale-record', 'wrong'));
        self::assertSame('old-record', $this->dao->get('k:session'));
        self::assertTrue($this->dao->compareAndUpdate('k:session', 'old-record', 'new-record'));
        self::assertSame('new-record', $this->dao->get('k:session'));
        self::assertLessThanOrEqual($ttl, $this->dao->getTimeout('k:session'));
    }

    public function testSetIfNotExistsUnderFlock(): void
    {
        $this->assertTrue($this->dao->setIfNotExists('k:nx', 'a', 30));
        $this->assertFalse($this->dao->setIfNotExists('k:nx', 'b', 30));
        $this->assertSame('a', $this->dao->get('k:nx'));

        // TTL 到期后可再次获取
        $this->dao->expire('k:nx', 1);
        sleep(2);
        $this->assertTrue($this->dao->setIfNotExists('k:nx', 'c', 30));
        $this->assertSame('c', $this->dao->get('k:nx'));
    }

    public function testIncrementUnderFlock(): void
    {
        $this->assertSame(1, $this->dao->increment('k:cnt', 1, 60));
        $this->assertSame(2, $this->dao->increment('k:cnt', 1, 60));
        $this->assertSame(6, $this->dao->increment('k:cnt', 4, 60));
        // TTL 仅在首次创建时生效
        $this->assertGreaterThan(0, $this->dao->getTimeout('k:cnt'));
        // 负数修正
        $this->assertSame(0, $this->dao->increment('k:cnt', -10, 60));
        // 永不过期分支
        $this->assertSame(1, $this->dao->increment('k:perm', 1, null));
        $this->assertSame(-1, $this->dao->getTimeout('k:perm'));
    }

    public function testSearchAndSearchKeys(): void
    {
        $this->dao->set('satoken:login:token:aaa', 'v1', 60);
        $this->dao->set('satoken:login:token:bbb', 'v2', 60);
        $this->dao->set('satoken:other:ccc', 'v3', 60);

        $keys = $this->dao->searchKeys('satoken:login:token:', '', 0, 10);
        $this->assertCount(2, $keys);
        sort($keys);
        $this->assertSame('satoken:login:token:aaa', $keys[0]);

        $values = $this->dao->search('satoken:login:token:', 'bbb', 0, 10);
        $this->assertSame(['v2'], $values);

        // 过期记录被扫描清理
        $this->dao->set('satoken:login:token:dead', 'x', 1);
        sleep(2);
        $this->dao->searchKeys('satoken:login:token:', '', 0, 10);
        $this->assertNull($this->dao->get('satoken:login:token:dead'));
    }

    public function testPersistenceAcrossInstances(): void
    {
        $this->dao->set('k:persist', 'survives', 60);

        // 新实例读取同一目录：数据仍然在（文件存储的核心价值）
        $dao2 = new SaTokenDaoFile(['path' => $this->basePath]);
        $this->assertSame('survives', $dao2->get('k:persist'));
        $this->assertTrue($dao2->exists('k:persist'));
    }

    public function testCorruptedRecordTreatedAsMissing(): void
    {
        $this->dao->set('k:corrupt', 'v', 60);
        // 手工破坏数据文件
        $hash = hash('sha256', 'k:corrupt');
        file_put_contents($this->basePath . '/data/' . $hash . '.dat', 'garbage-not-json');

        $this->assertNull($this->dao->get('k:corrupt'));
        $this->assertFalse($this->dao->exists('k:corrupt'));
    }

    public function testCorruptedExpiryAndMismatchedKeyAreTreatedAsMissing(): void
    {
        foreach ([
            'k:corrupt-expiry' => ['key' => 'k:corrupt-expiry', 'v' => base64_encode('value'), 'e' => 'invalid'],
            'k:mismatched-key' => ['key' => 'another-key', 'v' => base64_encode('value'), 'e' => null],
            'k:missing-expiry' => ['key' => 'k:missing-expiry', 'v' => base64_encode('value')],
        ] as $key => $record) {
            $path = $this->basePath . '/data/' . hash('sha256', $key) . '.dat';
            file_put_contents($path, json_encode($record) ?: '{}');

            $this->assertNull($this->dao->get($key));
            $this->assertFileDoesNotExist($path);
        }
    }

    public function testSizeAndDeleteMultiple(): void
    {
        $this->dao->set('k:m1', '1', 60);
        $this->dao->set('k:m2', '2', 60);
        $this->dao->set('k:m3', '3', 60);

        $this->assertSame(3, $this->dao->size());

        $this->dao->deleteMultiple(['k:m1', 'k:m2']);
        $this->assertNull($this->dao->get('k:m1'));
        $this->assertNull($this->dao->get('k:m2'));
        $this->assertSame(1, $this->dao->size());
    }

    public function testStorageConfigAutoAssembly(): void
    {
        // storage.type=file 配置驱动装配：init 后无需手动 setDao
        SaToken::reset();
        $path = $this->basePath . '-cfg';
        SaToken::init([
            'tokenName' => 'satoken',
            'timeout'   => 300,
            'aesKey'    => str_repeat('k', 32),
            'storage'   => ['type' => 'file', 'path' => $path],
        ]);

        $this->assertInstanceOf(SaTokenDaoFile::class, SaToken::getDao());

        // 全链路：登录/校验/注销落在文件存储上
        $result = StpUtil::login(70001);
        $token = $result->getAccessToken();

        // 模拟客户端携带 token 的请求上下文
        \SaToken\Util\SaTokenContext::setRequest(new class ($token) {
            public function __construct(private string $t)
            {
            }

            public function getHeaderLine(string $name): string
            {
                return strtolower($name) === 'satoken' ? $this->t : '';
            }

            public function getMethod(): string
            {
                return 'GET';
            }
        });
        StpUtil::checkLogin();

        $dao = SaToken::getDao();
        $this->assertTrue($dao->exists('satoken:login:token:' . $token));

        StpUtil::logout();
        $this->assertFalse(StpUtil::isLogin());

        SaToken::reset();
    }
}
