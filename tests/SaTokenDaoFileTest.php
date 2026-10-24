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
