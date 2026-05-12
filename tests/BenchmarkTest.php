<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\Util\SaHealthCheck;

/**
 * 性能基准测试
 */
class BenchmarkTest extends TestCase
{
    protected StpLogic $stp;
    protected SaTokenDaoMemory $dao;

    protected function setUp(): void
    {
        SaToken::reset();
        $config = new SaTokenConfig([
            'tokenName' => 'satoken',
            'timeout' => 86400,
            'tokenStyle' => 'uuid',
            'concurrent' => true,
            'maxLoginCount' => 100,
        ]);
        SaToken::setConfig($config);
        $this->dao = new SaTokenDaoMemory();
        SaToken::setDao($this->dao);
        $this->stp = new StpLogic('login');
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    /**
     * 基准：登录操作（1000次）
     *
     * @testdox Benchmark: Login 1000 times
     */
    public function testBenchmarkLogin(): void
    {
        $iterations = 1000;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $this->stp->login($i + 1);
        }

        $duration = microtime(true) - $start;
        $opsPerSec = $iterations / $duration;

        $this->assertGreaterThan(0, $duration);

        echo "Login benchmark: {$iterations} operations in " . number_format($duration, 4) . 's, ' . number_format($opsPerSec, 2) . " ops/s\n";

        $this->assertLessThan(10, $duration);
    }

    /**
     * 基准：检查登录（10000次）
     *
     * @testdox Benchmark: CheckLogin 10000 times
     */
    public function testBenchmarkCheckLogin(): void
    {
        $loginId = 1001;
        $result = $this->stp->login($loginId);
        $token = $result->getAccessToken();
        $manager = new \SaToken\TokenManager();

        $iterations = 10000;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $manager->getLoginIdByToken($token);
        }

        $duration = microtime(true) - $start;
        $opsPerSec = $iterations / $duration;

        echo "CheckLogin benchmark: {$iterations} operations in " . number_format($duration, 4) . 's, ' . number_format($opsPerSec, 2) . " ops/s\n";

        $this->assertLessThan(10, $duration);
    }

    /**
     * 基准：搜索操作（1000次）
     *
     * @testdox Benchmark: Search 1000 times with prefix index
     */
    public function testBenchmarkSearch(): void
    {
        $loginId = 2001;

        for ($i = 0; $i < 100; $i++) {
            $this->stp->login($loginId + $i);
        }

        $iterations = 1000;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $this->dao->search('sa-token:login:token:', '', 0, 100);
        }

        $duration = microtime(true) - $start;
        $opsPerSec = $iterations / $duration;

        echo "Search benchmark: {$iterations} operations in " . number_format($duration, 4) . 's, ' . number_format($opsPerSec, 2) . " ops/s\n";

        $this->assertLessThan(10, $duration);
    }

    /**
     * 基准：健康检查
     *
     * @testdox Benchmark: Health check 100 times
     */
    public function testBenchmarkHealthCheck(): void
    {
        $iterations = 100;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            SaHealthCheck::check();
        }

        $duration = microtime(true) - $start;
        $opsPerSec = $iterations / $duration;

        echo "HealthCheck benchmark: {$iterations} operations in " . number_format($duration, 4) . 's, ' . number_format($opsPerSec, 2) . " ops/s\n";

        $this->assertLessThan(2, $duration);
    }

    /**
     * 基准：批量删除
     *
     * @testdox Benchmark: Batch delete 100 tokens
     */
    public function testBenchmarkBatchDelete(): void
    {
        $loginId = 3001;

        for ($i = 0; $i < 100; $i++) {
            $this->stp->login($loginId + $i);
        }

        $iterations = 10;
        $start = microtime(true);

        for ($i = 0; $i < $iterations; $i++) {
            $this->stp->logoutByLoginId($loginId + $i);
        }

        $duration = microtime(true) - $start;

        echo "BatchDelete benchmark: {$iterations} operations in " . number_format($duration, 4) . "s\n";

        $this->assertLessThan(5, $duration);
    }
}
