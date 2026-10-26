<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Dao\SaTokenDaoInterface;
use SaToken\SaToken;
use SaToken\Util\SaHealthCheck;

class SaHealthCheckTest extends TestCase
{
    protected function setUp(): void
    {
        SaToken::reset();
    }

    protected function tearDown(): void
    {
        SaToken::reset();
    }

    public function testDaoFailureDoesNotExposeDriverExceptionDetails(): void
    {
        $secretConnectionDetails = 'redis://internal-user:top-secret@redis.internal:6379/4';
        $dao = $this->createMock(SaTokenDaoInterface::class);
        $dao->method('set')->willThrowException(new \RuntimeException($secretConnectionDetails));
        SaToken::setDao($dao);

        $report = SaHealthCheck::check();

        self::assertSame(SaHealthCheck::STATUS_FAIL, $report['checks']['dao']['status']);
        self::assertSame('DAO check failed', $report['checks']['dao']['message'] ?? null);
        self::assertStringNotContainsString($secretConnectionDetails, json_encode($report) ?: '');
    }
}
