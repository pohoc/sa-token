<?php

declare(strict_types=1);

namespace SaToken\Tests;

class TestResponseTracker
{
    /** @var array<string, string> */
    public array $headers = [];

    public ?int $statusCode = null;

    public function header(string $name, string $value): void
    {
        $this->headers[$name] = $value;
    }

    public function status(int $code): void
    {
        $this->statusCode = $code;
    }
}
