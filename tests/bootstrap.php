<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

$rootDir = dirname(__DIR__);
$envFile = $rootDir . '/.env';

if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (is_array($lines)) {
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (str_contains($line, '=')) {
                [$name, $value] = explode('=', $line, 2);
                $name = trim($name);
                $value = trim($value);
                if ($name !== '') {
                    $_ENV[$name] = $value;
                    putenv("$name=$value");
                }
            }
        }
    }
}
