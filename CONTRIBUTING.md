# Contributing

Thank you for your interest in contributing to `sa-token`!

## Development Setup

```bash
git clone https://github.com/pohoc/sa-token.git
cd sa-token
composer install
```

## Running Tests

```bash
vendor/bin/phpunit
```

## Code Style

This project uses [PHP-CS-Fixer](https://github.com/PHP-CS-Fixer/PHP-CS-Fixer) with the ruleset defined in `.php-cs-fixer.php`.

```bash
# Check
vendor/bin/php-cs-fixer fix --dry-run --diff

# Fix
vendor/bin/php-cs-fixer fix
```

## Static Analysis

This project uses [PHPStan](https://phpstan.org/) at level 5.

```bash
vendor/bin/phpstan analyse
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Ensure tests pass (`vendor/bin/phpunit`)
5. Ensure static analysis passes (`vendor/bin/phpstan analyse`)
6. Ensure code style is consistent (`vendor/bin/php-cs-fixer fix`)
7. Commit with a clear message
8. Open a pull request

## Coding Standards

- PHP 8.1+ compatible
- `declare(strict_types=1)` in every file
- PSR-4 autoloading
- PSR-12 coding style
- Add PHPDoc to public methods

## Security

If you discover a security vulnerability, please follow the instructions in [SECURITY.md](SECURITY.md). **Do not** open a public issue.
