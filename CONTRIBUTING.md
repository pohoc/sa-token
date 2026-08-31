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

## Coverage

Requires Xdebug or PCOV (see composer.json scripts):

```bash
composer coverage   # generates coverage/ (HTML) and coverage.xml (clover)
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

This project uses [PHPStan](https://phpstan.org/) at level `max`.

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

## Release Process

发版受两条硬性门禁约束（v0.2.0 事故后的固化）：

1. **Tag 推送被 Ruleset 拦截**：`v*` tag 指向的提交必须已有 `CI green gate` 检查且结论为 success（即该提交在 main 上跑完整套 CI 并全绿）；同时 v* tag 禁止删除与重指（Packagist 版本不可变）。
2. **Release 流程二次校验**：tag 触发的 release workflow 在创建 Release 前会再验证同一提交的 `CI green gate` 状态。

发版步骤：

```bash
# 1. 推送代码并等待 main 的 PHP CI 全绿（含 CI green gate 检查）
git push origin main
gh run watch   # 或在 Actions 页面确认

# 2. 全绿后打 tag 并推送（触发 Release 流水线）
git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z
```

一次性配置（repo admin）：

```bash
GH_TOKEN=ghp_xxx ./scripts/setup-tag-protection.sh
```
