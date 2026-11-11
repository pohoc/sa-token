<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;

class ChangelogGenerationTest extends TestCase
{
    private string $repository;

    protected function setUp(): void
    {
        $this->repository = sys_get_temp_dir() . '/sa-token-changelog-' . bin2hex(random_bytes(8));
        mkdir($this->repository . '/scripts', 0777, true);
        copy(dirname(__DIR__) . '/scripts/changelog.php', $this->repository . '/scripts/changelog.php');

        $this->runCommand('git init -q');
        $this->runCommand('git config user.name "Sa-Token Test"');
        $this->runCommand('git config user.email "test@example.invalid"');
        file_put_contents(
            $this->repository . '/CHANGELOG.md',
            "# 变更日志\n\n本日志由发布流程维护。\n\n## 未发布\n\n### 变更\n- 手工内容不应成为版本日志来源\n\n## [v0.3.0] - 2026-10-27\n\n旧版本说明。\n",
        );
        $this->runCommand('git add CHANGELOG.md scripts/changelog.php');
        $this->runCommand('git commit -qm "release: seed fixture"');
        $this->runCommand('git -c tag.gpgSign=false tag v0.3.0');
    }

    protected function tearDown(): void
    {
        if (!isset($this->repository) || !is_dir($this->repository)) {
            return;
        }

        $this->removeDirectory($this->repository);
    }

    public function testGeneratesReleaseNotesFromUserFacingConventionalCommits(): void
    {
        $this->commit('feat(session): ✨ add rotation support');
        $this->commit('fix(auth): 🐛 reject invalid credentials');
        $this->commit('docs(readme): 📝 clarify migration steps');
        $this->commit('docs(changelog): 📝 internal release wording');
        $this->commit('ci(release): 🎡 tune workflow');
        $this->runCommand('git -c tag.gpgSign=false tag v0.3.1');

        $this->runCommand('php scripts/changelog.php --tag v0.3.1');
        $changelog = file_get_contents($this->repository . '/CHANGELOG.md');
        self::assertIsString($changelog);
        self::assertStringContainsString('## [v0.3.1]', $changelog);
        self::assertStringContainsString('### 新增', $changelog);
        self::assertStringContainsString('- (feat/session) ✨ add rotation support', $changelog);
        self::assertStringContainsString('### 修复', $changelog);
        self::assertStringContainsString('- (fix/auth) 🐛 reject invalid credentials', $changelog);
        self::assertStringContainsString('- (docs/readme) 📝 clarify migration steps', $changelog);
        self::assertStringNotContainsString('未发布', $changelog);
        self::assertStringNotContainsString('手工内容', $changelog);
        self::assertStringNotContainsString('internal release wording', $changelog);
        self::assertStringNotContainsString('tune workflow', $changelog);
    }

    private function commit(string $subject): void
    {
        file_put_contents($this->repository . '/change.txt', $subject . "\n", FILE_APPEND);
        $this->runCommand('git add change.txt');
        $this->runCommand('git commit -qm ' . escapeshellarg($subject));
    }

    private function runCommand(string $command): string
    {
        exec('cd ' . escapeshellarg($this->repository) . ' && ' . $command . ' 2>&1', $output, $status);
        self::assertSame(0, $status, implode("\n", $output));
        return implode("\n", $output);
    }

    private function removeDirectory(string $directory): void
    {
        foreach (new \DirectoryIterator($directory) as $item) {
            if ($item->isDot()) {
                continue;
            }

            $path = $item->getPathname();
            if ($item->isDir() && !$item->isLink()) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }
        rmdir($directory);
    }
}
