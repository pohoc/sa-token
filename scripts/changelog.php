<?php

declare(strict_types=1);

/**
 * Archive the curated "Unreleased" section under an existing release tag.
 *
 * Usage: php scripts/changelog.php [--tag <tag>]
 * If --tag is omitted, HEAD must point exactly at a version tag.
 */

$root = dirname(__DIR__);
chdir($root);

$options = parseArgs($argv);
$tag = $options['tag'] ?? getHeadTag();

if ($tag === null) {
    fwrite(STDERR, "无法确定版本 tag。请在 tag checkout 上运行，或使用 --tag vX.Y.Z\n");
    exit(1);
}

if (!preg_match('/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$/', $tag)) {
    fwrite(STDERR, "无效的版本 tag：$tag\n");
    exit(1);
}

$tags = getTags();
if (!in_array($tag, $tags, true)) {
    fwrite(STDERR, "未找到 git tag：$tag\n");
    exit(1);
}

if (!isAncestor($tag, 'HEAD')) {
    fwrite(STDERR, "版本 tag $tag 不在当前提交历史中\n");
    exit(1);
}

$changelogPath = "$root/CHANGELOG.md";
$content = file_get_contents($changelogPath);
if ($content === false) {
    fwrite(STDERR, "无法读取 CHANGELOG.md\n");
    exit(1);
}
if (preg_match('//u', $content) !== 1) {
    fwrite(STDERR, "CHANGELOG.md 不是有效 UTF-8，拒绝改写以避免破坏内容\n");
    exit(1);
}

$lines = preg_split('/\r\n|\n|\r/', rtrim($content, "\r\n")) ?: [];
$notice = '本日志由发布流程维护；归档时保留已有版本记录。';
$previousNotice = '发布时，脚本会将“未发布”条目归档到对应版本；历史版本内容保持不变。';
$lines = array_values(array_filter(
    $lines,
    static fn (string $line): bool =>
        $line !== '本文件由脚本自动生成，基于 git tag 和 commit 记录。'
        && $line !== $notice
        && $line !== $previousNotice
        && !preg_match('/^\[[^\]]+\]:\s+https?:\/\/\S+\s*$/', $line),
));

if (($lines[0] ?? null) !== '# 变更日志') {
    fwrite(STDERR, "CHANGELOG.md 缺少标题 '# 变更日志'\n");
    exit(1);
}

$unreleasedIndex = findHeading($lines, '## 未发布');
$tagHeading = findVersionHeading($lines, $tag);
if ($tagHeading !== null) {
    if ($unreleasedIndex !== null) {
        $unreleasedEnd = count($lines);
        for ($index = $unreleasedIndex + 1; $index < count($lines); $index++) {
            if (str_starts_with($lines[$index], '## ')) {
                $unreleasedEnd = $index;
                break;
            }
        }
        $unreleasedBody = array_slice($lines, $unreleasedIndex + 1, $unreleasedEnd - $unreleasedIndex - 1);
        if (trim(implode("\n", $unreleasedBody)) === '') {
            $lines = array_merge(array_slice($lines, 0, $unreleasedIndex), array_slice($lines, $unreleasedEnd));
        }
    }
} else {
    if ($tag !== end($tags)) {
        fwrite(STDERR, "只能归档最新的版本 tag；最新 tag 为 " . end($tags) . "\n");
        exit(1);
    }

    $historyStart = count($lines);
    $scanStart = $unreleasedIndex === null ? 0 : $unreleasedIndex + 1;
    for ($index = $scanStart; $index < count($lines); $index++) {
        if ($index !== $unreleasedIndex && str_starts_with($lines[$index], '## ')) {
            $historyStart = $index;
            break;
        }
    }

    $unreleased = $unreleasedIndex === null
        ? []
        : array_slice($lines, $unreleasedIndex + 1, $historyStart - $unreleasedIndex - 1);
    $unreleasedText = trim(implode("\n", $unreleased));
    $releaseBody = $unreleasedText === '' ? ['_无显著变更_'] : explode("\n", $unreleasedText);
    $releaseDate = getTagDate($tag);
    $dateSuffix = $releaseDate === null ? '' : " - $releaseDate";
    $prefixEnd = $unreleasedIndex ?? $historyStart;
    $prefix = array_slice($lines, 0, $prefixEnd);

    $lines = array_merge(
        $prefix,
        [''],
        ["## [$tag]$dateSuffix", ''],
        $releaseBody,
        [''],
        array_slice($lines, $historyStart),
    );
}

$title = array_shift($lines);
while (($lines[0] ?? null) === '') {
    array_shift($lines);
}

$output = implode("\n", array_merge([$title, '', $notice, ''], $lines));
$output = rtrim($output) . "\n\n" . generateLinks($tags);

if (file_put_contents($changelogPath, $output) === false) {
    fwrite(STDERR, "无法写入 CHANGELOG.md\n");
    exit(1);
}

echo "CHANGELOG.md 已更新版本 $tag\n";

/** @return array{tag?: string} */
function parseArgs(array $argv): array
{
    $options = [];
    for ($index = 1; $index < count($argv); $index++) {
        if ($argv[$index] === '--tag' && isset($argv[$index + 1])) {
            $options['tag'] = $argv[++$index];
        }
    }

    return $options;
}

function getHeadTag(): ?string
{
    exec('git describe --tags --exact-match HEAD 2>/dev/null', $output, $status);
    return $status === 0 && isset($output[0]) ? trim($output[0]) : null;
}

/** @return list<string> */
function getTags(): array
{
    exec('git tag --list', $output, $status);
    if ($status !== 0) {
        fwrite(STDERR, "无法读取 git tags\n");
        exit(1);
    }

    $tags = array_values(array_filter($output));
    usort($tags, static fn (string $a, string $b): int => version_compare(ltrim($a, 'v'), ltrim($b, 'v')));
    return $tags;
}

function isAncestor(string $commit, string $ref): bool
{
    exec('git merge-base --is-ancestor ' . escapeshellarg($commit) . ' ' . escapeshellarg($ref), $output, $status);
    return $status === 0;
}

function findHeading(array $lines, string $heading): ?int
{
    foreach ($lines as $index => $line) {
        if ($line === $heading) {
            return $index;
        }
    }

    return null;
}

function findVersionHeading(array $lines, string $tag): ?int
{
    $expectedPrefix = "## [$tag]";
    foreach ($lines as $index => $line) {
        if (str_starts_with($line, $expectedPrefix) && preg_match('/^## \[' . preg_quote($tag, '/') . '\](?:\s|$)/', $line)) {
            return $index;
        }
    }

    return null;
}

function getTagDate(string $tag): ?string
{
    exec('git log -1 --format=%cs ' . escapeshellarg($tag), $output, $status);
    return $status === 0 && isset($output[0]) ? trim($output[0]) : null;
}

/** @param list<string> $tags */
function generateLinks(array $tags): string
{
    $repo = getRepoUrl();
    if ($repo === null) {
        return '';
    }

    $links = '';
    foreach ($tags as $index => $tag) {
        if ($index === 0) {
            $links .= "[$tag]: $repo/releases/tag/$tag\n";
            continue;
        }

        $previous = $tags[$index - 1];
        $links .= "[$tag]: $repo/compare/$previous...$tag\n";
    }

    return $links;
}

function getRepoUrl(): ?string
{
    exec('git remote get-url origin 2>/dev/null', $output, $status);
    if ($status !== 0 || !isset($output[0])) {
        return null;
    }

    $url = trim($output[0]);
    if (preg_match('/^git@([^:]+):(.+)\.git$/', $url, $matches)) {
        return "https://$matches[1]/$matches[2]";
    }

    return preg_replace('/\.git$/', '', $url);
}
