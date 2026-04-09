<?php

/**
 * 自动从 git tag 和 commit 生成 CHANGELOG.md
 *
 * 用法: php scripts/changelog.php [--from <tag>] [--to <tag>]
 *
 * 约定式提交格式:
 *   feat:     → 新增
 *   fix:      → 修复
 *   refactor: → 变更
 *   perf:     → 变更
 *   chore:    → 变更（内部）
 *   ci:       → 变更（CI）
 *   docs:     → 文档
 *   test:     → 测试
 *   style:    → 忽略
 */

$root = dirname(__DIR__);
chdir($root);

$options = parseArgs($argv);
$fromTag = $options['from'] ?? null;
$toTag   = $options['to'] ?? null;

$tags = getTags();

if (empty($tags)) {
    echo "未找到任何 git tag，请先创建 tag\n";
    exit(1);
}

// 确定版本范围
if ($fromTag !== null && $toTag !== null) {
    $ranges = [["$fromTag..$toTag", $toTag, getTagDate($toTag)]];
} else {
    $ranges = buildRanges($tags);
}

$sections = [
    'feat'     => '新增',
    'fix'      => '修复',
    'refactor' => '变更',
    'perf'     => '变更',
    'chore'    => '变更',
    'ci'       => '变更',
    'docs'     => '文档',
    'test'     => '测试',
];

$sectionOrder = ['修复', '新增', '变更', '文档', '测试'];
$sectionIcons = [
    '修复' => '### 修复',
    '新增' => '### 新增',
    '变更' => '### 变更',
    '文档' => '### 文档',
    '测试' => '### 测试',
];

$output = "# 变更日志\n\n本文件由脚本自动生成，基于 git tag 和 commit 记录。\n\n";
$links = [];

foreach ($ranges as [$range, $version, $date]) {
    $commits = getCommits($range);
    $grouped = groupCommits($commits, $sections);

    $dateStr = $date ? $date->format('Y-m-d') : '';
    $output .= "## [$version]" . ($dateStr ? " - $dateStr" : '') . "\n\n";

    $hasContent = false;
    foreach ($sectionOrder as $sectionName) {
        if (!isset($grouped[$sectionName]) || empty($grouped[$sectionName])) {
            continue;
        }
        $output .= $sectionIcons[$sectionName] . "\n";
        foreach ($grouped[$sectionName] as $entry) {
            $output .= "- $entry\n";
        }
        $output .= "\n";
        $hasContent = true;
    }

    if (!$hasContent) {
        $output .= "_无显著变更_\n\n";
    }
}

// 生成比较链接
$output .= generateLinks($tags);

file_put_contents("$root/CHANGELOG.md", $output);
echo "CHANGELOG.md 已生成\n";

// ============ 函数 ============

function parseArgs(array $argv): array
{
    $opts = [];
    for ($i = 1; $i < count($argv); $i++) {
        if ($argv[$i] === '--from' && isset($argv[$i + 1])) {
            $opts['from'] = $argv[++$i];
        } elseif ($argv[$i] === '--to' && isset($argv[$i + 1])) {
            $opts['to'] = $argv[++$i];
        }
    }
    return $opts;
}

function getTags(): array
{
    $output = [];
    exec('git tag -l', $output);
    $tags = array_filter($output);

    // 语义化版本排序
    usort($tags, function ($a, $b) {
        return version_compare(ltrim($a, 'v'), ltrim($b, 'v'));
    });

    return $tags;
}

function getTagDate(string $tag): ?DateTime
{
    $output = [];
    exec("git log -1 --format=%ai " . escapeshellarg($tag), $output);
    if (!empty($output[0])) {
        return new DateTime(trim($output[0]));
    }
    return null;
}

function buildRanges(array $tags): array
{
    $ranges = [];

    // 只列出已发布 tag
    for ($i = count($tags) - 1; $i >= 0; $i--) {
        $tag = $tags[$i];
        $from = $i > 0 ? $tags[$i - 1] : null;
        $range = $from ? "$from..$tag" : $tag;
        $ranges[] = [$range, $tag, getTagDate($tag)];
    }

    return $ranges;
}

function getCommits(string $range): array
{
    $output = [];
    exec("git log --no-merges --format=%s " . escapeshellarg($range), $output);
    return array_filter($output);
}

function groupCommits(array $commits, array $sections): array
{
    $grouped = [];

    foreach ($commits as $msg) {
        $parsed = parseCommit($msg);
        $type = $parsed['type'];
        $text = $parsed['text'];

        if (!isset($sections[$type])) {
            $sectionName = '变更';
        } else {
            $sectionName = $sections[$type];
        }

        if ($type === 'style') {
            continue; // 忽略纯格式变更
        }

        if (!isset($grouped[$sectionName])) {
            $grouped[$sectionName] = [];
        }
        $grouped[$sectionName][] = $text;
    }

    // 去重
    foreach ($grouped as &$items) {
        $items = array_values(array_unique($items));
    }

    return $grouped;
}

function parseCommit(string $msg): array
{
    // 约定式提交: type(scope): description
    // 也支持 emoji 格式: type: :emoji: description
    if (preg_match('/^(\w+)(?:\(([^)]+)\))?:\s*(.+)$/u', $msg, $m)) {
        $type = strtolower($m[1]);
        $scope = $m[2] ?? '';
        $desc = $m[3];

        // 去除 emoji 前缀
        $desc = preg_replace('/^:[\w-]+:\s*/u', '', $desc);

        // 如果有 scope，附加到描述
        if ($scope !== '') {
            $desc = "($scope) $desc";
        }

        return ['type' => $type, 'text' => $desc];
    }

    // 非约定式提交，归为变更
    return ['type' => 'chore', 'text' => $msg];
}

function generateLinks(array $tags): string
{
    $repo = getRepoUrl();
    if (!$repo) {
        return '';
    }

    $links = "\n";

    // 已发布 tag
    for ($i = 0; $i < count($tags); $i++) {
        $tag = $tags[$i];
        if ($i === 0) {
            $links .= "[$tag]: $repo/releases/tag/$tag\n";
        } else {
            $prev = $tags[$i - 1];
            $links .= "[$tag]: $repo/compare/$prev...$tag\n";
        }
    }

    return $links;
}

function getRepoUrl(): ?string
{
    $output = [];
    exec('git remote get-url origin 2>/dev/null', $output);
    if (empty($output[0])) {
        return null;
    }

    $url = trim($output[0]);

    // SSH → HTTPS
    if (preg_match('/git@([^:]+):(.+)\.git$/', $url, $m)) {
        return "https://$m[1]/$m[2]";
    }

    // HTTPS，去掉 .git
    $url = preg_replace('/\.git$/', '', $url);
    return $url;
}
