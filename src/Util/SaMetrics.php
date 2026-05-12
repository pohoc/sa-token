<?php

declare(strict_types=1);

namespace SaToken\Util;

/**
 * Sa-Token 性能指标收集
 */
class SaMetrics
{
    /**
     * @var array<string, array{count: int, totalTime: float, minTime: float, maxTime: float}>
     */
    protected static array $metrics = [];

    /**
     * @var array<string, float>
     */
    protected static array $activeTimers = [];

    /**
     * 开始计时
     *
     * @param string $name 指标名称
     */
    public static function start(string $name): void
    {
        self::$activeTimers[$name] = microtime(true);
    }

    /**
     * 结束计时并记录指标
     *
     * @param string $name 指标名称
     */
    public static function end(string $name): void
    {
        $startTime = self::$activeTimers[$name] ?? null;
        if ($startTime === null) {
            return;
        }

        $duration = microtime(true) - $startTime;
        unset(self::$activeTimers[$name]);

        self::record($name, $duration);
    }

    /**
     * 记录指标
     *
     * @param string $name     指标名称
     * @param float  $duration 耗时（秒）
     */
    public static function record(string $name, float $duration): void
    {
        if (!isset(self::$metrics[$name])) {
            self::$metrics[$name] = [
                'count' => 0,
                'totalTime' => 0.0,
                'minTime' => PHP_FLOAT_MAX,
                'maxTime' => 0.0,
            ];
        }

        $metric = &self::$metrics[$name];
        $metric['count']++;
        $metric['totalTime'] += $duration;
        $metric['minTime'] = min($metric['minTime'], $duration);
        $metric['maxTime'] = max($metric['maxTime'], $duration);
    }

    /**
     * 获取所有指标
     *
     * @return array<string, array{count: int, totalTime: float, minTime: float, maxTime: float, avgTime: float}>
     */
    public static function getAll(): array
    {
        $result = [];
        foreach (self::$metrics as $name => $metric) {
            $result[$name] = [
                'count' => $metric['count'],
                'totalTime' => $metric['totalTime'],
                'minTime' => $metric['minTime'] === PHP_FLOAT_MAX ? 0 : $metric['minTime'],
                'maxTime' => $metric['maxTime'],
                'avgTime' => $metric['count'] > 0 ? $metric['totalTime'] / $metric['count'] : 0,
            ];
        }
        return $result;
    }

    /**
     * 获取单个指标
     *
     * @param  string                                                                                   $name 指标名称
     * @return array{count: int, totalTime: float, minTime: float, maxTime: float, avgTime: float}|null
     */
    public static function get(string $name): ?array
    {
        $all = self::getAll();
        return $all[$name] ?? null;
    }

    /**
     * 重置所有指标
     */
    public static function reset(): void
    {
        self::$metrics = [];
        self::$activeTimers = [];
    }
}
