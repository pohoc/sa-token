<?php

declare(strict_types=1);

namespace SaToken\Util;

use SaToken\SaToken;

/**
 * Sa-Token 健康检查工具
 */
class SaHealthCheck
{
    /**
     * 健康检查结果状态码
     */
    public const STATUS_PASS = 'pass';
    public const STATUS_FAIL = 'fail';
    public const STATUS_WARN = 'warn';

    /**
     * 获取完整的健康检查报告
     *
     * @return array{status: string, version: string, checks: array<string, array{status: string, message?: string, data?: mixed}>, metrics?: mixed}
     */
    public static function check(): array
    {
        $checks = [];
        $overallStatus = self::STATUS_PASS;

        // DAO 存储检查
        $daoCheck = self::checkDao();
        $checks['dao'] = $daoCheck;
        if ($daoCheck['status'] === self::STATUS_FAIL) {
            $overallStatus = self::STATUS_FAIL;
        }

        // 配置检查
        $configCheck = self::checkConfig();
        $checks['config'] = $configCheck;
        if ($configCheck['status'] === self::STATUS_FAIL) {
            $overallStatus = self::STATUS_FAIL;
        }

        $result = [
            'status' => $overallStatus,
            'version' => '2.0',
            'checks' => $checks,
        ];

        // 添加性能指标（如果有）
        $metrics = SaMetrics::getAll();
        if (!empty($metrics)) {
            $result['metrics'] = $metrics;
        }

        return $result;
    }

    /**
     * 检查 DAO 存储
     *
     * @return array{status: string, message?: string, data?: mixed}
     */
    protected static function checkDao(): array
    {
        try {
            $dao = SaToken::getDao();

            // 测试写入
            $testKey = 'sa-token:health-check:' . uniqid();
            $dao->set($testKey, 'ok', 60);

            // 测试读取
            $value = $dao->get($testKey);
            if ($value !== 'ok') {
                return [
                    'status' => self::STATUS_FAIL,
                    'message' => 'DAO read mismatch',
                ];
            }

            // 测试删除
            $dao->delete($testKey);

            $daoClass = get_class($dao);

            // 额外检查：对于 Memory DAO 检查前缀索引
            if (method_exists($dao, 'getPrefixIndex')) {
                return [
                    'status' => self::STATUS_PASS,
                    'data' => [
                        'type' => $daoClass,
                        'prefixIndexEnabled' => true,
                    ],
                ];
            }

            return [
                'status' => self::STATUS_PASS,
                'data' => [
                    'type' => $daoClass,
                ],
            ];
        } catch (\Throwable $e) {
            return [
                'status' => self::STATUS_FAIL,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * 检查配置
     *
     * @return array{status: string, message?: string, data?: mixed}
     */
    protected static function checkConfig(): array
    {
        $config = SaToken::getConfig();
        $warnings = [];

        // 检查加密密钥
        if ($config->isTokenEncrypt() && empty($config->getAesKey()) && empty($config->getTokenEncryptKey())) {
            $warnings[] = 'Token encryption enabled but using default key';
        }

        // 检查签名密钥
        if (empty($config->getSignKey())) {
            $warnings[] = 'Using default sign key';
        }

        // 检查签名算法
        if ($config->getSignAlg() === 'md5') {
            $warnings[] = 'Using md5 for signing, consider sha256';
        }

        if (!empty($warnings)) {
            return [
                'status' => self::STATUS_WARN,
                'message' => implode('; ', $warnings),
                'data' => [
                    'tokenEncrypt' => $config->isTokenEncrypt(),
                    'signAlg' => $config->getSignAlg(),
                    'timeout' => $config->getTimeout(),
                ],
            ];
        }

        return [
            'status' => self::STATUS_PASS,
            'data' => [
                'tokenEncrypt' => $config->isTokenEncrypt(),
                'signAlg' => $config->getSignAlg(),
                'timeout' => $config->getTimeout(),
            ],
        ];
    }
}
