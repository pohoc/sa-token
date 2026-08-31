<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Action\SaTokenActionInterface;
use SaToken\Auth\SaHttpAuth;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoInterface;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\Listener\SaTokenEvent;
use SaToken\Listener\SaTokenListenerInterface;
use SaToken\Sign\SaSign;

/**
 * Sa-Token 核心入口类
 *
 * 管理全局配置、上下文和容器，是整个框架的核心管理器
 *
 * 使用示例：
 *   // 自动加载配置
 *   SaToken::init();
 *
 *   // 手动传入配置
 *   SaToken::init(['tokenName' => 'my-token', 'timeout' => 7200]);
 *
 *   // 获取配置
 *   $config = SaToken::getConfig();
 */
class SaToken
{
    /**
     * 全局配置实例
     * @var SaTokenConfig|null
     */
    protected static ?SaTokenConfig $config = null;

    /**
     * 存储层实例
     * @var SaTokenDaoInterface|null
     */
    protected static ?SaTokenDaoInterface $dao = null;

    /**
     * 事件分发器
     * @var SaTokenEvent|null
     */
    protected static ?SaTokenEvent $event = null;

    /**
     * StpLogic 实例池（多账号体系）
     * @var array<string, StpLogic>
     */
    protected static array $stpLogicMap = [];

    /**
     * 业务行为接口实例
     * @var SaTokenActionInterface|null
     */
    protected static ?SaTokenActionInterface $action = null;

    /**
     * 是否已初始化
     * @var bool
     */
    protected static bool $initialized = false;

    protected static ?SaHttpAuth $httpAuth = null;

    protected static ?Auth\SaApiKey $apiKey = null;

    protected static ?SaSign $sign = null;

    protected static ?Middleware\SaGlobalFilter $globalFilter = null;

    /**
     * 初始化 Sa-Token
     /**
     * @param array<string, mixed>|SaTokenConfig|null $config
     */
    public static function init(array|SaTokenConfig|null $config = null): void
    {
        if ($config instanceof SaTokenConfig) {
            self::$config = $config;
        } elseif (is_array($config)) {
            /** @var array<string, mixed> $config */
            self::$config = new SaTokenConfig($config);
        } else {
            self::$config = self::loadConfigFile();
        }

        if (self::$event === null) {
            self::$event = new SaTokenEvent();
        }

        $config = self::$config ?? self::getConfig();
        \SaToken\Security\SaAuditLog::setEnabled($config->isAuditLog());
        \SaToken\Security\SaAuditLog::setMaxEntries($config->getAuditLogMaxEntries());
        \SaToken\Security\SaAuditLog::setTtlDays($config->getAuditLogTtlDays());

        self::$stpLogicMap = [];

        // storage 配置自动装配存储层：仅在未显式 setDao 时生效，
        // 保证代码内 setDao(new RedisDao(...)) 的优先级高于配置文件
        if (self::$dao === null) {
            self::$dao = self::buildDaoFromStorageConfig($config);
        }

        // 配置热更新时必须同步废弃已固化的单例：
        // getSign()/getApiKey() 等在首次调用时把当时的密钥/头名固定进实例，
        // 不清理的话轮换 signKey 后旧密钥仍然有效（泄露的密钥无法通过 init 轮换）
        self::$sign = null;
        self::$apiKey = null;
        self::$globalFilter = null;
        self::$httpAuth = null;

        self::$initialized = true;
    }

    /**
     * 根据 storage 配置构造存储层（memory / file / redis）
     *
     * @param  SaTokenConfig       $config
     * @return SaTokenDaoInterface
     */
    protected static function buildDaoFromStorageConfig(SaTokenConfig $config): SaTokenDaoInterface
    {
        $storage = $config->getStorage();
        $type = $storage['type'] ?? 'memory';
        $type = is_string($type) ? strtolower($type) : 'memory';

        switch ($type) {
            case 'file':
                /** @var array<string, mixed> $fileConfig */
                $fileConfig = array_diff_key($storage, ['type' => true]);
                return new \SaToken\Dao\SaTokenDaoFile($fileConfig);

            case 'redis':
                if (!class_exists(\Redis::class)) {
                    throw new \SaToken\Exception\SaTokenException('storage.type=redis 需要 ext-redis 扩展');
                }
                /** @var array<string, mixed> $redisConfig */
                $redisConfig = array_diff_key($storage, ['type' => true]);
                return new \SaToken\Dao\SaTokenDaoRedis($redisConfig);

            case 'memory':
            default:
                if ($type !== 'memory') {
                    trigger_error("Sa-Token: 未知的 storage.type '{$type}'，已回退为 memory 存储", E_USER_WARNING);
                }
                return new SaTokenDaoMemory();
        }
    }

    /**
     * 从文件加载配置
     *
     * 依次扫描以下路径寻找 config/sa_token.php：
     * 1. 当前工作目录/config/sa_token.php
     * 2. 项目根目录（composer.json 所在目录）/config/sa_token.php
     *
     * @return SaTokenConfig
     */
    protected static function loadConfigFile(): SaTokenConfig
    {
        $paths = [
            getcwd() . '/config/sa_token.php',
            self::getProjectRoot() . '/config/sa_token.php',
        ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                $config = require $path;
                if (!is_array($config)) {
                    trigger_error("Sa-Token: 配置文件 {$path} 返回值不是数组，已忽略该文件并使用默认配置", E_USER_WARNING);
                    continue;
                }
                /** @var array<string, mixed> $config */
                return new SaTokenConfig($config);
            }
        }

        return new SaTokenConfig();
    }

    /**
     * 获取项目根目录（composer.json 所在目录）
     *
     * @return string
     */
    protected static function getProjectRoot(): string
    {
        // 从当前文件向上查找 composer.json
        $dir = dirname(__DIR__);
        while ($dir !== '/') {
            if (file_exists($dir . '/composer.json')) {
                return $dir;
            }
            $dir = dirname($dir);
        }
        return getcwd() ?: '/';
    }

    /**
     * 获取配置实例
     *
     * @return SaTokenConfig
     * @throws SaTokenException 未初始化时
     */
    public static function getConfig(): SaTokenConfig
    {
        if (self::$config === null) {
            self::init();
        }
        if (self::$config === null) {
            self::$config = new SaTokenConfig();
        }
        return self::$config;
    }

    /**
     * 设置配置实例
     *
     * @param  SaTokenConfig $config 配置实例
     * @return void
     */
    public static function setConfig(SaTokenConfig $config): void
    {
        self::$config = $config;
    }

    /**
     * 获取存储层实例
     *
     * @return SaTokenDaoInterface
     */
    public static function getDao(): SaTokenDaoInterface
    {
        if (self::$dao !== null) {
            return self::$dao;
        }
        self::$dao = new SaTokenDaoMemory();
        return self::$dao;
    }

    /**
     * 设置存储层实例
     *
     * @param  SaTokenDaoInterface $dao 存储层实例
     * @return void
     */
    public static function setDao(SaTokenDaoInterface $dao): void
    {
        self::$dao = $dao;
    }

    /**
     * 获取事件分发器
     *
     * @return SaTokenEvent
     */
    public static function getEvent(): SaTokenEvent
    {
        if (self::$event === null) {
            self::$event = new SaTokenEvent();
        }
        return self::$event;
    }

    /**
     * 添加事件监听器
     *
     * @param  SaTokenListenerInterface $listener 事件监听器
     * @return void
     */
    public static function addListener(SaTokenListenerInterface $listener): void
    {
        self::getEvent()->addListener($listener);
    }

    /**
     * 获取业务行为接口实例
     *
     * @return SaTokenActionInterface|null
     */
    public static function getAction(): ?SaTokenActionInterface
    {
        return self::$action;
    }

    /**
     * 设置业务行为接口实例
     *
     * @param  SaTokenActionInterface|null $action 业务行为接口实例
     * @return void
     */
    public static function setAction(?SaTokenActionInterface $action): void
    {
        self::$action = $action;
    }

    public static function getHttpAuth(): SaHttpAuth
    {
        if (self::$httpAuth === null) {
            self::$httpAuth = new SaHttpAuth();
        }
        return self::$httpAuth;
    }

    public static function getApiKey(): Auth\SaApiKey
    {
        if (self::$apiKey === null) {
            $config = self::getConfig();
            self::$apiKey = new Auth\SaApiKey([
                'headerName'       => $config->getApiKeyHeader(),
                'secretHeaderName' => $config->getApiSecretHeader(),
            ]);
        }
        return self::$apiKey;
    }

    public static function getGlobalFilter(): Middleware\SaGlobalFilter
    {
        if (self::$globalFilter === null) {
            self::$globalFilter = new Middleware\SaGlobalFilter();
        }
        return self::$globalFilter;
    }

    public static function getSign(): SaSign
    {
        if (self::$sign === null) {
            $config = self::getConfig();
            self::$sign = new SaSign([
                'key'          => $config->getSignKey(),
                'timestampGap' => $config->getSignTimestampGap(),
                'signAlg'      => $config->getSignAlg(),
            ]);
        }
        return self::$sign;
    }

    /**
     * 获取 StpLogic 实例（多账号体系）
     *
     * @param  string   $type 登录类型，默认 'login'
     * @return StpLogic
     */
    public static function getStpLogic(string $type = 'login'): StpLogic
    {
        // loginType 会成为注册表键与存储键的一部分：RPC 透传通道中该值
        // 来自请求头（攻击者可控），不加约束会让长驻进程的注册表无界增长
        if (!preg_match('/^[A-Za-z0-9_-]{1,32}$/', $type)) {
            throw new \SaToken\Exception\SaTokenException('非法的 loginType（仅允许字母/数字/下划线/中划线，最长 32 字符）');
        }
        if (!isset(self::$stpLogicMap[$type])) {
            self::$stpLogicMap[$type] = new StpLogic($type);
        }
        return self::$stpLogicMap[$type];
    }

    /**
     * 注册 StpLogic 实例
     *
     * @param  StpLogic $stpLogic StpLogic 实例
     * @return void
     */
    public static function registerStpLogic(StpLogic $stpLogic): void
    {
        self::$stpLogicMap[$stpLogic->getLoginType()] = $stpLogic;
    }

    /**
     * 判断是否已初始化
     *
     * @return bool
     */
    public static function isInitialized(): bool
    {
        return self::$initialized;
    }

    /**
     * 重置所有状态（用于测试）
     *
     * @return void
     */
    public static function reset(): void
    {
        self::$config = null;
        self::$dao = null;
        self::$event = null;
        self::$stpLogicMap = [];
        self::$action = null;
        self::$httpAuth = null;
        self::$apiKey = null;
        self::$globalFilter = null;
        self::$sign = null;
        self::$initialized = false;
        \SaToken\Security\SaAuditLog::reset();
        \SaToken\Security\SaSensitiveVerify::reset();
        \SaToken\Security\SaAntiBruteUtil::reset();
        \SaToken\Security\SaLoginDeviceManager::reset();
        \SaToken\Util\SaMetrics::reset();
    }

    public static function clearContext(): void
    {
        \SaToken\Util\SaTokenContext::clear();
        SaRouter::clearContext();
    }
}
