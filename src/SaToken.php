<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Action\SaTokenActionInterface;
use SaToken\Config\SaTokenConfig;
use SaToken\Dao\SaTokenDaoInterface;
use SaToken\Dao\SaTokenDaoMemory;
use SaToken\Exception\SaTokenException;
use SaToken\Listener\SaTokenEvent;
use SaToken\Listener\SaTokenListenerInterface;

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

    /**
     * 初始化 Sa-Token
     *
     * @param  array|SaTokenConfig|null $config 配置数组或 SaTokenConfig 实例，null 则自动加载
     * @return void
     */
    public static function init(array|SaTokenConfig|null $config = null): void
    {
        if ($config instanceof SaTokenConfig) {
            self::$config = $config;
        } elseif (is_array($config)) {
            self::$config = new SaTokenConfig($config);
        } else {
            // 自动加载 config/sa_token.php
            self::$config = self::loadConfigFile();
        }

        self::$event = new SaTokenEvent();
        self::$stpLogicMap = [];
        self::$initialized = true;
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
                if (is_array($config)) {
                    return new SaTokenConfig($config);
                }
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

    /**
     * 获取 StpLogic 实例（多账号体系）
     *
     * @param  string   $type 登录类型，默认 'login'
     * @return StpLogic
     */
    public static function getStpLogic(string $type = 'login'): StpLogic
    {
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
        self::$initialized = false;
    }
}
