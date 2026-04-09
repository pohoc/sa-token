<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Config\SaTokenConfig;
use SaToken\Util\SaFoxUtil;

/**
 * Token 管理器
 *
 * 负责 Token 的生成、校验、续期、撤销等核心操作
 *
 * 使用示例：
 *   $manager = new TokenManager();
 *   $token = $manager->createToken(10001, 'login');
 *   $manager->verifyToken($token);
 */
class TokenManager
{
    /**
     * 存储键前缀常量
     */
    public const TOKEN_PREFIX = 'satoken:login:token:';
    public const LOGIN_ID_PREFIX = 'satoken:login:loginId:';
    public const LAST_ACTIVE_PREFIX = 'satoken:login:lastActive:';
    public const SESSION_PREFIX = 'satoken:session:';
    public const TOKEN_SESSION_PREFIX = 'satoken:tokenSession:';
    public const DISABLE_PREFIX = 'satoken:disable:';
    public const SAFE_PREFIX = 'satoken:safe:';
    public const SWITCH_PREFIX = 'satoken:switch:';

    /**
     * 获取存储层
     *
     * @return \SaToken\Dao\SaTokenDaoInterface
     */
    protected function getDao(): \SaToken\Dao\SaTokenDaoInterface
    {
        return SaToken::getDao();
    }

    /**
     * 获取配置
     *
     * @return SaTokenConfig
     */
    protected function getConfig(): SaTokenConfig
    {
        return SaToken::getConfig();
    }

    /**
     * 生成 Token 值
     *
     * @param  mixed  $loginId   登录 ID
     * @param  string $loginType 登录类型
     * @return string Token 值
     */
    public function createTokenValue(mixed $loginId, string $loginType): string
    {
        $style = $this->getConfig()->getTokenStyle();
        return match ($style) {
            'uuid'          => SaFoxUtil::uuid(),
            'simple-random' => SaFoxUtil::randomString(32),
            default         => SaFoxUtil::uuid(),
        };
    }

    /**
     * 保存 Token 到存储层
     *
     * @param  string   $tokenValue Token 值
     * @param  mixed    $loginId    登录 ID
     * @param  string   $loginType  登录类型
     * @param  string   $deviceType 设备类型
     * @param  int|null $timeout    超时时间，null 使用全局配置
     * @return void
     */
    public function saveToken(string $tokenValue, mixed $loginId, string $loginType, string $deviceType = '', ?int $timeout = null): void
    {
        $config = $this->getConfig();
        $timeout = $timeout ?? $config->getTimeout();
        $effectiveTimeout = ($timeout === -1) ? null : $timeout;

        // 保存 token -> loginId 映射
        $this->getDao()->set(self::TOKEN_PREFIX . $tokenValue, (string) $loginId, $effectiveTimeout);

        // 保存 loginId -> token 列表映射（用于多端登录管理）
        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginId;
        $existingTokens = $this->getTokenListByLoginId($loginId, $loginType);
        $tokenData = [
            'tokenValue' => $tokenValue,
            'deviceType' => $deviceType,
            'createTime' => SaFoxUtil::getTime(),
        ];

        // 检查是否已有同设备类型的 Token
        $found = false;
        foreach ($existingTokens as $i => $item) {
            if ($item['deviceType'] === $deviceType) {
                $existingTokens[$i] = $tokenData;
                $found = true;
                break;
            }
        }
        if (!$found) {
            $existingTokens[] = $tokenData;
        }

        $this->getDao()->set($loginIdKey, SaFoxUtil::toJson($existingTokens), $effectiveTimeout);
    }

    /**
     * 根据 Token 值获取登录 ID
     *
     * @param  string      $tokenValue Token 值
     * @return string|null 登录 ID，不存在返回 null
     */
    public function getLoginIdByToken(string $tokenValue): ?string
    {
        return $this->getDao()->get(self::TOKEN_PREFIX . $tokenValue);
    }

    /**
     * 获取指定登录 ID 的所有 Token 列表
     *
     * @param  mixed                                                                      $loginId   登录 ID
     * @param  string                                                                     $loginType 登录类型
     * @return array<int, array{tokenValue: string, deviceType: string, createTime: int}>
     */
    public function getTokenListByLoginId(mixed $loginId, string $loginType): array
    {
        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginId;
        $json = $this->getDao()->get($loginIdKey);
        if ($json === null) {
            return [];
        }
        $list = SaFoxUtil::fromJson($json);
        return is_array($list) ? $list : [];
    }

    /**
     * 删除指定 Token
     *
     * @param  string $tokenValue Token 值
     * @param  mixed  $loginId    登录 ID
     * @param  string $loginType  登录类型
     * @return void
     */
    public function deleteToken(string $tokenValue, mixed $loginId, string $loginType): void
    {
        // 删除 token -> loginId 映射
        $this->getDao()->delete(self::TOKEN_PREFIX . $tokenValue);

        // 从 loginId 的 token 列表中移除
        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginId;
        $existingTokens = $this->getTokenListByLoginId($loginId, $loginType);
        $newTokens = array_values(array_filter($existingTokens, fn ($item) => $item['tokenValue'] !== $tokenValue));

        if (empty($newTokens)) {
            $this->getDao()->delete($loginIdKey);
        } else {
            $timeout = $this->getDao()->getTimeout($loginIdKey);
            // -2 表示 key 不存在，跳过保存避免创建新 key
            if ($timeout !== -2) {
                $effectiveTimeout = ($timeout === -1) ? null : $timeout;
                $this->getDao()->set($loginIdKey, SaFoxUtil::toJson($newTokens), $effectiveTimeout);
            }
        }

        // 删除活动时间记录
        $this->getDao()->delete(self::LAST_ACTIVE_PREFIX . $tokenValue);

        // 删除 TokenSession
        $this->getDao()->delete(self::TOKEN_SESSION_PREFIX . $tokenValue);
    }

    /**
     * 删除指定登录 ID 的所有 Token
     *
     * @param  mixed         $loginId   登录 ID
     * @param  string        $loginType 登录类型
     * @return array<string> 被删除的 Token 值列表
     */
    public function deleteAllTokenByLoginId(mixed $loginId, string $loginType): array
    {
        $tokens = $this->getTokenListByLoginId($loginId, $loginType);
        $deletedTokens = [];

        foreach ($tokens as $item) {
            $tokenValue = $item['tokenValue'];
            $this->getDao()->delete(self::TOKEN_PREFIX . $tokenValue);
            $this->getDao()->delete(self::LAST_ACTIVE_PREFIX . $tokenValue);
            $this->getDao()->delete(self::TOKEN_SESSION_PREFIX . $tokenValue);
            $deletedTokens[] = $tokenValue;
        }

        $this->getDao()->delete(self::LOGIN_ID_PREFIX . $loginType . ':' . $loginId);

        // 删除账号 Session
        $this->getDao()->delete(self::SESSION_PREFIX . $loginType . ':' . $loginId);

        return $deletedTokens;
    }

    /**
     * 更新最后活跃时间
     *
     * @param  string $tokenValue Token 值
     * @return void
     */
    public function updateLastActiveToNow(string $tokenValue): void
    {
        $config = $this->getConfig();
        if ($config->getActivityTimeout() <= 0) {
            return;
        }
        $this->getDao()->set(self::LAST_ACTIVE_PREFIX . $tokenValue, (string) SaFoxUtil::getTime(), $config->getActivityTimeout());
    }

    /**
     * 获取最后活跃时间
     *
     * @param  string   $tokenValue Token 值
     * @return int|null 时间戳，不存在返回 null
     */
    public function getLastActiveTime(string $tokenValue): ?int
    {
        $value = $this->getDao()->get(self::LAST_ACTIVE_PREFIX . $tokenValue);
        return $value !== null ? (int) $value : null;
    }

    /**
     * 获取 Token 剩余超时时间
     *
     * @param  string $tokenValue Token 值
     * @return int    剩余秒数，-2 表示不存在，-1 表示永不过期
     */
    public function getTokenTimeout(string $tokenValue): int
    {
        return $this->getDao()->getTimeout(self::TOKEN_PREFIX . $tokenValue);
    }

    /**
     * 续期 Token
     *
     * @param  string $tokenValue Token 值
     * @param  int    $timeout    新的超时时间（秒）
     * @return void
     */
    public function renewTimeout(string $tokenValue, int $timeout): void
    {
        $this->getDao()->expire(self::TOKEN_PREFIX . $tokenValue, $timeout);
    }

    /**
     * 判断 Token 是否有效
     *
     * @param  string $tokenValue Token 值
     * @return bool
     */
    public function isTokenValid(string $tokenValue): bool
    {
        if (SaFoxUtil::isEmpty($tokenValue)) {
            return false;
        }
        return $this->getDao()->exists(self::TOKEN_PREFIX . $tokenValue);
    }

    /**
     * 踢出指定 Token（标记为已踢出）
     *
     * @param  string $tokenValue Token 值
     * @param  mixed  $loginId    登录 ID
     * @param  string $loginType  登录类型
     * @return void
     */
    public function kickout(string $tokenValue, mixed $loginId, string $loginType): void
    {
        $this->deleteToken($tokenValue, $loginId, $loginType);
    }

    /**
     * 封禁管理 - 封禁账号
     *
     * @param  mixed  $loginId   登录 ID
     * @param  string $service   封禁服务
     * @param  int    $level     封禁等级
     * @param  int    $time      封禁时长（秒）
     * @param  string $loginType 登录类型
     * @return void
     */
    public function disable(mixed $loginId, string $service, int $level, int $time, string $loginType): void
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        $data = SaFoxUtil::toJson([
            'level'   => $level,
            'disable' => true,
            'time'    => $time,
        ]);
        $this->getDao()->set($key, $data, $time > 0 ? $time : null);
    }

    /**
     * 封禁管理 - 检查是否被封禁
     *
     * @param  mixed  $loginId   登录 ID
     * @param  string $service   封禁服务
     * @param  string $loginType 登录类型
     * @return bool
     */
    public function isDisable(mixed $loginId, string $service, string $loginType): bool
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        $json = $this->getDao()->get($key);
        if ($json === null) {
            return false;
        }
        $data = SaFoxUtil::fromJson($json);
        return isset($data['disable']) && $data['disable'] === true;
    }

    /**
     * 封禁管理 - 获取封禁等级
     *
     * @param  mixed  $loginId   登录 ID
     * @param  string $service   封禁服务
     * @param  string $loginType 登录类型
     * @return int    封禁等级，-1 表示未封禁
     */
    public function getDisableLevel(mixed $loginId, string $service, string $loginType): int
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        $json = $this->getDao()->get($key);
        if ($json === null) {
            return -1;
        }
        $data = SaFoxUtil::fromJson($json);
        return $data['level'] ?? -1;
    }

    /**
     * 封禁管理 - 获取封禁剩余时间
     *
     * @param  mixed  $loginId   登录 ID
     * @param  string $service   封禁服务
     * @param  string $loginType 登录类型
     * @return int    剩余秒数，-2 表示未封禁
     */
    public function getDisableTime(mixed $loginId, string $service, string $loginType): int
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        return $this->getDao()->getTimeout($key);
    }

    /**
     * 封禁管理 - 解除封禁
     *
     * @param  mixed  $loginId   登录 ID
     * @param  string $service   封禁服务
     * @param  string $loginType 登录类型
     * @return void
     */
    public function untieDisable(mixed $loginId, string $service, string $loginType): void
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        $this->getDao()->delete($key);
    }

    /**
     * 二级认证 - 开启安全窗口
     *
     * @param  string $tokenValue Token 值
     * @param  string $service    服务标识
     * @param  int    $safeTime   安全窗口时间（秒）
     * @param  string $loginType  登录类型
     * @return void
     */
    public function openSafe(string $tokenValue, string $service, int $safeTime, string $loginType): void
    {
        $key = self::SAFE_PREFIX . $loginType . ':' . $tokenValue . ':' . $service;
        $this->getDao()->set($key, (string) (SaFoxUtil::getTime() + $safeTime), $safeTime);
    }

    /**
     * 二级认证 - 检查是否在安全窗口内
     *
     * @param  string $tokenValue Token 值
     * @param  string $service    服务标识
     * @param  string $loginType  登录类型
     * @return bool
     */
    public function isSafe(string $tokenValue, string $service, string $loginType): bool
    {
        $key = self::SAFE_PREFIX . $loginType . ':' . $tokenValue . ':' . $service;
        $value = $this->getDao()->get($key);
        if ($value === null) {
            return false;
        }
        return (int) $value > SaFoxUtil::getTime();
    }

    /**
     * 二级认证 - 关闭安全窗口
     *
     * @param  string $tokenValue Token 值
     * @param  string $service    服务标识
     * @param  string $loginType  登录类型
     * @return void
     */
    public function closeSafe(string $tokenValue, string $service, string $loginType): void
    {
        $key = self::SAFE_PREFIX . $loginType . ':' . $tokenValue . ':' . $service;
        $this->getDao()->delete($key);
    }

    /**
     * 身份切换 - 保存切换信息
     *
     * @param  string $tokenValue Token 值
     * @param  mixed  $switchToId 切换目标 ID
     * @param  string $loginType  登录类型
     * @return void
     */
    public function setSwitchTo(string $tokenValue, mixed $switchToId, string $loginType): void
    {
        $key = self::SWITCH_PREFIX . $loginType . ':' . $tokenValue;
        $this->getDao()->set($key, SaFoxUtil::toString($switchToId));
    }

    /**
     * 身份切换 - 获取切换目标 ID
     *
     * @param  string      $tokenValue Token 值
     * @param  string      $loginType  登录类型
     * @return string|null 目标 ID，不存在返回 null
     */
    public function getSwitchTo(string $tokenValue, string $loginType): ?string
    {
        $key = self::SWITCH_PREFIX . $loginType . ':' . $tokenValue;
        return $this->getDao()->get($key);
    }

    /**
     * 身份切换 - 清除切换信息
     *
     * @param  string $tokenValue Token 值
     * @param  string $loginType  登录类型
     * @return void
     */
    public function clearSwitch(string $tokenValue, string $loginType): void
    {
        $key = self::SWITCH_PREFIX . $loginType . ':' . $tokenValue;
        $this->getDao()->delete($key);
    }

    /**
     * 搜索 Token 值（仅内存存储支持，Redis 等需重写）
     *
     * @param  string        $keyword 关键词
     * @param  int           $start   起始索引
     * @param  int           $size    数量
     * @return array<string>
     */
    public function searchTokenValue(string $keyword, int $start, int $size): array
    {
        // 默认实现不支持搜索，Redis 存储需重写
        return [];
    }

    /**
     * 搜索 Session ID（仅内存存储支持，Redis 等需重写）
     *
     * @param  string        $keyword 关键词
     * @param  int           $start   起始索引
     * @param  int           $size    数量
     * @return array<string>
     */
    public function searchSessionId(string $keyword, int $start, int $size): array
    {
        // 默认实现不支持搜索
        return [];
    }
}
