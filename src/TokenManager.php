<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Config\SaTokenConfig;
use SaToken\Exception\SaTokenException;
use SaToken\Plugin\SaTokenJwt;
use SaToken\Util\SaFoxUtil;
use SaToken\Util\SaTokenContext;
use SaToken\Util\SaTokenEncryptor;

class TokenManager
{
    public const TOKEN_PREFIX = 'satoken:login:token:';
    public const LOGIN_ID_PREFIX = 'satoken:login:loginId:';
    public const LAST_ACTIVE_PREFIX = 'satoken:login:lastActive:';
    public const SESSION_PREFIX = 'satoken:session:';
    public const TOKEN_SESSION_PREFIX = 'satoken:tokenSession:';
    public const DISABLE_PREFIX = 'satoken:disable:';
    public const SAFE_PREFIX = 'satoken:safe:';
    public const SWITCH_PREFIX = 'satoken:switch:';
    public const REFRESH_TOKEN_PREFIX = 'satoken:refresh:';
    public const REFRESH_TOKEN_MAP_PREFIX = 'satoken:refreshMap:';
    public const FINGERPRINT_PREFIX = 'satoken:fingerprint:';
    public const BLACKLIST_PREFIX = 'satoken:blacklist:';

    protected ?SaTokenEncryptor $encryptor = null;

    protected ?SaTokenJwt $jwtInstance = null;

    /**
     * @var array<string, string>
     */
    protected array $lockValues = [];

    protected function getDao(): \SaToken\Dao\SaTokenDaoInterface
    {
        return SaToken::getDao();
    }

    protected function getConfig(): SaTokenConfig
    {
        return SaToken::getConfig();
    }

    protected function getEncryptor(): SaTokenEncryptor
    {
        if ($this->encryptor === null) {
            $config = $this->getConfig();
            $key = $config->getTokenEncryptKey() ?: $config->getAesKey();
            if ($config->getCryptoType() === 'sm') {
                $key = $config->getTokenEncryptKey() ?: $config->getSm4Key();
            }
            $this->encryptor = new SaTokenEncryptor($config->isTokenEncrypt(), $key, $config->getCryptoType());
        }
        return $this->encryptor;
    }

    protected function getJwtInstance(): SaTokenJwt
    {
        if ($this->jwtInstance === null) {
            $config = $this->getConfig();
            $this->jwtInstance = new SaTokenJwt([
                'jwtSecretKey' => $config->getJwtSecretKey(),
                'cryptoType'   => $config->getCryptoType(),
            ]);
        }
        return $this->jwtInstance;
    }

    protected function encryptValue(string $value): string
    {
        return $this->getEncryptor()->encrypt($value);
    }

    protected function decryptValue(string $value): string
    {
        return $this->getEncryptor()->decrypt($value);
    }

    public function createTokenValue(mixed $loginId, string $loginType, string $prefix = ''): string
    {
        $action = SaToken::getAction();
        if ($action !== null) {
            $customToken = $action->generateTokenValue($loginId, $loginType);
            if ($customToken !== null) {
                // 自定义生成器是认证凭据的直接来源，最低防呆必须保留：
                // 可预测/短熵的 token（如 md5(loginId)）等于开放任意账号伪造
                if (SaFoxUtil::isEmpty($customToken)) {
                    throw new SaTokenException('自定义 generateTokenValue 返回了空 Token');
                }
                if (strlen($customToken) < 16) {
                    throw new SaTokenException('自定义 Token 熵不足（至少 16 字符），存在被伪造或碰撞的风险');
                }
                return $customToken;
            }
        }

        $effectivePrefix = $prefix !== '' ? $prefix : '';

        $style = $this->getConfig()->getTokenStyle();
        $raw = match ($style) {
            'uuid'          => SaFoxUtil::uuid(),
            'simple-random' => SaFoxUtil::randomString(32),
            'random-64'     => SaFoxUtil::randomString(64),
            'random-128'    => SaFoxUtil::randomString(128),
            'random-256'    => SaFoxUtil::randomString(256),
            'ticket'        => SaFoxUtil::randomString(24),
            default         => SaFoxUtil::uuid(),
        };
        return $effectivePrefix . $raw;
    }

    public function saveToken(string $tokenValue, mixed $loginId, string $loginType, string $deviceType = '', ?int $timeout = null): string
    {
        $config = $this->getConfig();
        $timeout = $timeout ?? $config->getTimeout();
        $effectiveTimeout = ($timeout === -1) ? null : $timeout;

        if ($config->getJwtMode() === 'mixed') {
            $tokenValue = $this->getJwtInstance()->createMixedToken($loginId, $loginType, $effectiveTimeout);
        }

        // Token 值冲突即覆盖他人会话（会话劫持），必须拒绝而不是盲写；
        // 冲突时按 maxTryTimes 重新生成重试（自定义生成器输出固定值时重试耗尽后抛出）
        $maxTries = max(1, $this->getConfig()->getMaxTryTimes());
        for ($attempt = 0; $attempt < $maxTries; $attempt++) {
            if (!$this->getDao()->exists(self::TOKEN_PREFIX . $tokenValue)) {
                $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
                $this->getDao()->set(self::TOKEN_PREFIX . $tokenValue, $this->encryptValue($loginIdStr), $effectiveTimeout);
                return $this->finalizeToken($tokenValue, $loginId, $loginType, $deviceType, $effectiveTimeout);
            }
            $tokenValue = $this->createTokenValue($loginId, $loginType);
            if ($this->getConfig()->getJwtMode() === 'mixed') {
                $tokenValue = $this->getJwtInstance()->createMixedToken($loginId, $loginType, $effectiveTimeout);
            }
        }

        throw new SaTokenException('Token 值冲突：相同 Token 已存在（生成器缺乏唯一性保证）');
    }

    /**
     * 保存 loginId 会话列表与映射（saveToken 的后半段，拆出以支持冲突重试）
     */
    protected function finalizeToken(string $tokenValue, mixed $loginId, string $loginType, string $deviceType, ?int $effectiveTimeout): string
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginIdStr;
        $existingTokens = $this->getTokenListByLoginId($loginId, $loginType);
        $tokenData = [
            'tokenValue' => $tokenValue,
            'deviceType' => $deviceType,
            'createTime' => SaFoxUtil::getTime(),
        ];

        $found = false;
        foreach ($existingTokens as $i => $item) {
            if ($item['tokenValue'] === $tokenValue) {
                $existingTokens[$i] = $tokenData;
                $found = true;
                break;
            }
        }
        if (!$found) {
            $replaced = false;
            if ($deviceType !== '') {
                foreach ($existingTokens as $i => $item) {
                    $itemDeviceType = is_string($item['deviceType'] ?? null) ? $item['deviceType'] : '';
                    $itemTokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
                    if ($itemDeviceType === $deviceType && !$this->isTokenValid($itemTokenValue)) {
                        $existingTokens[$i] = $tokenData;
                        $replaced = true;
                        break;
                    }
                }
            }
            if (!$replaced) {
                $existingTokens[] = $tokenData;
            }
        }

        $this->getDao()->set($loginIdKey, $this->encryptValue(SaFoxUtil::toJson($existingTokens)), $effectiveTimeout);

        // mixed 模式下实际存储的是 JWT，必须返回真实值供调用方下发给客户端
        return $tokenValue;
    }

    public function getLoginIdByToken(string $tokenValue): ?string
    {
        // Dao 记录是会话存在性的唯一权威来源：
        // logout/kickout/吊销均通过删除该记录实现，因此不存在记录的 Token 一律无效
        $value = $this->getDao()->get(self::TOKEN_PREFIX . $tokenValue);
        if ($value === null) {
            return null;
        }
        $loginId = $this->decryptValue($value);

        $config = $this->getConfig();
        if ($config->getJwtMode() === 'mixed') {
            // mixed 模式下 JWT 签名作为额外的真实性校验：签名可解码时主题必须一致
            try {
                $jwtLoginId = $this->getJwtInstance()->getLoginId($tokenValue);
            } catch (\Throwable) {
                $jwtLoginId = null;
            }
            if ($jwtLoginId !== null && $jwtLoginId !== $loginId) {
                return null;
            }
        }

        return $loginId;
    }

    /**
     * @return array<array<string, mixed>>
     */
    public function getTokenListByLoginId(mixed $loginId, string $loginType): array
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginIdStr;
        $json = $this->getDao()->get($loginIdKey);
        if ($json === null) {
            return [];
        }
        $decrypted = $this->decryptValue($json);
        $list = SaFoxUtil::fromJson($decrypted);
        if (!is_array($list)) {
            return [];
        }
        /** @var array<array<string, mixed>> $list */
        return $list;
    }

    public function deleteToken(string $tokenValue, mixed $loginId, string $loginType): void
    {
        // 会话列表是整包读改写，必须与 login/refresh 共用账号级互斥锁，
        // 否则并发 logout/kickout 与 login 会互相覆盖（复活已删条目/丢失新 Token）。
        // acquireLock 可重入，login 持锁路径不会被自阻塞
        $loginIdStr0 = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr0);
        if (!$this->acquireLock($lockKey, 5)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            $this->deleteTokenLocked($tokenValue, $loginId, $loginType);
        } finally {
            $this->releaseLock($lockKey);
        }
    }

    protected function deleteTokenLocked(string $tokenValue, mixed $loginId, string $loginType): void
    {
        $this->getDao()->delete(self::TOKEN_PREFIX . $tokenValue);

        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginIdStr;
        $existingTokens = $this->getTokenListByLoginId($loginId, $loginType);
        $newTokens = array_values(array_filter($existingTokens, fn ($item) => $item['tokenValue'] !== $tokenValue));

        if (empty($newTokens)) {
            $this->getDao()->delete($loginIdKey);
        } else {
            $timeout = $this->getDao()->getTimeout($loginIdKey);
            if ($timeout !== -2) {
                $effectiveTimeout = ($timeout === -1) ? null : $timeout;
                $this->getDao()->set($loginIdKey, $this->encryptValue(SaFoxUtil::toJson($newTokens)), $effectiveTimeout);
            }
        }

        $this->getDao()->delete(self::LAST_ACTIVE_PREFIX . $tokenValue);
        $this->getDao()->delete(self::TOKEN_SESSION_PREFIX . $tokenValue);
    }

    /**
     * @return array<string>
     */
    public function deleteAllTokenByLoginId(mixed $loginId, string $loginType): array
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->acquireLock($lockKey, 5)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            return $this->deleteAllTokenByLoginIdLocked($loginId, $loginType);
        } finally {
            $this->releaseLock($lockKey);
        }
    }

    /**
     * @return array<string>
     */
    protected function deleteAllTokenByLoginIdLocked(mixed $loginId, string $loginType): array
    {
        $tokens = $this->getTokenListByLoginId($loginId, $loginType);
        $deletedTokens = [];

        $keysToDelete = [];
        foreach ($tokens as $item) {
            $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            if ($tokenValue === '') {
                continue;
            }
            $keysToDelete[] = self::TOKEN_PREFIX . $tokenValue;
            $keysToDelete[] = self::LAST_ACTIVE_PREFIX . $tokenValue;
            $keysToDelete[] = self::TOKEN_SESSION_PREFIX . $tokenValue;
            $keysToDelete[] = self::FINGERPRINT_PREFIX . $tokenValue;
            $keysToDelete[] = self::BLACKLIST_PREFIX . $tokenValue;

            $refreshToken = $this->getRefreshTokenByAccessToken($loginId, $loginType, $tokenValue);
            if ($refreshToken !== null) {
                $keysToDelete[] = self::REFRESH_TOKEN_PREFIX . $refreshToken;
                $keysToDelete[] = self::REFRESH_TOKEN_MAP_PREFIX . $tokenValue;
            }

            $deletedTokens[] = $tokenValue;
        }

        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $keysToDelete[] = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginIdStr;
        $keysToDelete[] = self::SESSION_PREFIX . $loginType . ':' . $loginIdStr;

        if (count($keysToDelete) > 0) {
            $this->getDao()->deleteMultiple($keysToDelete);
        }

        return $deletedTokens;
    }

    public function updateLastActiveToNow(string $tokenValue): void
    {
        $config = $this->getConfig();
        if ($config->getActivityTimeout() <= 0) {
            return;
        }
        $this->getDao()->set(self::LAST_ACTIVE_PREFIX . $tokenValue, $this->encryptValue((string) SaFoxUtil::getTime()), $config->getActivityTimeout());
    }

    public function getLastActiveTime(string $tokenValue): ?int
    {
        $value = $this->getDao()->get(self::LAST_ACTIVE_PREFIX . $tokenValue);
        if ($value === null) {
            return null;
        }
        $decrypted = $this->decryptValue($value);
        return (int) $decrypted;
    }

    public function getTokenTimeout(string $tokenValue): int
    {
        return $this->getDao()->getTimeout(self::TOKEN_PREFIX . $tokenValue);
    }

    public function renewTimeout(string $tokenValue, int $timeout): void
    {
        $this->getDao()->expire(self::TOKEN_PREFIX . $tokenValue, $timeout);
    }

    public function isTokenValid(string $tokenValue): bool
    {
        if (SaFoxUtil::isEmpty($tokenValue)) {
            return false;
        }
        return $this->getDao()->exists(self::TOKEN_PREFIX . $tokenValue);
    }

    public function kickout(string $tokenValue, mixed $loginId, string $loginType): void
    {
        $this->deleteToken($tokenValue, $loginId, $loginType);
    }

    public function disable(mixed $loginId, string $service, int $level, int $time, string $loginType): void
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginIdStr . ':' . $service;
        $data = SaFoxUtil::toJson([
            'level'   => $level,
            'disable' => true,
            'time'    => $time,
        ]);
        $this->getDao()->set($key, $this->encryptValue($data), $time > 0 ? $time : null);
    }

    public function isDisable(mixed $loginId, string $service, string $loginType): bool
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginIdStr . ':' . $service;
        $json = $this->getDao()->get($key);
        if ($json === null) {
            return false;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($data)) {
            return false;
        }
        return isset($data['disable']) && $data['disable'] === true;
    }

    public function getDisableLevel(mixed $loginId, string $service, string $loginType): int
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginIdStr . ':' . $service;
        $json = $this->getDao()->get($key);
        if ($json === null) {
            return -1;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($data)) {
            return -1;
        }
        $level = $data['level'] ?? -1;
        return is_int($level) ? $level : -1;
    }

    public function getDisableTime(mixed $loginId, string $service, string $loginType): int
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginIdStr . ':' . $service;
        return $this->getDao()->getTimeout($key);
    }

    public function untieDisable(mixed $loginId, string $service, string $loginType): void
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginIdStr . ':' . $service;
        $this->getDao()->delete($key);
    }

    public function openSafe(string $tokenValue, string $service, int $safeTime, string $loginType): void
    {
        $key = self::SAFE_PREFIX . $loginType . ':' . $tokenValue . ':' . $service;
        $this->getDao()->set($key, $this->encryptValue((string) (SaFoxUtil::getTime() + $safeTime)), $safeTime);
    }

    public function isSafe(string $tokenValue, string $service, string $loginType): bool
    {
        $key = self::SAFE_PREFIX . $loginType . ':' . $tokenValue . ':' . $service;
        $value = $this->getDao()->get($key);
        if ($value === null) {
            return false;
        }
        $decrypted = $this->decryptValue($value);
        return (int) $decrypted > SaFoxUtil::getTime();
    }

    public function closeSafe(string $tokenValue, string $service, string $loginType): void
    {
        $key = self::SAFE_PREFIX . $loginType . ':' . $tokenValue . ':' . $service;
        $this->getDao()->delete($key);
    }

    public function setSwitchTo(string $tokenValue, mixed $switchToId, string $loginType): void
    {
        $key = self::SWITCH_PREFIX . $loginType . ':' . $tokenValue;
        // 身份切换跟随 Token 生命周期：Token 过期/被删除后切换关系不应残留；
        // Token 不存在（-2）时直接拒绝写入，避免产生永不回收的孤儿键
        $tokenTimeout = $this->getTokenTimeout($tokenValue);
        if ($tokenTimeout === -2) {
            throw new SaTokenException('Token 不存在，无法切换身份');
        }
        $effectiveTimeout = ($tokenTimeout > 0) ? $tokenTimeout : null;
        $this->getDao()->set($key, $this->encryptValue(SaFoxUtil::toString($switchToId)), $effectiveTimeout);
    }

    public function getSwitchTo(string $tokenValue, string $loginType): ?string
    {
        $key = self::SWITCH_PREFIX . $loginType . ':' . $tokenValue;
        $value = $this->getDao()->get($key);
        if ($value === null) {
            return null;
        }
        return $this->decryptValue($value);
    }

    public function clearSwitch(string $tokenValue, string $loginType): void
    {
        $key = self::SWITCH_PREFIX . $loginType . ':' . $tokenValue;
        $this->getDao()->delete($key);
    }

    /**
     * @return array<string>
     */
    public function searchTokenValue(string $keyword, int $start, int $size): array
    {
        return $this->getDao()->search(self::TOKEN_PREFIX, $keyword, $start, $size);
    }

    /**
     * @return array<string>
     */
    public function searchSessionId(string $keyword, int $start, int $size): array
    {
        return $this->getDao()->search(self::SESSION_PREFIX, $keyword, $start, $size);
    }

    /**
     * @return array<string>
     */
    public function searchTokenSessionId(string $keyword, int $start, int $size): array
    {
        return $this->getDao()->search(self::TOKEN_SESSION_PREFIX, $keyword, $start, $size);
    }

    public function resetEncryptor(): void
    {
        $this->encryptor = null;
        $this->jwtInstance = null;
    }

    public function saveRefreshToken(string $refreshToken, string $accessToken, mixed $loginId, string $loginType, int $timeout): void
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $data = SaFoxUtil::toJson([
            'loginId'      => $loginIdStr,
            'loginType'    => $loginType,
            'accessToken'  => $accessToken,
            'createTime'   => SaFoxUtil::getTime(),
        ]);
        $effectiveTimeout = ($timeout === -1) ? null : $timeout;
        $this->getDao()->set(self::REFRESH_TOKEN_PREFIX . $refreshToken, $this->encryptValue($data), $effectiveTimeout);

        $mapKey = self::REFRESH_TOKEN_MAP_PREFIX . $loginType . ':' . $loginIdStr . ':' . $accessToken;
        $this->getDao()->set($mapKey, $this->encryptValue($refreshToken), $effectiveTimeout);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getRefreshTokenData(string $refreshToken): ?array
    {
        $value = $this->getDao()->get(self::REFRESH_TOKEN_PREFIX . $refreshToken);
        if ($value === null) {
            return null;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($value));
        if (!is_array($data)) {
            return null;
        }
        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * 原子消费 RefreshToken：读取并立即删除主记录，
     * 保证并发重放同一 RefreshToken 时仅有一个请求成功
     *
     * @return array<string, mixed>|null
     */
    public function consumeRefreshToken(string $refreshToken): ?array
    {
        $raw = $this->getDao()->getAndDelete(self::REFRESH_TOKEN_PREFIX . $refreshToken);
        if ($raw === null) {
            return null;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($raw));
        if (!is_array($data)) {
            return null;
        }
        /** @var array<string, mixed> $data */
        $loginId = is_string($data['loginId'] ?? null) ? $data['loginId'] : '';
        $loginType = is_string($data['loginType'] ?? null) ? $data['loginType'] : '';
        $accessToken = is_string($data['accessToken'] ?? null) ? $data['accessToken'] : '';
        if ($loginId !== '' && $loginType !== '' && $accessToken !== '') {
            $this->getDao()->delete(self::REFRESH_TOKEN_MAP_PREFIX . $loginType . ':' . $loginId . ':' . $accessToken);
        }

        return $data;
    }

    /**
     * 获取 RefreshToken 的剩余有效期（秒），-1 表示永不过期，-2 表示不存在
     */
    public function getRefreshTokenTimeout(string $refreshToken): int
    {
        return $this->getDao()->getTimeout(self::REFRESH_TOKEN_PREFIX . $refreshToken);
    }

    public function getRefreshTokenByAccessToken(mixed $loginId, string $loginType, string $accessToken): ?string
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $mapKey = self::REFRESH_TOKEN_MAP_PREFIX . $loginType . ':' . $loginIdStr . ':' . $accessToken;
        $value = $this->getDao()->get($mapKey);
        if ($value === null) {
            return null;
        }
        return $this->decryptValue($value);
    }

    public function deleteRefreshToken(string $refreshToken): void
    {
        $data = $this->getRefreshTokenData($refreshToken);
        $this->getDao()->delete(self::REFRESH_TOKEN_PREFIX . $refreshToken);

        if ($data !== null) {
            $loginId = is_string($data['loginId'] ?? null) ? $data['loginId'] : '';
            $loginType = is_string($data['loginType'] ?? null) ? $data['loginType'] : '';
            $accessToken = is_string($data['accessToken'] ?? null) ? $data['accessToken'] : '';
            if ($loginId !== '' && $accessToken !== '') {
                $mapKey = self::REFRESH_TOKEN_MAP_PREFIX . $loginType . ':' . $loginId . ':' . $accessToken;
                $this->getDao()->delete($mapKey);
            }
        }
    }

    public function deleteRefreshTokenByAccessToken(mixed $loginId, string $loginType, string $accessToken): void
    {
        $refreshToken = $this->getRefreshTokenByAccessToken($loginId, $loginType, $accessToken);
        if ($refreshToken !== null) {
            $this->deleteRefreshToken($refreshToken);
        }
    }

    public function isRefreshTokenValid(string $refreshToken): bool
    {
        return $this->getDao()->exists(self::REFRESH_TOKEN_PREFIX . $refreshToken);
    }

    public function saveFingerprint(string $tokenValue, string $fingerprint, ?int $timeout = null): void
    {
        $effectiveTimeout = ($timeout === -1) ? null : $timeout;
        $this->getDao()->set(self::FINGERPRINT_PREFIX . $tokenValue, $this->encryptValue($fingerprint), $effectiveTimeout);
    }

    public function getFingerprint(string $tokenValue): ?string
    {
        $value = $this->getDao()->get(self::FINGERPRINT_PREFIX . $tokenValue);
        if ($value === null) {
            return null;
        }
        return $this->decryptValue($value);
    }

    public function deleteFingerprint(string $tokenValue): void
    {
        $this->getDao()->delete(self::FINGERPRINT_PREFIX . $tokenValue);
    }

    public function computeFingerprint(): string
    {
        $ip = SaTokenContext::getClientIp() ?? '';
        $ua = SaTokenContext::getHeader('User-Agent') ?? '';
        return hash('sha256', $ip . '|' . $ua);
    }

    public function addToBlacklist(string $tokenValue, ?int $timeout): void
    {
        $this->getDao()->set(self::BLACKLIST_PREFIX . $tokenValue, '1', ($timeout !== null && $timeout > 0) ? $timeout : null);
    }

    public function isBlacklisted(string $tokenValue): bool
    {
        return $this->getDao()->exists(self::BLACKLIST_PREFIX . $tokenValue);
    }

    public function removeFromBlacklist(string $tokenValue): void
    {
        $this->getDao()->delete(self::BLACKLIST_PREFIX . $tokenValue);
    }

    public const LOCK_PREFIX = 'satoken:lock:';

    public function acquireLock(string $key, int $ttl = 5): bool
    {
        $lockKey = self::LOCK_PREFIX . $key;

        // 可重入：本实例已持有该锁（如 login 持锁调用 deleteToken）时直接放行，
        // 避免嵌套获取导致 5 秒自阻塞
        if (isset($this->lockValues[$lockKey])) {
            return true;
        }

        $lockValue = bin2hex(random_bytes(8));

        $acquired = $this->getDao()->setIfNotExists($lockKey, $lockValue, $ttl > 0 ? $ttl : null);
        if ($acquired) {
            $this->lockValues[$lockKey] = $lockValue;
        }
        return $acquired;
    }

    public function releaseLock(string $key): void
    {
        $lockKey = self::LOCK_PREFIX . $key;
        $lockValue = $this->lockValues[$lockKey] ?? null;
        if ($lockValue === null) {
            return;
        }

        $dao = $this->getDao();
        if ($dao instanceof \SaToken\Dao\SaTokenDaoRedis) {
            $script = <<<'LUA'
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
LUA;
            $dao->getClient()->eval($script, [$lockKey, $lockValue], 1);
        } elseif ($dao->get($lockKey) === $lockValue) {
            $dao->delete($lockKey);
        }

        unset($this->lockValues[$lockKey]);
    }
}
