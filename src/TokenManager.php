<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Config\SaTokenConfig;
use SaToken\Exception\SaTokenException;
use SaToken\Plugin\SaTokenJwt;
use SaToken\Util\SaFoxUtil;
use SaToken\Util\SaTokenContext;
use SaToken\Util\SaTokenEncryptor;
use SaToken\Util\SaTokenTimeout;

class TokenManager
{
    public const TOKEN_PREFIX = 'satoken:login:token:';
    public const LOGIN_ID_PREFIX = 'satoken:login:loginId:';
    public const LOGIN_ID_V2_PREFIX = 'satoken:login:v2:loginId:';
    public const LAST_ACTIVE_PREFIX = 'satoken:login:lastActive:';
    public const SESSION_PREFIX = 'satoken:session:';
    public const TOKEN_SESSION_PREFIX = 'satoken:tokenSession:';
    public const DISABLE_PREFIX = 'satoken:disable:';
    public const SAFE_PREFIX = 'satoken:safe:';
    protected const SAFE_V2_PREFIX = 'satoken:safe:v2:';
    protected const SAFE_SERVICES_PREFIX = 'satoken:safe:services:';
    public const SWITCH_PREFIX = 'satoken:switch:';
    public const REFRESH_TOKEN_PREFIX = 'satoken:refresh:';
    public const REFRESH_TOKEN_USED_PREFIX = 'satoken:refresh:used:';
    public const REFRESH_TOKEN_MAP_PREFIX = 'satoken:refreshMap:';
    protected const REFRESH_TOKEN_ACCOUNT_PREFIX = 'satoken:refreshAccount:';
    public const FINGERPRINT_PREFIX = 'satoken:fingerprint:';
    public const BLACKLIST_PREFIX = 'satoken:blacklist:';

    /** Build a collision-free login session key while preserving legacy keys without colons. */
    public static function buildSessionId(string $loginType, string $loginId): string
    {
        return self::SESSION_PREFIX . self::encodeKeyComponent($loginType) . ':' . self::encodeKeyComponent($loginId);
    }

    /** Escape tuple delimiters while leaving ordinary legacy key components unchanged. */
    public static function encodeKeyComponent(string $component): string
    {
        return str_replace(['%', ':'], ['%25', '%3A'], $component);
    }

    public static function buildLoginIdKey(string $loginType, string $loginId): string
    {
        return self::LOGIN_ID_V2_PREFIX . self::encodeKeyComponent($loginType) . ':' . self::encodeKeyComponent($loginId);
    }

    protected static function buildLegacyLoginIdKey(string $loginType, string $loginId): string
    {
        return self::LOGIN_ID_PREFIX . $loginType . ':' . $loginId;
    }

    protected static function buildDisableKey(string $loginType, string $loginId, string $service): string
    {
        return self::DISABLE_PREFIX . self::encodeKeyComponent($loginType) . ':'
            . self::encodeKeyComponent($loginId) . ':' . self::encodeKeyComponent($service);
    }

    protected ?SaTokenEncryptor $encryptor = null;

    protected ?string $encryptorConfigFingerprint = null;

    protected ?SaTokenJwt $jwtInstance = null;

    protected ?string $jwtConfigFingerprint = null;

    /**
     * @var array<string, string>
     */
    protected array $lockValues = [];

    /** @var array<string, int> */
    protected array $lockDepths = [];

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
        $config = $this->getConfig();
        $key = $config->getTokenEncryptKey() ?: $config->getAesKey();
        if ($config->getCryptoType() === 'sm') {
            $key = $config->getTokenEncryptKey() ?: $config->getSm4Key();
        }
        $fingerprint = hash('sha256', serialize([
            $config->isTokenEncrypt(),
            $key,
            $config->getCryptoType(),
        ]));
        if ($this->encryptor === null || $this->encryptorConfigFingerprint !== $fingerprint) {
            $this->encryptor = new SaTokenEncryptor($config->isTokenEncrypt(), $key, $config->getCryptoType());
            $this->encryptorConfigFingerprint = $fingerprint;
        }
        return $this->encryptor;
    }

    protected function getJwtInstance(): SaTokenJwt
    {
        $config = $this->getConfig();
        $fingerprint = hash('sha256', serialize([
            $config->getJwtSecretKey(),
            $config->getCryptoType(),
        ]));
        if ($this->jwtInstance === null || $this->jwtConfigFingerprint !== $fingerprint) {
            $this->jwtInstance = new SaTokenJwt([
                'jwtSecretKey' => $config->getJwtSecretKey(),
                'cryptoType'   => $config->getCryptoType(),
            ]);
            $this->jwtConfigFingerprint = $fingerprint;
        }
        return $this->jwtInstance;
    }

    protected function encryptValue(string $value): string
    {
        return $this->getEncryptor()->encrypt($value);
    }

    protected function decryptValue(string $value): string
    {
        $decrypted = $this->getEncryptor()->decryptChecked($value);
        if ($decrypted === null) {
            throw new SaTokenException('Token 存储数据完整性校验失败');
        }
        return $decrypted;
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
                // Keep credential classes disjoint even when a custom action
                // returns the same value on every call. In particular, an
                // access token must never also be accepted as its refresh token.
                return $prefix . $customToken;
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
        SaTokenTimeout::validate($timeout ?? $this->getConfig()->getTimeout());

        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }

        $loginIdStr = (string) $loginId;
        $loginLockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->acquireLock($loginLockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            return $this->saveTokenWithLoginLock($tokenValue, $loginId, $loginType, $deviceType, $timeout);
        } finally {
            $this->releaseLock($loginLockKey);
        }
    }

    protected function saveTokenWithLoginLock(string $tokenValue, mixed $loginId, string $loginType, string $deviceType, ?int $timeout): string
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
            $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
            $tokenLockKey = $this->tokenValueLockKey($tokenValue);
            if ($this->acquireLock($tokenLockKey, 30)) {
                try {
                    // 吊销黑名单必须阻止同一 bearer 值在 TTL 内被重新签发。
                    if (!$this->isBlacklisted($tokenValue)
                        && $this->getDao()->setIfNotExists(self::TOKEN_PREFIX . $tokenValue, $this->encryptValue($loginIdStr), $effectiveTimeout)) {
                        $this->clearTokenBoundState($tokenValue, $loginType);
                        $finalizedToken = $this->finalizeToken($tokenValue, $loginId, $loginType, $deviceType, $effectiveTimeout);
                        $this->updateLastActiveToNow($tokenValue);
                        return $finalizedToken;
                    }
                } finally {
                    $this->releaseLock($tokenLockKey);
                }
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
        $loginIdKey = self::buildLoginIdKey($loginType, $loginIdStr);
        $expectedList = $this->getDao()->get($loginIdKey);
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

        // The account list may contain tokens with different TTLs. Its lifetime
        // must cover the longest-lived token, otherwise a newer short session
        // can make older valid tokens fail the loginType ownership check early.
        /** @var int|null $listTimeout */
        $listTimeout = 1;
        foreach ($existingTokens as $item) {
            $itemTokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            if ($itemTokenValue === '') {
                continue;
            }
            $tokenTimeout = $this->getDao()->getTimeout(self::TOKEN_PREFIX . $itemTokenValue);
            if ($tokenTimeout === -1) {
                $listTimeout = null;
                break;
            }
            if ($tokenTimeout > $listTimeout) {
                $listTimeout = $tokenTimeout;
            }
            $refreshToken = $this->getRefreshTokenByAccessToken($loginIdStr, $loginType, $itemTokenValue);
            if ($refreshToken !== null) {
                $refreshTimeout = $this->getRefreshTokenTimeout($refreshToken);
                if ($refreshTimeout === -1) {
                    $listTimeout = null;
                    break;
                }
                if ($refreshTimeout > $listTimeout) {
                    $listTimeout = $refreshTimeout;
                }
            }
        }

        $dao = $this->getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
            || !$dao->compareAndSet(
                $loginIdKey,
                $expectedList,
                $this->encryptValue(SaFoxUtil::toJson($existingTokens)),
                $listTimeout
            )) {
            throw new SaTokenException('账号会话列表已并发变更或 DAO 不支持原子条件写入，请重试');
        }

        // mixed 模式下实际存储的是 JWT，必须返回真实值供调用方下发给客户端
        return $tokenValue;
    }

    protected function tokenValueLockKey(string $tokenValue): string
    {
        return 'token-value:' . hash('sha256', $tokenValue);
    }

    protected function clearTokenBoundState(string $tokenValue, string $loginType): void
    {
        $dao = $this->getDao();
        $dao->delete(self::LAST_ACTIVE_PREFIX . $tokenValue);
        $dao->delete(self::TOKEN_SESSION_PREFIX . $tokenValue);
        $dao->delete(self::FINGERPRINT_PREFIX . $tokenValue);
        $this->clearSwitch($tokenValue, $loginType);

        $services = $this->getSafeServices($tokenValue, $loginType);
        foreach ($services as $service) {
            $dao->delete($this->safeStateKey($tokenValue, $service, $loginType));
        }
        $dao->delete($this->safeServicesKey($tokenValue, $loginType));
    }

    public function getLoginIdByToken(string $tokenValue): ?string
    {
        // Dao 记录是会话存在性的唯一权威来源：
        // logout/kickout/吊销均通过删除该记录实现，因此不存在记录的 Token 一律无效
        $value = $this->getDao()->get(self::TOKEN_PREFIX . $tokenValue);
        if ($value === null) {
            return null;
        }
        try {
            $loginId = $this->decryptValue($value);
        } catch (SaTokenException) {
            return null;
        }

        $config = $this->getConfig();
        if ($config->getJwtMode() === 'mixed') {
            // mixed 模式下必须同时通过 JWT 签名与 exp 校验；空身份也要拒绝，
            // 否则过期/伪造 JWT 会因 DAO 记录仍在而被当作普通有状态 Token 接受。
            try {
                $jwtLoginId = $this->getJwtInstance()->getLoginId($tokenValue);
            } catch (\Throwable) {
                $jwtLoginId = null;
            }
            if ($jwtLoginId === null || $jwtLoginId !== $loginId) {
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
        $loginIdKey = self::buildLoginIdKey($loginType, $loginIdStr);
        $json = $this->getDao()->get($loginIdKey);
        if ($json === null) {
            // Read old raw/encoded indexes when their spelling is unambiguous.
            // Any percent sign could be either literal legacy data or an escape
            // from the prior encoded format (%25 / %3A), so fail closed instead
            // of mistaking another login type's new index for this old index.
            if (str_contains($loginType, '%') || str_contains($loginIdStr, '%')) {
                return [];
            }
            $legacyJson = $this->getDao()->get(self::buildLegacyLoginIdKey($loginType, $loginIdStr));
            if ($legacyJson === null) {
                return [];
            }
            $legacyList = SaFoxUtil::fromJson($this->decryptValue($legacyJson));
            if (!is_array($legacyList)) {
                return [];
            }
            $filtered = [];
            foreach ($legacyList as $item) {
                if (!is_array($item)) {
                    continue;
                }
                $normalized = [];
                foreach ($item as $key => $value) {
                    if (is_string($key)) {
                        $normalized[$key] = $value;
                    }
                }
                $tokenValue = $normalized['tokenValue'] ?? null;
                if (is_string($tokenValue) && $this->getLoginIdByToken($tokenValue) === $loginIdStr) {
                    $filtered[] = $normalized;
                }
            }
            return $filtered;
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
        if (!$this->acquireLock($lockKey, 30)) {
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
        $tokenLockKey = $this->tokenValueLockKey($tokenValue);
        if (!$this->acquireLock($tokenLockKey, 30)) {
            throw new SaTokenException('Token 正在签发或注销，请稍后重试');
        }

        try {
            $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
            // 只有 token 主记录仍属于指定账号，且账号列表确实登记了该 token，
            // 才允许清理它及其关联状态。否则伪造 loginId/loginType 会造成跨账号注销。
            if ($this->getLoginIdByToken($tokenValue) !== $loginIdStr) {
                return;
            }
            $loginIdKey = self::buildLoginIdKey($loginType, $loginIdStr);
            $expectedList = $this->getDao()->get($loginIdKey);
            $existingTokens = $this->getTokenListByLoginId($loginId, $loginType);
            if (!in_array($tokenValue, array_column($existingTokens, 'tokenValue'), true)) {
                return;
            }
            $newTokens = array_values(array_filter($existingTokens, fn ($item) => $item['tokenValue'] !== $tokenValue));

            if ($expectedList !== null) {
                $dao = $this->getDao();
                $timeout = $dao->getTimeout($loginIdKey);
                $effectiveTimeout = ($timeout === -1) ? null : max(1, $timeout);
                $newList = $newTokens === [] ? null : $this->encryptValue(SaFoxUtil::toJson($newTokens));
                if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                    || !$dao->compareAndSet($loginIdKey, $expectedList, $newList, $effectiveTimeout)) {
                    throw new SaTokenException('账号会话列表已并发变更或 DAO 不支持原子条件写入，请重试');
                }
            }

            $this->clearTokenBoundState($tokenValue, $loginType);
            // token 主键最后删除：NX 签发方在这之前无法重用同一 bearer 值。
            $this->getDao()->delete(self::TOKEN_PREFIX . $tokenValue);
        } finally {
            $this->releaseLock($tokenLockKey);
        }
    }

    /**
     * @return array<string>
     */
    public function deleteAllTokenByLoginId(mixed $loginId, string $loginType): array
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->acquireLock($lockKey, 30)) {
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
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $loginLockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        $loginIdKey = self::buildLoginIdKey($loginType, $loginIdStr);
        $expectedList = $this->getDao()->get($loginIdKey);
        $tokens = $this->getTokenListByLoginId($loginId, $loginType);
        $deletedTokens = [];

        $tokenLockKeys = [];
        foreach ($tokens as $item) {
            $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            if ($tokenValue !== '') {
                $tokenLockKeys[] = $this->tokenValueLockKey($tokenValue);
            }
        }
        $tokenLockKeys = array_values(array_unique($tokenLockKeys));
        sort($tokenLockKeys, SORT_STRING);
        $acquiredLocks = [];
        $lastRenewal = hrtime(true);
        $renewLocks = function () use (&$acquiredLocks, $loginLockKey, &$lastRenewal): void {
            if (hrtime(true) - $lastRenewal < 10_000_000_000) {
                return;
            }
            if (!$this->renewLock($loginLockKey, 30)) {
                throw new SaTokenException('账号会话锁租约已失效，请重试');
            }
            array_walk($acquiredLocks, function (string $acquiredLock): void {
                if (!$this->renewLock($acquiredLock, 30)) {
                    throw new SaTokenException('Token 锁租约已失效，请重试');
                }
            });
            $lastRenewal = hrtime(true);
        };
        try {
            foreach ($tokenLockKeys as $tokenLockKey) {
                $renewLocks();
                if (!$this->acquireLock($tokenLockKey, 30)) {
                    throw new SaTokenException('Token 正在签发或注销，请稍后重试');
                }
                $acquiredLocks[] = $tokenLockKey;
            }
        } catch (\Throwable $exception) {
            foreach ($acquiredLocks as $acquiredLock) {
                $this->releaseLock($acquiredLock);
            }
            throw $exception;
        }

        $keysToDelete = [];
        try {
            foreach ($tokens as $item) {
                $renewLocks();
                $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
                if ($tokenValue === '') {
                    continue;
                }
                $keysToDelete[] = self::TOKEN_PREFIX . $tokenValue;
                $keysToDelete[] = self::LAST_ACTIVE_PREFIX . $tokenValue;
                $keysToDelete[] = self::TOKEN_SESSION_PREFIX . $tokenValue;
                $keysToDelete[] = self::FINGERPRINT_PREFIX . $tokenValue;
                $refreshToken = $this->getRefreshTokenByAccessToken($loginId, $loginType, $tokenValue);
                if ($refreshToken !== null) {
                    $keysToDelete[] = self::REFRESH_TOKEN_PREFIX . $refreshToken;
                    $keysToDelete[] = self::buildRefreshTokenMapKey($loginId, $loginType, $tokenValue);
                }

                $deletedTokens[] = $tokenValue;
            }

            $dao = $this->getDao();
            if ($expectedList !== null) {
                if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                    || !$dao->compareAndSet($loginIdKey, $expectedList, null)) {
                    throw new SaTokenException('账号会话列表已并发变更或 DAO 不支持原子条件写入，请重试');
                }
            }
            $keysToDelete[] = self::buildSessionId($loginType, $loginIdStr);

            if (count($keysToDelete) > 0) {
                $dao->deleteMultiple($keysToDelete);
            }
            foreach ($deletedTokens as $tokenValue) {
                $this->clearTokenBoundState($tokenValue, $loginType);
            }
        } finally {
            foreach ($acquiredLocks as $acquiredLock) {
                $this->releaseLock($acquiredLock);
            }
        }

        $this->deleteRefreshTokensByLoginIdLocked($loginIdStr, $loginType);

        return $deletedTokens;
    }

    public function updateLastActiveToNow(string $tokenValue): void
    {
        $config = $this->getConfig();
        if ($config->getActivityTimeout() <= 0) {
            return;
        }

        // The marker intentionally expires after the idle window. Its creation at
        // issuance plus fail-closed handling of a missing marker makes expiry an
        // unambiguous signal that the Token was inactive for too long.
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
        SaTokenTimeout::validate($timeout);
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
        SaTokenTimeout::validate($time, '封禁时长');
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::buildDisableKey($loginType, $loginIdStr, $service);
        $data = SaFoxUtil::toJson([
            'level'   => $level,
            'disable' => true,
            'time'    => $time,
        ]);
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            $this->getDao()->set($key, $this->encryptValue($data), $time > 0 ? $time : null);
        } finally {
            $this->releaseLock($lockKey);
        }
    }

    public function isDisable(mixed $loginId, string $service, string $loginType): bool
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::buildDisableKey($loginType, $loginIdStr, $service);
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
        $key = self::buildDisableKey($loginType, $loginIdStr, $service);
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
        $key = self::buildDisableKey($loginType, $loginIdStr, $service);
        return $this->getDao()->getTimeout($key);
    }

    public function untieDisable(mixed $loginId, string $service, string $loginType): void
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::buildDisableKey($loginType, $loginIdStr, $service);
        $this->getDao()->delete($key);
    }

    public function openSafe(string $tokenValue, string $service, int $safeTime, string $loginType): void
    {
        if ($safeTime <= 0) {
            throw new SaTokenException('安全窗口必须是正整数秒数');
        }
        SaTokenTimeout::validate($safeTime, '安全窗口');

        $tokenLockKey = $this->tokenValueLockKey($tokenValue);
        if (!$this->acquireLock($tokenLockKey, 30)) {
            throw new SaTokenException('Token 正在签发或注销，请稍后重试');
        }

        try {
            $tokenTimeout = $this->getTokenTimeout($tokenValue);
            if ($tokenTimeout === -2 || $this->isBlacklisted($tokenValue)) {
                throw new SaTokenException('Token 不存在或已撤销，无法开启安全状态');
            }
            $effectiveSafeTime = $safeTime;
            if ($tokenTimeout >= 0) {
                $effectiveSafeTime = min($safeTime, max(1, $tokenTimeout));
            }

            $services = $this->getSafeServices($tokenValue, $loginType);
            if (!in_array($service, $services, true)) {
                $services[] = $service;
            }

            $registryTimeout = $tokenTimeout >= 0 ? max(1, $tokenTimeout) : null;
            $this->getDao()->set(
                $this->safeServicesKey($tokenValue, $loginType),
                $this->encryptValue(SaFoxUtil::toJson($services)),
                $registryTimeout
            );
            $this->getDao()->set(
                $this->safeStateKey($tokenValue, $service, $loginType),
                $this->encryptValue((string) (SaFoxUtil::getTime() + $effectiveSafeTime)),
                $effectiveSafeTime
            );
        } finally {
            $this->releaseLock($tokenLockKey);
        }
    }

    public function isSafe(string $tokenValue, string $service, string $loginType): bool
    {
        $value = $this->getDao()->get($this->safeStateKey($tokenValue, $service, $loginType));
        if ($value === null) {
            return false;
        }
        $decrypted = $this->decryptValue($value);
        return (int) $decrypted > SaFoxUtil::getTime();
    }

    public function closeSafe(string $tokenValue, string $service, string $loginType): void
    {
        $tokenLockKey = $this->tokenValueLockKey($tokenValue);
        if (!$this->acquireLock($tokenLockKey, 30)) {
            throw new SaTokenException('Token 正在签发或注销，请稍后重试');
        }

        try {
            $this->getDao()->delete($this->safeStateKey($tokenValue, $service, $loginType));
            $services = array_values(array_filter(
                $this->getSafeServices($tokenValue, $loginType),
                static fn (string $registeredService): bool => $registeredService !== $service
            ));
            $registryKey = $this->safeServicesKey($tokenValue, $loginType);
            if ($services === []) {
                $this->getDao()->delete($registryKey);
            } else {
                $timeout = $this->getDao()->getTimeout($registryKey);
                $effectiveTimeout = $timeout > 0 ? $timeout : null;
                $this->getDao()->set($registryKey, $this->encryptValue(SaFoxUtil::toJson($services)), $effectiveTimeout);
            }
        } finally {
            $this->releaseLock($tokenLockKey);
        }
    }

    protected function safeStateKey(string $tokenValue, string $service, string $loginType): string
    {
        return self::SAFE_V2_PREFIX . $loginType . ':' . hash('sha256', $tokenValue) . ':' . hash('sha256', $service);
    }

    protected function safeServicesKey(string $tokenValue, string $loginType): string
    {
        return self::SAFE_SERVICES_PREFIX . $loginType . ':' . hash('sha256', $tokenValue);
    }

    /** @return list<string> */
    protected function getSafeServices(string $tokenValue, string $loginType): array
    {
        $json = $this->getDao()->get($this->safeServicesKey($tokenValue, $loginType));
        if ($json === null) {
            return [];
        }
        $services = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($services)) {
            throw new SaTokenException('Token 安全状态索引损坏');
        }

        $validServices = [];
        foreach ($services as $service) {
            if (is_string($service) && !in_array($service, $validServices, true)) {
                $validServices[] = $service;
            }
        }
        return $validServices;
    }

    public function setSwitchTo(string $tokenValue, mixed $switchToId, string $loginType): void
    {
        $key = self::buildSwitchKey($tokenValue, $loginType);
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
        $dao = $this->getDao();
        $value = $dao->get(self::buildSwitchKey($tokenValue, $loginType));
        if ($value === null
            && !str_contains($loginType, ':') && !str_contains($loginType, '%')
            && !str_contains($tokenValue, ':') && !str_contains($tokenValue, '%')) {
            // Keep unambiguous legacy keys readable during upgrade. Delimiters and
            // escape markers must never fall back to the collision-prone namespace:
            // a legacy '%' can alias the encoded spelling of another token's key.
            $value = $dao->get(self::buildLegacySwitchKey($tokenValue, $loginType));
        }
        if ($value === null) {
            return null;
        }
        return $this->decryptValue($value);
    }

    public function clearSwitch(string $tokenValue, string $loginType): void
    {
        $dao = $this->getDao();
        $dao->delete(self::buildSwitchKey($tokenValue, $loginType));
        if (!str_contains($loginType, ':') && !str_contains($loginType, '%')
            && !str_contains($tokenValue, ':') && !str_contains($tokenValue, '%')) {
            $dao->delete(self::buildLegacySwitchKey($tokenValue, $loginType));
        }
    }

    protected static function buildSwitchKey(string $tokenValue, string $loginType): string
    {
        return self::SWITCH_PREFIX . self::encodeKeyComponent($loginType) . ':' . self::encodeKeyComponent($tokenValue);
    }

    protected static function buildLegacySwitchKey(string $tokenValue, string $loginType): string
    {
        return self::SWITCH_PREFIX . $loginType . ':' . $tokenValue;
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
        $this->encryptorConfigFingerprint = null;
        $this->jwtInstance = null;
        $this->jwtConfigFingerprint = null;
    }

    public function saveRefreshToken(string $refreshToken, string $accessToken, mixed $loginId, string $loginType, int $timeout): void
    {
        SaTokenTimeout::validate($timeout, 'RefreshToken');

        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }

        $loginIdStr = (string) $loginId;
        $loginLockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->acquireLock($loginLockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            $accessTokenOwner = (new StpLogic($loginType, $this))->getLoginIdByToken($accessToken);
            if ($accessTokenOwner !== $loginIdStr) {
                throw new SaTokenException('AccessToken 无效或不属于指定账号，拒绝绑定 RefreshToken');
            }
            if (!$this->getConfig()->isJwtStateless()) {
                $accountTokens = $this->getTokenListByLoginId($loginIdStr, $loginType);
                if (!in_array($accessToken, array_column($accountTokens, 'tokenValue'), true)) {
                    throw new SaTokenException('AccessToken 不属于指定账号或登录类型，拒绝绑定 RefreshToken');
                }
            }

            // Extend or migrate the account index before persisting the refresh
            // record. If a concurrent logout/login changes the index while a
            // stale account-lock lease is being recovered, fail closed without
            // leaving a refresh credential that outlives its session index.
            $this->extendLoginIdListTimeout($loginIdStr, $loginType, $timeout);
            if ((new StpLogic($loginType, $this))->getLoginIdByToken($accessToken) !== $loginIdStr) {
                throw new SaTokenException('AccessToken 在绑定 RefreshToken 期间已失效');
            }

            $refreshData = [
                'loginId'      => $loginIdStr,
                'loginType'    => $loginType,
                'accessToken'  => $accessToken,
                'createTime'   => SaFoxUtil::getTime(),
            ];
            if ($this->getConfig()->isTokenFingerprint()) {
                $refreshData['fingerprint'] = $this->computeFingerprint();
            }
            $data = SaFoxUtil::toJson($refreshData);
            $effectiveTimeout = ($timeout === -1) ? null : $timeout;
            $refreshKey = self::REFRESH_TOKEN_PREFIX . $refreshToken;
            $refreshRaw = $this->encryptValue($data);
            if (!$this->renewLock($loginLockKey, 30)
                || (new StpLogic($loginType, $this))->getLoginIdByToken($accessToken) !== $loginIdStr) {
                throw new SaTokenException('账号会话锁或 AccessToken 已失效，拒绝绑定 RefreshToken');
            }
            // Register the credential before writing it. If the process stops
            // between these writes, account revocation still knows which key to
            // inspect; a stale index entry without a credential is harmless.
            $this->addRefreshTokenToAccountIndex($loginIdStr, $loginType, $refreshToken, $timeout);
            if (!$this->getDao()->setIfNotExists(
                $refreshKey,
                $refreshRaw,
                $effectiveTimeout
            )) {
                $existingData = $this->getRefreshTokenData($refreshToken);
                if (($existingData['loginId'] ?? null) !== $loginIdStr
                    || ($existingData['loginType'] ?? null) !== $loginType) {
                    $this->removeRefreshTokenFromAccountIndex($loginIdStr, $loginType, $refreshToken);
                }
                throw new SaTokenException('RefreshToken 值冲突，拒绝覆盖其他会话凭据');
            }

            $mapKey = self::buildRefreshTokenMapKey($loginIdStr, $loginType, $accessToken);
            $dao = $this->getDao();
            $previousMapValue = $dao->get($mapKey);
            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                || !$dao->compareAndSet($mapKey, $previousMapValue, $this->encryptValue($refreshToken), $effectiveTimeout)) {
                if ($dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
                    $dao->compareAndDelete($refreshKey, $refreshRaw);
                }
                $this->removeRefreshTokenFromAccountIndex($loginIdStr, $loginType, $refreshToken);
                throw new SaTokenException('RefreshToken 映射已并发变更或 DAO 不支持原子条件写入，请重试');
            }

            if (!$this->renewLock($loginLockKey, 30)
                || (new StpLogic($loginType, $this))->getLoginIdByToken($accessToken) !== $loginIdStr) {
                $this->deleteRefreshToken($refreshToken);
                throw new SaTokenException('账号会话锁或 AccessToken 在绑定期间已失效');
            }
        } finally {
            $this->releaseLock($loginLockKey);
        }
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
        $consumptionLockKey = 'refresh-token:' . hash('sha256', $refreshToken);
        if (!$this->acquireLock($consumptionLockKey, 30)) {
            throw new SaTokenException('RefreshToken 正在处理中，请稍后重试');
        }

        try {
            return $this->consumeRefreshTokenLocked($refreshToken);
        } finally {
            $this->releaseLock($consumptionLockKey);
        }
    }

    /** @return array<string, mixed>|null */
    protected function consumeRefreshTokenLocked(string $refreshToken): ?array
    {
        $dao = $this->getDao();
        $refreshKey = self::REFRESH_TOKEN_PREFIX . $refreshToken;
        $snapshot = $dao->get($refreshKey);
        if ($snapshot === null) {
            return null;
        }

        $markerKey = self::REFRESH_TOKEN_USED_PREFIX . hash('sha256', $refreshToken);
        $decodedSnapshot = SaFoxUtil::fromJson($this->decryptValue($snapshot));
        if ($this->getConfig()->isRefreshTokenRotation()
            && is_array($decodedSnapshot)
            && is_string($decodedSnapshot['loginId'] ?? null)
            && is_string($decodedSnapshot['loginType'] ?? null)
            && is_string($decodedSnapshot['accessToken'] ?? null)) {
            // Retain the consumed token's owner until its original expiry. A
            // permanent or sub-second remaining TTL gets a bounded 24-hour
            // replay window so rotated credentials cannot grow storage forever.
            $timeout = $dao->getTimeout($refreshKey);
            $markerTimeout = $timeout > 0 ? $timeout : 86400;
            $dao->set($markerKey, $snapshot, $markerTimeout);
        }

        $raw = $dao->getAndDelete($refreshKey);
        if ($raw === null) {
            if ($this->getConfig()->isRefreshTokenRotation()
                && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
                $dao->compareAndDelete($markerKey, $snapshot);
            }
            return null;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($raw));
        if (!is_array($data)) {
            return null;
        }

        if ($raw !== $snapshot && $this->getConfig()->isRefreshTokenRotation()
            && is_string($data['loginId'] ?? null)
            && is_string($data['loginType'] ?? null)
            && is_string($data['accessToken'] ?? null)) {
            $dao->set($markerKey, $raw, 86400);
        }
        /** @var array<string, mixed> $data */
        $loginId = is_string($data['loginId'] ?? null) ? $data['loginId'] : '';
        $loginType = is_string($data['loginType'] ?? null) ? $data['loginType'] : '';
        $accessToken = is_string($data['accessToken'] ?? null) ? $data['accessToken'] : '';
        if ($loginId !== '' && $loginType !== '' && $accessToken !== '') {
            $dao = $this->getDao();
            $mapKey = self::buildRefreshTokenMapKey($loginId, $loginType, $accessToken);
            $mapped = $dao->get($mapKey);
            if ($mapped !== null && $this->decryptValue($mapped) === $refreshToken
                && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
                $dao->compareAndSet($mapKey, $mapped, null);
            }
        }

        if ($loginId !== '' && $loginType !== '') {
            $this->removeRefreshTokenFromAccountIndex($loginId, $loginType, $refreshToken);
        }

        return $data;
    }

    /** @return array<string, mixed>|null */
    public function getConsumedRefreshTokenData(string $refreshToken): ?array
    {
        $value = $this->getDao()->get(self::REFRESH_TOKEN_USED_PREFIX . hash('sha256', $refreshToken));
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

    public function deleteConsumedRefreshTokenData(string $refreshToken): void
    {
        $this->getDao()->delete(self::REFRESH_TOKEN_USED_PREFIX . hash('sha256', $refreshToken));
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
        $mapKey = self::buildRefreshTokenMapKey($loginIdStr, $loginType, $accessToken);
        $value = $this->getDao()->get($mapKey);
        if ($value === null && !str_contains($loginIdStr, ':') && !str_contains($loginType, ':') && !str_contains($accessToken, ':')) {
            // Legacy tuple keys are safe to read only when every component excludes
            // the delimiter; verify the referenced record before trusting the index.
            $value = $this->getDao()->get(self::buildLegacyRefreshTokenMapKey($loginIdStr, $loginType, $accessToken));
            if ($value !== null) {
                $legacyRefreshToken = $this->decryptValue($value);
                $legacyData = $this->getRefreshTokenData($legacyRefreshToken);
                if (($legacyData['loginId'] ?? null) !== $loginIdStr
                    || ($legacyData['loginType'] ?? null) !== $loginType
                    || ($legacyData['accessToken'] ?? null) !== $accessToken) {
                    return null;
                }
            }
        }
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
                $dao = $this->getDao();
                $mapKey = self::buildRefreshTokenMapKey($loginId, $loginType, $accessToken);
                $mapped = $dao->get($mapKey);
                if ($mapped !== null && $this->decryptValue($mapped) === $refreshToken
                    && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
                    $dao->compareAndSet($mapKey, $mapped, null);
                }
            }
            if ($loginId !== '' && $loginType !== '') {
                $this->removeRefreshTokenFromAccountIndex($loginId, $loginType, $refreshToken);
            }
        }
    }

    protected static function buildRefreshTokenMapKey(mixed $loginId, string $loginType, string $accessToken): string
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        return self::REFRESH_TOKEN_MAP_PREFIX . self::encodeKeyComponent($loginType) . ':'
            . self::encodeKeyComponent($loginIdStr) . ':' . self::encodeKeyComponent($accessToken);
    }

    protected static function buildRefreshTokenAccountKey(string $loginId, string $loginType): string
    {
        return self::REFRESH_TOKEN_ACCOUNT_PREFIX . self::encodeKeyComponent($loginType) . ':'
            . self::encodeKeyComponent($loginId);
    }

    protected function addRefreshTokenToAccountIndex(string $loginId, string $loginType, string $refreshToken, int $timeout): void
    {
        $dao = $this->getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
            throw new SaTokenException('DAO 不支持原子维护 RefreshToken 账号索引');
        }

        $key = self::buildRefreshTokenAccountKey($loginId, $loginType);
        for ($attempt = 0; $attempt < 8; $attempt++) {
            $currentRaw = $dao->get($key);
            $tokens = [];
            if ($currentRaw !== null) {
                $decoded = SaFoxUtil::fromJson($this->decryptValue($currentRaw));
                if (!is_array($decoded)) {
                    throw new SaTokenException('RefreshToken 账号索引格式无效');
                }
                foreach ($decoded as $value) {
                    if (is_string($value) && $value !== '') {
                        $tokens[] = $value;
                    }
                }
            }
            $tokens = array_values(array_unique($tokens));
            if (!in_array($refreshToken, $tokens, true)) {
                $tokens[] = $refreshToken;
            }

            $currentTimeout = $dao->getTimeout($key);
            $indexTimeout = $currentTimeout === -1 || $timeout === -1
                ? null
                : max(1, $currentTimeout, $timeout);
            $nextRaw = $this->encryptValue(SaFoxUtil::toJson($tokens));
            if ($dao->compareAndSet($key, $currentRaw, $nextRaw, $indexTimeout)) {
                return;
            }
        }

        throw new SaTokenException('RefreshToken 账号索引持续并发变更，请重试');
    }

    protected function removeRefreshTokenFromAccountIndex(string $loginId, string $loginType, string $refreshToken): void
    {
        $dao = $this->getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
            throw new SaTokenException('DAO 不支持原子维护 RefreshToken 账号索引');
        }

        $key = self::buildRefreshTokenAccountKey($loginId, $loginType);
        for ($attempt = 0; $attempt < 8; $attempt++) {
            $currentRaw = $dao->get($key);
            if ($currentRaw === null) {
                return;
            }
            $decoded = SaFoxUtil::fromJson($this->decryptValue($currentRaw));
            if (!is_array($decoded)) {
                throw new SaTokenException('RefreshToken 账号索引格式无效');
            }
            $tokens = array_values(array_filter(
                $decoded,
                static fn (mixed $value): bool => is_string($value) && $value !== $refreshToken
            ));
            if (count($tokens) === count($decoded)) {
                return;
            }

            $timeout = $dao->getTimeout($key);
            $effectiveTimeout = $timeout === -1 ? null : max(1, $timeout);
            $nextRaw = $tokens === [] ? null : $this->encryptValue(SaFoxUtil::toJson($tokens));
            if ($dao->compareAndSet($key, $currentRaw, $nextRaw, $effectiveTimeout)) {
                return;
            }
        }

        throw new SaTokenException('RefreshToken 账号索引持续并发变更，请重试');
    }

    protected function deleteRefreshTokensByLoginIdLocked(string $loginId, string $loginType): void
    {
        $dao = $this->getDao();
        $key = self::buildRefreshTokenAccountKey($loginId, $loginType);
        $snapshot = $dao->get($key);
        if ($snapshot === null) {
            return;
        }
        $decoded = SaFoxUtil::fromJson($this->decryptValue($snapshot));
        if (!is_array($decoded)) {
            throw new SaTokenException('RefreshToken 账号索引格式无效');
        }

        foreach ($decoded as $refreshToken) {
            if (!is_string($refreshToken) || $refreshToken === '') {
                continue;
            }
            $data = $this->getRefreshTokenData($refreshToken);
            if (($data['loginId'] ?? null) === $loginId && ($data['loginType'] ?? null) === $loginType) {
                $this->getDao()->delete(self::REFRESH_TOKEN_PREFIX . $refreshToken);
                $accessToken = is_string($data['accessToken'] ?? null) ? $data['accessToken'] : '';
                if ($accessToken !== '') {
                    $mapKey = self::buildRefreshTokenMapKey($loginId, $loginType, $accessToken);
                    $mapped = $dao->get($mapKey);
                    if ($mapped !== null && $this->decryptValue($mapped) === $refreshToken
                        && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
                        $dao->compareAndSet($mapKey, $mapped, null);
                    }
                }
            }
        }

        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
            || !$dao->compareAndSet($key, $snapshot, null)) {
            throw new SaTokenException('RefreshToken 账号索引已并发变更，请重试');
        }
    }

    protected static function buildLegacyRefreshTokenMapKey(string $loginId, string $loginType, string $accessToken): string
    {
        return self::REFRESH_TOKEN_MAP_PREFIX . $loginType . ':' . $loginId . ':' . $accessToken;
    }

    protected function extendLoginIdListTimeout(string $loginId, string $loginType, int $refreshTimeout): void
    {
        $key = self::buildLoginIdKey($loginType, $loginId);
        $currentTimeout = $this->getDao()->getTimeout($key);
        if ($currentTimeout === -2) {
            // A pre-upgrade account may still have a legacy list that is read
            // through the collision-filtered compatibility path. Migrate that
            // list before extending it so old sessions remain revocable too.
            $tokens = $this->getTokenListByLoginId($loginId, $loginType);
            if ($tokens === []) {
                return;
            }

            $timeout = $this->getDao()->getTimeout(self::buildLegacyLoginIdKey($loginType, $loginId));
            $listTimeout = $timeout === -1 || $refreshTimeout === -1 ? null : max(1, $timeout, $refreshTimeout);
            foreach ($tokens as $item) {
                $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
                if ($tokenValue === '') {
                    continue;
                }
                $tokenTimeout = $this->getTokenTimeout($tokenValue);
                if ($tokenTimeout === -1) {
                    $listTimeout = null;
                    break;
                }
                if ($tokenTimeout > 0 && $listTimeout !== null) {
                    $listTimeout = max($listTimeout, $tokenTimeout);
                }
                $linkedRefreshToken = $this->getRefreshTokenByAccessToken($loginId, $loginType, $tokenValue);
                if ($linkedRefreshToken !== null) {
                    $linkedTimeout = $this->getRefreshTokenTimeout($linkedRefreshToken);
                    if ($linkedTimeout === -1) {
                        $listTimeout = null;
                        break;
                    }
                    if ($linkedTimeout > 0 && $listTimeout !== null) {
                        $listTimeout = max($listTimeout, $linkedTimeout);
                    }
                }
            }
            $json = SaFoxUtil::toJson($tokens);
            $dao = $this->getDao();
            if ($dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                && $dao->compareAndSet($key, null, $this->encryptValue($json), $listTimeout)) {
                return;
            }

            // A newer login may have installed the V2 list after the legacy
            // read. Never replace it with the stale migration snapshot.
            $this->extendExistingLoginIdListTimeout($key, $listTimeout);
            return;
        }

        $targetTimeout = $currentTimeout === -1 || $refreshTimeout === -1
            ? null
            : max($currentTimeout, $refreshTimeout);
        $this->extendExistingLoginIdListTimeout($key, $targetTimeout);
    }

    protected function extendExistingLoginIdListTimeout(string $key, ?int $targetTimeout): void
    {
        $dao = $this->getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
            throw new SaTokenException('DAO 不支持安全延长账号会话索引有效期');
        }

        for ($attempt = 0; $attempt < 8; $attempt++) {
            $currentValue = $dao->get($key);
            if ($currentValue === null) {
                throw new SaTokenException('账号会话列表在延长有效期期间已变更，请重试');
            }

            if ($targetTimeout === null) {
                if ($dao->compareAndSet($key, $currentValue, $currentValue, null)) {
                    return;
                }
                continue;
            }

            if ($dao instanceof \SaToken\Dao\SaTokenDaoCompareAndExpireInterface
                && $dao->compareAndExpire($key, $currentValue, $targetTimeout)) {
                return;
            }

            // If the value changed, retry against its latest encoding. If only
            // the TTL changed, compareAndExpire is defined to preserve the
            // longer lifetime and succeeds without shortening it.
            if ($dao->get($key) === $currentValue) {
                throw new SaTokenException('DAO 不支持安全延长账号会话索引有效期');
            }
        }

        throw new SaTokenException('账号会话列表持续并发变更，请重试');
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

    public function revokeStatelessTokensByLoginId(string $loginId, string $loginType): void
    {
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginId);
        if (!$this->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            $key = 'satoken:jwt:revoked-before:' . $loginType . ':' . hash('sha256', $loginId);
            $current = $this->getDao()->get($key);
            $cutoff = microtime(true);
            if ($current !== null && is_numeric($current) && is_finite((float) $current)) {
                $cutoff = max($cutoff, (float) $current);
            }
            // 保留水位而不设置 TTL，避免无过期 JWT 在缓存过期后重新有效。
            $this->getDao()->set($key, sprintf('%.6F', $cutoff));
            $this->deleteRefreshTokensByLoginIdLocked($loginId, $loginType);
        } finally {
            $this->releaseLock($lockKey);
        }
    }

    public function isStatelessTokenRevokedByLoginId(string $loginId, string $loginType, mixed $issuedAt): bool
    {
        $key = 'satoken:jwt:revoked-before:' . $loginType . ':' . hash('sha256', $loginId);
        $cutoff = $this->getDao()->get($key);
        if ($cutoff === null) {
            return false;
        }
        if (!is_numeric($cutoff)
            || !is_finite((float) $cutoff)
            || (float) $cutoff <= 0
            || (!is_int($issuedAt) && !is_float($issuedAt))
            || (is_float($issuedAt) && !is_finite($issuedAt))) {
            return true;
        }

        return (float) $issuedAt < (float) $cutoff;
    }

    public function removeFromBlacklist(string $tokenValue): void
    {
        $this->getDao()->delete(self::BLACKLIST_PREFIX . $tokenValue);
    }

    public const LOCK_PREFIX = 'satoken:lock:';

    public function acquireLock(string $key, int $ttl = 5): bool
    {
        $lockKey = self::LOCK_PREFIX . $key;
        $stateKey = SaTokenContext::getContextId() . "\0" . $lockKey;

        // 可重入：本实例已持有该锁（如 login 持锁调用 deleteToken）时直接放行，
        // 避免嵌套获取导致 5 秒自阻塞。实例会跨请求复用，因此本地所有权必须按
        // 请求/协程上下文隔离；否则另一个协程会被误判为同一持有者并绕过分布式锁。
        if (isset($this->lockValues[$stateKey])) {
            // 本地持有记录不能证明 Redis/DAO 中的租约仍有效：TTL 过期后锁可能已被
            // 其他请求接管。失去所有权时清掉本地重入状态并拒绝本次获取。
            if ($this->getDao()->get($lockKey) !== $this->lockValues[$stateKey]) {
                unset($this->lockValues[$stateKey], $this->lockDepths[$stateKey]);
                return false;
            }

            $this->lockDepths[$stateKey] = ($this->lockDepths[$stateKey] ?? 1) + 1;
            return true;
        }

        $lockValue = bin2hex(random_bytes(8));

        $acquired = \SaToken\Dao\SaTokenDaoLock::acquire($this->getDao(), $lockKey, $lockValue, $ttl > 0 ? $ttl : null);
        if ($acquired) {
            $this->lockValues[$stateKey] = $lockValue;
            $this->lockDepths[$stateKey] = 1;
        }
        return $acquired;
    }

    public function releaseLock(string $key): void
    {
        $lockKey = self::LOCK_PREFIX . $key;
        $stateKey = SaTokenContext::getContextId() . "\0" . $lockKey;
        $lockValue = $this->lockValues[$stateKey] ?? null;
        if ($lockValue === null) {
            return;
        }

        $depth = $this->lockDepths[$stateKey] ?? 1;
        if ($depth > 1) {
            $this->lockDepths[$stateKey] = $depth - 1;
            return;
        }

        $dao = $this->getDao();
        \SaToken\Dao\SaTokenDaoLock::release($dao, $lockKey, $lockValue);

        unset($this->lockValues[$stateKey]);
        unset($this->lockDepths[$stateKey]);
    }

    /** 仅在当前请求上下文仍持有同一租约时续期。 */
    public function renewLock(string $key, int $ttl = 30): bool
    {
        if ($ttl <= 0) {
            return false;
        }

        $lockKey = self::LOCK_PREFIX . $key;
        $stateKey = SaTokenContext::getContextId() . "\0" . $lockKey;
        $lockValue = $this->lockValues[$stateKey] ?? null;
        if ($lockValue === null) {
            return false;
        }

        if (!\SaToken\Dao\SaTokenDaoLock::renew($this->getDao(), $lockKey, $lockValue, $ttl)) {
            unset($this->lockValues[$stateKey], $this->lockDepths[$stateKey]);
            return false;
        }

        return true;
    }
}
