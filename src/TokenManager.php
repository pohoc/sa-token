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
    /** Match the JWT parser ceiling while bounding attacker-controlled DAO keys. */
    public const MAX_TOKEN_VALUE_BYTES = 65536;

    public const TOKEN_PREFIX = 'satoken:login:token:';
    public const LOGIN_ID_PREFIX = 'satoken:login:loginId:';
    public const LOGIN_ID_V2_PREFIX = 'satoken:login:v2:loginId:';
    public const LAST_ACTIVE_PREFIX = 'satoken:login:lastActive:';
    public const SESSION_PREFIX = 'satoken:session:';
    public const TOKEN_SESSION_PREFIX = 'satoken:tokenSession:';
    public const TOKEN_SESSION_LINEAGE_PREFIX = 'satoken:tokenSessionLineage:';
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
    public const JWT_GENERATION_PREFIX = 'satoken:jwt:generation:';

    public static function buildStatelessTokenGenerationKey(string $loginId, string $loginType): string
    {
        return self::JWT_GENERATION_PREFIX . self::encodeKeyComponent($loginType) . ':' . hash('sha256', $loginId);
    }

    public function getStatelessTokenGeneration(string $loginId, string $loginType): int
    {
        $key = self::buildStatelessTokenGenerationKey($loginId, $loginType);
        $value = $this->getDao()->get($key);
        if ($value === null) {
            return 0;
        }

        $value = $this->decryptBoundValue($key, $value);

        $generation = self::parseStatelessTokenGeneration($value);
        if ($generation === null) {
            throw new SaTokenException('无状态 JWT 账号会话版本数据无效');
        }

        return $generation;
    }

    protected static function parseStatelessTokenGeneration(string $value): ?int
    {
        if (preg_match('/^(0|[1-9][0-9]*)$/D', $value) !== 1) {
            return null;
        }

        $generation = filter_var($value, FILTER_VALIDATE_INT);
        return is_int($generation) && $generation >= 0 ? $generation : null;
    }

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

    protected function encryptBoundValue(string $key, string $value): string
    {
        return $this->getEncryptor()->encryptForContext($value, $key);
    }

    protected function decryptBoundValue(string $key, string $value): string
    {
        $decrypted = $this->getEncryptor()->decryptCheckedForContext($value, $key);
        if ($decrypted === null) {
            throw new SaTokenException('Token 存储记录完整性校验失败');
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

    public function saveToken(
        string $tokenValue,
        mixed $loginId,
        string $loginType,
        string $deviceType = '',
        ?int $timeout = null,
        ?string $sessionId = null
    ): string {
        $this->validateTokenValueLength($tokenValue);
        SaTokenTimeout::validate($timeout ?? $this->getConfig()->getTimeout());

        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }

        $loginIdStr = (string) $loginId;
        $sessionId = $sessionId !== null && $sessionId !== '' ? $sessionId : SaFoxUtil::randomString(32);
        $loginLockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->acquireLock($loginLockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            return $this->saveTokenWithLoginLock($tokenValue, $loginId, $loginType, $deviceType, $timeout, $sessionId);
        } finally {
            $this->releaseLock($loginLockKey);
        }
    }

    protected function saveTokenWithLoginLock(
        string $tokenValue,
        mixed $loginId,
        string $loginType,
        string $deviceType,
        ?int $timeout,
        string $sessionId
    ): string {
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
                    $dao = $this->getDao();
                    $tokenKey = self::TOKEN_PREFIX . $tokenValue;
                    if (!$this->isBlacklisted($tokenValue) && !$dao->exists($tokenKey)) {
                        $this->clearTokenBoundState($tokenValue, $loginType);
                        $lineageKey = self::TOKEN_SESSION_LINEAGE_PREFIX . $tokenValue;
                        $lineageValue = $this->encryptBoundValue($lineageKey, SaFoxUtil::toJson([
                            'loginId' => $loginIdStr,
                            'loginType' => $loginType,
                            'sessionId' => $sessionId,
                        ]));
                        // Publish the authenticated owner before the bearer
                        // record. Otherwise a reused token becomes visible
                        // between setIfNotExists() and finalizeToken(), while
                        // a stale account index can claim it for its old type.
                        // The token-value lock is a lease and can expire while
                        // this worker is paused. Claim lineage conditionally so
                        // a stale lock owner cannot overwrite the owner metadata
                        // published by the worker that took over the lease.
                        if (!$dao->setIfNotExists($lineageKey, $lineageValue, $effectiveTimeout)) {
                            continue;
                        }
                        try {
                            if ($dao->setIfNotExists($tokenKey, $this->encryptBoundValue($tokenKey, $loginIdStr), $effectiveTimeout)) {
                                try {
                                    $finalizedToken = $this->finalizeToken(
                                        $tokenValue,
                                        $loginId,
                                        $loginType,
                                        $deviceType,
                                        $effectiveTimeout,
                                        $sessionId
                                    );
                                    $this->updateLastActiveToNow($tokenValue);
                                    return $finalizedToken;
                                } catch (\Throwable $exception) {
                                    // A persistence failure after writing the bearer
                                    // must not leave an orphaned credential behind.
                                    // Revalidate the lease before cleanup, then use
                                    // compare-and-delete so an expired owner cannot
                                    // remove a token issued by the next lock holder.
                                    if ($this->acquireLock($tokenLockKey, 30)) {
                                        try {
                                            $this->rollbackFailedTokenCreation($tokenValue, $loginIdStr, $loginType);
                                        } finally {
                                            $this->releaseLock($tokenLockKey);
                                        }
                                    }
                                    throw $exception;
                                }
                            }
                        } finally {
                            if ($dao->get($tokenKey) === null
                                && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
                                $dao->compareAndDelete($lineageKey, $lineageValue);
                            }
                        }
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
    protected function finalizeToken(
        string $tokenValue,
        mixed $loginId,
        string $loginType,
        string $deviceType,
        ?int $effectiveTimeout,
        string $sessionId
    ): string {
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
                $this->encryptBoundValue($loginIdKey, SaFoxUtil::toJson($existingTokens)),
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

    protected function rollbackFailedTokenCreation(string $tokenValue, string $loginId, string $loginType): void
    {
        $dao = $this->getDao();
        $tokenKey = self::TOKEN_PREFIX . $tokenValue;
        $storedValue = $dao->get($tokenKey);
        if ($storedValue === null || $this->decryptBoundValue($tokenKey, $storedValue) !== $loginId) {
            return;
        }

        $lineageKey = self::TOKEN_SESSION_LINEAGE_PREFIX . $tokenValue;
        $lineageValue = $dao->get($lineageKey);
        if ($lineageValue !== null) {
            $lineage = SaFoxUtil::fromJson($this->decryptBoundValue($lineageKey, $lineageValue));
            if (!is_array($lineage)
                || ($lineage['loginId'] ?? null) !== $loginId
                || ($lineage['loginType'] ?? null) !== $loginType) {
                return;
            }
        }

        $boundStateSnapshots = $this->captureTokenBoundState(
            $this->getTokenBoundStateKeys($tokenValue, $loginType)
        );

        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface
            || !$dao->compareAndDelete($tokenKey, $storedValue)) {
            return;
        }

        $this->deleteTokenBoundStateIfUnchanged($boundStateSnapshots);
    }

    protected function clearTokenBoundState(string $tokenValue, string $loginType): void
    {
        $dao = $this->getDao();
        $dao->delete(self::LAST_ACTIVE_PREFIX . $tokenValue);
        $dao->delete(self::TOKEN_SESSION_PREFIX . $tokenValue);
        $dao->delete(self::TOKEN_SESSION_LINEAGE_PREFIX . $tokenValue);
        $dao->delete(self::FINGERPRINT_PREFIX . $tokenValue);
        $this->clearSwitch($tokenValue, $loginType);

        $services = $this->getSafeServices($tokenValue, $loginType);
        foreach ($services as $service) {
            $dao->delete($this->safeStateKey($tokenValue, $service, $loginType));
        }
        $dao->delete($this->safeServicesKey($tokenValue, $loginType));
    }

    /** @return list<string> */
    protected function getTokenBoundStateKeys(string $tokenValue, string $loginType): array
    {
        $keys = [
            self::LAST_ACTIVE_PREFIX . $tokenValue,
            self::TOKEN_SESSION_PREFIX . $tokenValue,
            self::TOKEN_SESSION_LINEAGE_PREFIX . $tokenValue,
            self::FINGERPRINT_PREFIX . $tokenValue,
            self::buildSwitchKey($tokenValue, $loginType),
            $this->safeServicesKey($tokenValue, $loginType),
        ];
        if (!str_contains($loginType, ':') && !str_contains($loginType, '%')
            && !str_contains($tokenValue, ':') && !str_contains($tokenValue, '%')) {
            $keys[] = self::buildLegacySwitchKey($tokenValue, $loginType);
        }
        foreach ($this->getSafeServices($tokenValue, $loginType) as $service) {
            $keys[] = $this->safeStateKey($tokenValue, $service, $loginType);
        }

        return array_values(array_unique($keys));
    }

    /** @param list<string> $keys
     * @return array<string, string>
     */
    protected function captureTokenBoundState(array $keys): array
    {
        $snapshots = [];
        foreach ($keys as $key) {
            $value = $this->getDao()->get($key);
            if ($value !== null) {
                $snapshots[$key] = $value;
            }
        }

        return $snapshots;
    }

    /** @param array<string, string> $snapshots */
    protected function deleteTokenBoundStateIfUnchanged(array $snapshots): void
    {
        $dao = $this->getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
            throw new SaTokenException('DAO 不支持 Token 状态的原子比较删除');
        }
        foreach ($snapshots as $key => $value) {
            $dao->compareAndDelete($key, $value);
        }
    }

    public function getLoginIdByToken(string $tokenValue): ?string
    {
        if ($tokenValue === '' || strlen($tokenValue) > self::MAX_TOKEN_VALUE_BYTES) {
            return null;
        }

        // Dao 记录是会话存在性的唯一权威来源：
        // logout/kickout/吊销均通过删除该记录实现，因此不存在记录的 Token 一律无效
        $tokenKey = self::TOKEN_PREFIX . $tokenValue;
        $value = $this->getDao()->get($tokenKey);
        if ($value === null) {
            return null;
        }
        try {
            $loginId = $this->decryptBoundValue($tokenKey, $value);
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
            return is_array($legacyList)
                ? $this->filterTokenListForOwner($legacyList, $loginIdStr, $loginType)
                : [];
        }
        // V2 indexes are authenticated to their storage key. Continue reading
        // authenticated pre-context records during upgrade, but validate every
        // live bearer against its own authenticated owner before exposing it.
        $decrypted = $this->getEncryptor()->decryptCheckedForContext($json, $loginIdKey)
            ?? $this->decryptValue($json);
        $list = SaFoxUtil::fromJson($decrypted);
        if (!is_array($list)) {
            return [];
        }
        /** @var array<array<string, mixed>> $list */
        return $this->filterTokenListForOwner($list, $loginIdStr, $loginType);
    }

    /**
     * Do not let a transplanted or stale account index disclose a live bearer
     * owned by another account or login type. Expired/missing bearer entries
     * remain available for refresh-token cleanup and legacy index migration.
     *
     * @param  array<array-key, mixed>     $list
     * @return array<array<string, mixed>>
     */
    protected function filterTokenListForOwner(array $list, string $loginId, string $loginType): array
    {
        $filtered = [];
        foreach ($list as $item) {
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
            if (!is_string($tokenValue) || $tokenValue === '') {
                continue;
            }
            if ($this->getDao()->exists(self::TOKEN_PREFIX . $tokenValue)) {
                if ($this->getLoginIdByToken($tokenValue) !== $loginId) {
                    continue;
                }
                $recordedLoginType = $this->getTokenSessionLoginType($tokenValue);
                if ($recordedLoginType !== null && $recordedLoginType !== $loginType) {
                    continue;
                }
            }
            $filtered[] = $normalized;
        }

        return $filtered;
    }

    /**
     * Read or assign the stable session lineage attached to a stateful token.
     *
     * @return array{loginId: string, sessionId: string}|null
     */
    public function getTokenSessionBinding(string $tokenValue, string $loginType): ?array
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return null;
        }
        $tokenKey = self::TOKEN_PREFIX . $tokenValue;
        $tokenRecord = $this->getDao()->get($tokenKey);
        if ($tokenRecord === null) {
            return null;
        }
        try {
            $loginId = $this->decryptBoundValue($tokenKey, $tokenRecord);
        } catch (SaTokenException) {
            return null;
        }
        if ($loginId === '') {
            return null;
        }

        $preCapturedSessionId = null;
        $sessionLineageKey = self::TOKEN_SESSION_LINEAGE_PREFIX . $tokenValue;
        $sessionValue = $this->getDao()->get($sessionLineageKey);
        $legacyBindingKey = self::TOKEN_SESSION_PREFIX . $tokenValue;
        $legacyBindingValue = null;
        if ($sessionValue !== null) {
            try {
                $sessionData = SaFoxUtil::fromJson($this->decryptBoundValue($sessionLineageKey, $sessionValue));
                if (!is_array($sessionData)
                    || ($sessionData['loginId'] ?? null) !== $loginId
                    || ($sessionData['loginType'] ?? null) !== $loginType
                    || !is_string($sessionData['sessionId'] ?? null)
                    || $sessionData['sessionId'] === '') {
                    return null;
                }
                $preCapturedSessionId = $sessionData['sessionId'];
            } catch (SaTokenException) {
                return null;
            }
        } else {
            // Previous releases placed lineage metadata in TOKEN_SESSION_PREFIX,
            // which is also the public TokenSession data namespace. Migrate only
            // the exact typed sidecar shape and leave user session records alone.
            $legacyBindingValue = $this->getDao()->get($legacyBindingKey);
            if ($legacyBindingValue !== null) {
                try {
                    $legacyData = SaFoxUtil::fromJson($this->decryptValue($legacyBindingValue));
                    if (is_array($legacyData)
                        && array_keys($legacyData) === ['loginId', 'loginType', 'sessionId']
                        && ($legacyData['loginId'] ?? null) === $loginId
                        && ($legacyData['loginType'] ?? null) === $loginType
                        && is_string($legacyData['sessionId'] ?? null)
                        && preg_match('/^[A-Za-z0-9]{32}$/D', $legacyData['sessionId']) === 1) {
                        $preCapturedSessionId = $legacyData['sessionId'];
                    }
                } catch (SaTokenException) {
                    // Do not let unrelated user-owned session data block auth.
                }
            }
        }

        $config = $this->getConfig();
        if ($config->getJwtMode() === 'mixed') {
            $jwt = $this->getJwtInstance();
            if ($jwt->getLoginId($tokenValue) !== $loginId || $jwt->getLoginType($tokenValue) !== $loginType) {
                return null;
            }
        }

        $loginLockKey = 'login:' . $loginType . ':' . hash('sha256', $loginId);
        if (!$this->acquireLock($loginLockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            $loginIdKey = self::buildLoginIdKey($loginType, $loginId);
            $listKey = $loginIdKey;
            $expectedList = $this->getDao()->get($listKey);
            if ($expectedList === null && !str_contains($loginType, '%') && !str_contains($loginId, '%')) {
                $listKey = self::buildLegacyLoginIdKey($loginType, $loginId);
                $expectedList = $this->getDao()->get($listKey);
            }
            if ($expectedList === null) {
                return null;
            }

            $decryptedList = $listKey === $loginIdKey
                ? ($this->getEncryptor()->decryptCheckedForContext($expectedList, $loginIdKey)
                    ?? $this->decryptValue($expectedList))
                : $this->decryptValue($expectedList);
            $list = SaFoxUtil::fromJson($decryptedList);
            if (!is_array($list)) {
                return null;
            }
            $list = $this->filterTokenListForOwner($list, $loginId, $loginType);

            $tokenIsListed = false;
            foreach ($list as $item) {
                if (is_array($item) && ($item['tokenValue'] ?? null) === $tokenValue) {
                    $tokenIsListed = true;
                    break;
                }
            }
            if (!$tokenIsListed) {
                return $preCapturedSessionId !== null
                    ? ['loginId' => $loginId, 'sessionId' => $preCapturedSessionId]
                    : null;
            }

            $sessionId = $preCapturedSessionId ?? SaFoxUtil::randomString(32);
            $tokenTimeout = $this->getDao()->getTimeout(self::TOKEN_PREFIX . $tokenValue);
            $lineageValue = $this->encryptBoundValue($sessionLineageKey, SaFoxUtil::toJson([
                'loginId' => $loginId,
                'loginType' => $loginType,
                'sessionId' => $sessionId,
            ]));
            if ($sessionValue === null) {
                // Lazy migration may race with token-value reuse after a lease
                // or expiry. Never replace lineage already claimed by a new owner.
                if (!$this->getDao()->setIfNotExists(
                    $sessionLineageKey,
                    $lineageValue,
                    $tokenTimeout > 0 ? $tokenTimeout : null
                )) {
                    return null;
                }
            }
            if ($legacyBindingValue !== null && $preCapturedSessionId !== null
                && $this->getDao() instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
                $this->getDao()->compareAndDelete($legacyBindingKey, $legacyBindingValue);
            }

            return ['loginId' => $loginId, 'sessionId' => $sessionId];
        } finally {
            $this->releaseLock($loginLockKey);
        }
    }

    /**
     * Return the login type recorded in a token's authenticated session lineage.
     *
     * `null` means this is a legacy token without lineage metadata. An empty
     * string means lineage exists but is malformed or no longer matches the
     * bearer record, and callers must fail closed.
     */
    public function getTokenSessionLoginType(string $tokenValue): ?string
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return '';
        }
        $tokenKey = self::TOKEN_PREFIX . $tokenValue;
        $tokenRecord = $this->getDao()->get($tokenKey);
        if ($tokenRecord === null) {
            return '';
        }
        try {
            $loginId = $this->decryptBoundValue($tokenKey, $tokenRecord);
        } catch (SaTokenException) {
            return '';
        }
        if ($loginId === '') {
            return '';
        }

        $lineage = $this->getDao()->get(self::TOKEN_SESSION_LINEAGE_PREFIX . $tokenValue);
        if ($lineage !== null) {
            try {
                $data = SaFoxUtil::fromJson($this->decryptBoundValue(self::TOKEN_SESSION_LINEAGE_PREFIX . $tokenValue, $lineage));
            } catch (SaTokenException) {
                return '';
            }
            if (!is_array($data)
                || ($data['loginId'] ?? null) !== $loginId
                || !is_string($data['loginType'] ?? null)
                || $data['loginType'] === ''
                || !is_string($data['sessionId'] ?? null)
                || $data['sessionId'] === '') {
                return '';
            }
            return $data['loginType'];
        }

        // Prior releases stored the typed lineage in TOKEN_SESSION_PREFIX,
        // which is also a public session namespace. Only the exact legacy
        // sidecar shape is authoritative; ordinary user session data is not.
        $legacyBinding = $this->getDao()->get(self::TOKEN_SESSION_PREFIX . $tokenValue);
        if ($legacyBinding !== null) {
            try {
                $data = SaFoxUtil::fromJson($this->decryptValue($legacyBinding));
            } catch (SaTokenException) {
                return null;
            }
            if (is_array($data)
                && array_keys($data) === ['loginId', 'loginType', 'sessionId']
                && ($data['loginId'] ?? null) === $loginId
                && is_string($data['loginType'] ?? null)
                && $data['loginType'] !== ''
                && is_string($data['sessionId'] ?? null)
                && preg_match('/^[A-Za-z0-9]{32}$/D', $data['sessionId']) === 1) {
                return $data['loginType'];
            }
        }

        return null;
    }

    public function getTokenSessionId(string $tokenValue, string $loginType): ?string
    {
        return $this->getTokenSessionBinding($tokenValue, $loginType)['sessionId'] ?? null;
    }

    /**
     * Remove every active access and refresh credential in one rotated session lineage.
     *
     * @return array<string>
     */
    public function deleteTokenSessionById(string $sessionId, mixed $loginId, string $loginType): array
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $loginLockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->acquireLock($loginLockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            $deletedTokens = [];
            foreach ($this->getTokenListByLoginId($loginId, $loginType) as $item) {
                $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
                if ($tokenValue === '' || $this->getTokenSessionId($tokenValue, $loginType) !== $sessionId) {
                    continue;
                }
                $this->deleteRefreshTokenByAccessToken($loginId, $loginType, $tokenValue);
                $this->deleteTokenLocked($tokenValue, $loginId, $loginType);
                $deletedTokens[] = $tokenValue;
            }
            return $deletedTokens;
        } finally {
            $this->releaseLock($loginLockKey);
        }
    }

    public function deleteToken(string $tokenValue, mixed $loginId, string $loginType): void
    {
        $this->validateTokenValueLength($tokenValue);
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
            $dao = $this->getDao();
            $tokenKey = self::TOKEN_PREFIX . $tokenValue;
            $storedTokenRecord = $dao->get($tokenKey);
            if ($storedTokenRecord === null) {
                return;
            }
            // 只有 token 主记录仍属于指定账号，且账号列表确实登记了该 token，
            // 才允许清理它及其关联状态。否则伪造 loginId/loginType 会造成跨账号注销。
            if ($this->getLoginIdByToken($tokenValue) !== $loginIdStr) {
                return;
            }
            // Account indexes can outlive an expired token record. If the
            // bearer value has since been issued to another login type, a
            // stale index in the original type must not revoke the new owner.
            $recordedLoginType = $this->getTokenSessionLoginType($tokenValue);
            if ($recordedLoginType !== null && $recordedLoginType !== $loginType) {
                return;
            }
            $loginIdKey = self::buildLoginIdKey($loginType, $loginIdStr);
            $expectedList = $this->getDao()->get($loginIdKey);
            $existingTokens = $this->getTokenListByLoginId($loginId, $loginType);
            if (!in_array($tokenValue, array_column($existingTokens, 'tokenValue'), true)) {
                return;
            }
            $newTokens = array_values(array_filter($existingTokens, fn ($item) => $item['tokenValue'] !== $tokenValue));
            $boundStateSnapshots = $this->captureTokenBoundState(
                $this->getTokenBoundStateKeys($tokenValue, $loginType)
            );

            // A mixed JWT has no DAO-backed revocation state once this session
            // is deleted. Advance the account generation before removal so a
            // later switch to stateless mode cannot accept that old JWT via
            // the legacy-token compatibility path.
            if ($this->getConfig()->getJwtMode() === 'mixed') {
                $this->advanceStatelessTokenGenerationLocked($loginIdStr, $loginType);
            }

            // The bearer record is the authoritative login state. Revoke it
            // before changing the account index, so a storage failure cannot
            // leave a valid token stranded outside the index and impossible to
            // retry. Keep the token-value lock through cleanup to prevent reuse.
            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface
                || !$dao->compareAndDelete($tokenKey, $storedTokenRecord)) {
                throw new SaTokenException('Token 吊销失败，请重试');
            }

            if ($expectedList !== null) {
                $timeout = $dao->getTimeout($loginIdKey);
                $effectiveTimeout = ($timeout === -1) ? null : max(1, $timeout);
                $newList = $newTokens === [] ? null : $this->encryptBoundValue($loginIdKey, SaFoxUtil::toJson($newTokens));
                if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                    || !$dao->compareAndSet($loginIdKey, $expectedList, $newList, $effectiveTimeout)) {
                    throw new SaTokenException('账号会话列表已并发变更或 DAO 不支持原子条件写入，请重试');
                }
            }
            $this->deleteTokenBoundStateIfUnchanged($boundStateSnapshots);
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

        $tokenSnapshots = [];
        $refreshTokensToDelete = [];
        try {
            // Account-wide logout/kickout also invalidates mixed JWTs already
            // missing from the session index before a future stateless-mode
            // migration can reinterpret them as legacy stateless tokens.
            if ($this->getConfig()->getJwtMode() === 'mixed') {
                $this->advanceStatelessTokenGenerationLocked($loginIdStr, $loginType);
            }

            foreach ($tokens as $item) {
                $renewLocks();
                $tokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
                if ($tokenValue === '') {
                    continue;
                }
                $tokenKey = self::TOKEN_PREFIX . $tokenValue;
                $tokenRecord = $this->getDao()->get($tokenKey);
                if ($tokenRecord === null) {
                    continue;
                }
                // The account index is a revocation aid, not proof that the
                // globally unique bearer is still owned by this account. A
                // stale index entry must not revoke a token that has since
                // been assigned to another account or login type.
                if ($this->getLoginIdByToken($tokenValue) !== $loginIdStr
                    || $this->getDao()->get($tokenKey) !== $tokenRecord) {
                    continue;
                }
                $binding = $this->getTokenSessionBinding($tokenValue, $loginType);
                if ($binding === null || $binding['loginId'] !== $loginIdStr
                    || $this->getDao()->get($tokenKey) !== $tokenRecord) {
                    continue;
                }
                $tokenSnapshots[$tokenValue] = [
                    'record' => $tokenRecord,
                    'boundState' => $this->captureTokenBoundState(
                        $this->getTokenBoundStateKeys($tokenValue, $loginType)
                    ),
                ];
                $refreshToken = $this->getRefreshTokenByAccessToken($loginId, $loginType, $tokenValue);
                if ($refreshToken !== null) {
                    $refreshTokensToDelete[] = $refreshToken;
                }
            }

            $dao = $this->getDao();
            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
                throw new SaTokenException('DAO 不支持 Token 的原子比较删除');
            }
            $sessionIdKey = self::buildSessionId($loginType, $loginIdStr);
            $sessionIdSnapshot = $dao->get($sessionIdKey);
            // Force a lease check immediately before acting on captured
            // generations; the normal renewal interval is intentionally lazy.
            $lastRenewal = 0;
            $renewLocks();

            foreach ($tokenSnapshots as $tokenValue => $snapshot) {
                $renewLocks();
                if (!$dao->compareAndDelete(self::TOKEN_PREFIX . $tokenValue, $snapshot['record'])) {
                    continue;
                }
                $deletedTokens[] = $tokenValue;
                $this->deleteTokenBoundStateIfUnchanged($snapshot['boundState']);
            }
            if ($sessionIdSnapshot !== null) {
                $dao->compareAndDelete($sessionIdKey, $sessionIdSnapshot);
            }

            // Refresh credentials have their own value lock and may be reused
            // independently of this access-token lock. Never include them in
            // the bulk deletion snapshot; re-read and verify each owner under
            // its credential lock instead.
            foreach (array_unique($refreshTokensToDelete) as $refreshToken) {
                $renewLocks();
                $this->deleteRefreshTokenIfOwned($refreshToken, $loginIdStr, $loginType);
            }

            if ($expectedList !== null) {
                $renewLocks();
                if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                    || !$dao->compareAndSet($loginIdKey, $expectedList, null)) {
                    throw new SaTokenException('账号会话列表已并发变更或 DAO 不支持原子条件写入，请重试');
                }
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
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return;
        }
        $config = $this->getConfig();
        if ($config->getActivityTimeout() <= 0) {
            return;
        }

        // The marker intentionally expires after the idle window. Its creation at
        // issuance plus fail-closed handling of a missing marker makes expiry an
        // unambiguous signal that the Token was inactive for too long.
        $key = self::LAST_ACTIVE_PREFIX . $tokenValue;
        $this->getDao()->set($key, $this->encryptBoundValue($key, (string) SaFoxUtil::getTime()), $config->getActivityTimeout());
    }

    public function getLastActiveTime(string $tokenValue): ?int
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return null;
        }
        $key = self::LAST_ACTIVE_PREFIX . $tokenValue;
        $value = $this->getDao()->get($key);
        if ($value === null) {
            return null;
        }
        try {
            $decrypted = $this->decryptBoundValue($key, $value);
        } catch (SaTokenException) {
            return null;
        }
        return (int) $decrypted;
    }

    public function getTokenTimeout(string $tokenValue): int
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return -2;
        }
        return $this->getDao()->getTimeout(self::TOKEN_PREFIX . $tokenValue);
    }

    public function renewTimeout(string $tokenValue, int $timeout): void
    {
        $this->validateTokenValueLength($tokenValue);
        SaTokenTimeout::validate($timeout);
        $this->getDao()->expire(self::TOKEN_PREFIX . $tokenValue, $timeout);
    }

    /** Renew only while the credential is still owned by the expected login type and account. */
    public function renewTimeoutIfOwnedByLoginType(
        string $tokenValue,
        int $timeout,
        string $loginType,
        string $expectedLoginId
    ): bool {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return false;
        }
        SaTokenTimeout::validate($timeout);

        $accountLockKey = 'login:' . $loginType . ':' . hash('sha256', $expectedLoginId);
        if (!$this->acquireLock($accountLockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            $tokenLockKey = $this->tokenValueLockKey($tokenValue);
            if (!$this->acquireLock($tokenLockKey, 30)) {
                throw new SaTokenException('Token 正在签发或注销，请稍后重试');
            }

            try {
                if ($this->getLoginIdByToken($tokenValue) !== $expectedLoginId) {
                    return false;
                }

                $accountTokens = $this->getTokenListByLoginId($expectedLoginId, $loginType);
                if (!in_array($tokenValue, array_column($accountTokens, 'tokenValue'), true)) {
                    return false;
                }

                $this->getDao()->expire(self::TOKEN_PREFIX . $tokenValue, $timeout);
                if ($this->getTokenTimeout($tokenValue) === -2) {
                    return false;
                }

                $this->extendLoginIdListTimeout($expectedLoginId, $loginType, $timeout);
                $this->updateLastActiveToNow($tokenValue);
                return true;
            } finally {
                $this->releaseLock($tokenLockKey);
            }
        } finally {
            $this->releaseLock($accountLockKey);
        }
    }

    public function isTokenValid(string $tokenValue): bool
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return false;
        }
        return $this->getDao()->exists(self::TOKEN_PREFIX . $tokenValue);
    }

    /**
     * Fail closed when login setup fails after the token was persisted but the
     * account lock has already been taken over by another request.
     */
    public function invalidateTokenIfOwnedByLoginType(string $tokenValue, mixed $loginId, string $loginType): bool
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return false;
        }
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $tokenLockKey = $this->tokenValueLockKey($tokenValue);
        $acquired = false;
        for ($attempt = 0; $attempt < 100; $attempt++) {
            if ($this->acquireLock($tokenLockKey, 30)) {
                $acquired = true;
                break;
            }
            if ($attempt < 99) {
                usleep(10_000);
            }
        }
        if (!$acquired) {
            throw new SaTokenException('Token 正在签发或注销，无法完成失败登录清理');
        }

        try {
            if ($this->getLoginIdByToken($tokenValue) !== $loginIdStr) {
                return true;
            }

            $accountTokens = $this->getTokenListByLoginId($loginIdStr, $loginType);
            if (!in_array($tokenValue, array_column($accountTokens, 'tokenValue'), true)) {
                return true;
            }

            $timeout = $this->getTokenTimeout($tokenValue);
            if ($timeout === -2) {
                return true;
            }

            // Keep the bearer value unusable, including through a RefreshToken
            // whose cleanup may have been part of the failed login sequence.
            $this->addToBlacklist($tokenValue, $timeout === -1 ? null : max(1, $timeout));
            return true;
        } finally {
            $this->releaseLock($tokenLockKey);
        }
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
            // A unique generation lets a stale unban detect a newer ban even
            // when the distributed account-lock lease expired mid-operation.
            'revision' => bin2hex(random_bytes(16)),
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
        // Ban and unban must serialize with login and each other. Otherwise a
        // delayed unban can delete a newer ban while disable() is publishing it.
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$this->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            $dao = $this->getDao();
            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
                throw new SaTokenException('DAO 必须实现安全比较删除接口才能解除封禁');
            }
            $current = $dao->get($key);
            if ($current !== null && !$dao->compareAndDelete($key, $current)) {
                throw new SaTokenException('封禁状态已并发变更，拒绝执行过期解封操作');
            }
        } finally {
            $this->releaseLock($lockKey);
        }
    }

    public function openSafe(string $tokenValue, string $service, int $safeTime, string $loginType): void
    {
        $this->validateTokenValueLength($tokenValue);
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
            $servicesKey = $this->safeServicesKey($tokenValue, $loginType);
            $this->getDao()->set(
                $servicesKey,
                $this->encryptBoundValue($servicesKey, SaFoxUtil::toJson($services)),
                $registryTimeout
            );
            $this->getDao()->set(
                $this->safeStateKey($tokenValue, $service, $loginType),
                $this->encryptBoundValue($this->safeStateKey($tokenValue, $service, $loginType), (string) (SaFoxUtil::getTime() + $effectiveSafeTime)),
                $effectiveSafeTime
            );
        } finally {
            $this->releaseLock($tokenLockKey);
        }
    }

    public function isSafe(string $tokenValue, string $service, string $loginType): bool
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return false;
        }
        $value = $this->getDao()->get($this->safeStateKey($tokenValue, $service, $loginType));
        if ($value === null) {
            return false;
        }
        try {
            $decrypted = $this->decryptBoundValue($this->safeStateKey($tokenValue, $service, $loginType), $value);
        } catch (SaTokenException) {
            return false;
        }
        return (int) $decrypted > SaFoxUtil::getTime();
    }

    public function closeSafe(string $tokenValue, string $service, string $loginType): void
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return;
        }
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
                $this->getDao()->set($registryKey, $this->encryptBoundValue($registryKey, SaFoxUtil::toJson($services)), $effectiveTimeout);
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
        try {
            $decrypted = $this->decryptBoundValue($this->safeServicesKey($tokenValue, $loginType), $json);
        } catch (SaTokenException) {
            return [];
        }
        $services = SaFoxUtil::fromJson($decrypted);
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
        $this->validateTokenValueLength($tokenValue);
        if ($switchToId === null || $switchToId === '' || is_bool($switchToId) || !is_scalar($switchToId)) {
            throw new SaTokenException('切换身份必须是非空、非布尔标量');
        }

        $key = self::buildSwitchKey($tokenValue, $loginType);
        // 身份切换跟随 Token 生命周期：Token 过期/被删除后切换关系不应残留；
        // Token 不存在（-2）时直接拒绝写入，避免产生永不回收的孤儿键
        $tokenTimeout = $this->getTokenTimeout($tokenValue);
        if ($tokenTimeout === -2) {
            throw new SaTokenException('Token 不存在，无法切换身份');
        }
        $effectiveTimeout = ($tokenTimeout > 0) ? $tokenTimeout : null;
        $this->getDao()->set($key, $this->encryptBoundValue($key, SaFoxUtil::toString($switchToId)), $effectiveTimeout);
    }

    public function getSwitchTo(string $tokenValue, string $loginType): ?string
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return null;
        }
        $dao = $this->getDao();
        $key = self::buildSwitchKey($tokenValue, $loginType);
        $value = $dao->get($key);
        if ($value === null
            && !str_contains($loginType, ':') && !str_contains($loginType, '%')
            && !str_contains($tokenValue, ':') && !str_contains($tokenValue, '%')) {
            // Keep unambiguous legacy keys readable during upgrade. Delimiters and
            // escape markers must never fall back to the collision-prone namespace:
            // a legacy '%' can alias the encoded spelling of another token's key.
            $legacyValue = $dao->get(self::buildLegacySwitchKey($tokenValue, $loginType));
            if ($legacyValue !== null && !$this->getEncryptor()->isEnabled()) {
                $value = $legacyValue;
            }
        }
        if ($value === null) {
            return null;
        }
        try {
            return $this->decryptBoundValue($key, $value);
        } catch (SaTokenException) {
            return null;
        }
    }

    public function clearSwitch(string $tokenValue, string $loginType): void
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return;
        }
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
        $this->validateTokenValueLength($refreshToken);
        $this->validateTokenValueLength($accessToken);
        SaTokenTimeout::validate($timeout, 'RefreshToken');

        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }

        $loginIdStr = (string) $loginId;
        $loginLockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        $credentialLockKey = 'refresh-credential:' . hash('sha256', $refreshToken);
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
                'refreshToken' => $refreshToken,
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
            if (!$this->acquireLock($credentialLockKey, 30)) {
                throw new SaTokenException('RefreshToken 正在签发或消费，请稍后重试');
            }
            try {
                // In rotation mode a consumed token's replay marker must remain
                // authoritative until its retention expires. Re-registering the
                // same bearer value would turn that old credential valid again.
                if ($this->getConfig()->isRefreshTokenRotation()
                    && $this->getDao()->exists(self::REFRESH_TOKEN_USED_PREFIX . hash('sha256', $refreshToken))) {
                    throw new SaTokenException('RefreshToken 值冲突：该凭据已消费，拒绝重新签发');
                }
                // Access and refresh credentials are independent bearer classes.
                // A shared raw value would make a refresh credential usable in an
                // access-token slot (and can overwrite/revoke the wrong record).
                if ($this->getDao()->exists(self::TOKEN_PREFIX . $refreshToken)) {
                    throw new SaTokenException('RefreshToken 值冲突：与现有 AccessToken 重复');
                }
                if (!$this->renewLock($credentialLockKey, 30)) {
                    throw new SaTokenException('RefreshToken 凭据锁已失效，拒绝重新签发');
                }
                $refreshRaw = $this->encryptValue($data);
                if (!$this->renewLock($loginLockKey, 30)
                    || (new StpLogic($loginType, $this))->getLoginIdByToken($accessToken) !== $loginIdStr) {
                    throw new SaTokenException('账号会话锁或 AccessToken 已失效，拒绝绑定 RefreshToken');
                }
                // Register the credential before writing it. If the process stops
                // between these writes, account revocation still knows which key to
                // inspect; a stale index entry without a credential is harmless.
                $this->addRefreshTokenToAccountIndex($loginIdStr, $loginType, $refreshToken, $timeout);
                if (!$this->renewLock($credentialLockKey, 30)
                    || ($this->getConfig()->isRefreshTokenRotation()
                        && $this->getDao()->exists(self::REFRESH_TOKEN_USED_PREFIX . hash('sha256', $refreshToken)))) {
                    $this->removeRefreshTokenFromAccountIndex($loginIdStr, $loginType, $refreshToken);
                    throw new SaTokenException('RefreshToken 已消费或凭据锁已失效，拒绝重新签发');
                }
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
                $this->releaseLock($credentialLockKey);
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
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return null;
        }
        $value = $this->getDao()->get(self::REFRESH_TOKEN_PREFIX . $refreshToken);
        if ($value === null) {
            return null;
        }
        return $this->decodeRefreshTokenRecord($refreshToken, $value);
    }

    /** @return array<string, mixed>|null */
    protected function decodeRefreshTokenRecord(string $refreshToken, string $value): ?array
    {
        $data = SaFoxUtil::fromJson($this->decryptValue($value));
        if (!is_array($data)) {
            return null;
        }
        /** @var array<string, mixed> $data */
        if (!is_string($data['refreshToken'] ?? null)
            || !hash_equals($refreshToken, $data['refreshToken'])) {
            return null;
        }
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
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return null;
        }
        // Issuance and consumption must serialize on the same lock. Otherwise
        // a stale issuer can pass the replay-marker check while a consumer is
        // about to mark and delete this credential, then re-register its bearer.
        $consumptionLockKey = 'refresh-credential:' . hash('sha256', $refreshToken);
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
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return null;
        }
        $dao = $this->getDao();
        $refreshKey = self::REFRESH_TOKEN_PREFIX . $refreshToken;
        $snapshot = $dao->get($refreshKey);
        if ($snapshot === null) {
            return null;
        }

        $snapshotData = SaFoxUtil::fromJson($this->decryptValue($snapshot));
        if (!is_array($snapshotData)
            || !is_string($snapshotData['refreshToken'] ?? null)
            || !hash_equals($refreshToken, $snapshotData['refreshToken'])) {
            return null;
        }

        $markerKey = self::REFRESH_TOKEN_USED_PREFIX . hash('sha256', $refreshToken);
        $markerTimeout = 86400;
        $decodedSnapshot = $snapshotData;
        if ($this->getConfig()->isRefreshTokenRotation()
            && is_string($decodedSnapshot['loginId'] ?? null)
            && is_string($decodedSnapshot['loginType'] ?? null)
            && is_string($decodedSnapshot['accessToken'] ?? null)) {
            // Retain the consumed token's owner until its original expiry.
            // Permanent credentials need a permanent marker so replay can still
            // revoke their live descendants; only an already-missing/near-expiry
            // TTL falls back to a bounded 24-hour replay window.
            $timeout = $dao->getTimeout($refreshKey);
            $markerTimeout = $timeout === -1 ? null : ($timeout > 0 ? $timeout : 86400);
            $dao->set($markerKey, $snapshot, $markerTimeout);
        }

        $raw = $dao->getAndDelete($refreshKey);
        if ($raw === null) {
            // A concurrent consumer may have won after our lease expired. The
            // marker is the only evidence that lets the resumed request detect
            // reuse and revoke the winner's descendant session; never erase it
            // merely because this request did not consume the credential.
            return null;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($raw));
        if (!is_array($data)
            || !is_string($data['refreshToken'] ?? null)
            || !hash_equals($refreshToken, $data['refreshToken'])) {
            return null;
        }

        if ($raw !== $snapshot && $this->getConfig()->isRefreshTokenRotation()
            && is_string($data['loginId'] ?? null)
            && is_string($data['loginType'] ?? null)
            && is_string($data['accessToken'] ?? null)) {
            $dao->set($markerKey, $raw, $markerTimeout);
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
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return null;
        }
        $value = $this->getDao()->get(self::REFRESH_TOKEN_USED_PREFIX . hash('sha256', $refreshToken));
        if ($value === null) {
            return null;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($value));
        if (!is_array($data)
            || !is_string($data['refreshToken'] ?? null)
            || !hash_equals($refreshToken, $data['refreshToken'])) {
            return null;
        }
        /** @var array<string, mixed> $data */
        return $data;
    }

    public function deleteConsumedRefreshTokenData(string $refreshToken): void
    {
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return;
        }
        $this->getDao()->delete(self::REFRESH_TOKEN_USED_PREFIX . hash('sha256', $refreshToken));
    }

    /**
     * 获取 RefreshToken 的剩余有效期（秒），-1 表示永不过期，-2 表示不存在
     */
    public function getRefreshTokenTimeout(string $refreshToken): int
    {
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return -2;
        }
        return $this->getDao()->getTimeout(self::REFRESH_TOKEN_PREFIX . $refreshToken);
    }

    public function getRefreshTokenByAccessToken(mixed $loginId, string $loginType, string $accessToken): ?string
    {
        if (!$this->isTokenValueWithinLimit($accessToken)) {
            return null;
        }
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
        try {
            $refreshToken = $this->decryptValue($value);
        } catch (SaTokenException) {
            return null;
        }
        $data = $this->getRefreshTokenData($refreshToken);
        if (($data['loginId'] ?? null) !== $loginIdStr
            || ($data['loginType'] ?? null) !== $loginType
            || ($data['accessToken'] ?? null) !== $accessToken) {
            return null;
        }
        return $refreshToken;
    }

    public function deleteRefreshToken(string $refreshToken): void
    {
        $this->validateTokenValueLength($refreshToken);
        $credentialLockKey = 'refresh-credential:' . hash('sha256', $refreshToken);
        if (!$this->acquireLock($credentialLockKey, 30)) {
            throw new SaTokenException('RefreshToken 正在签发或消费，请稍后重试');
        }

        try {
            $this->deleteRefreshTokenUnderLock($refreshToken);
        } finally {
            $this->releaseLock($credentialLockKey);
        }
    }

    protected function deleteRefreshTokenIfOwned(string $refreshToken, string $loginId, string $loginType): void
    {
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return;
        }
        $credentialLockKey = 'refresh-credential:' . hash('sha256', $refreshToken);
        if (!$this->acquireLock($credentialLockKey, 30)) {
            throw new SaTokenException('RefreshToken 正在签发或消费，请稍后重试');
        }

        try {
            $this->deleteRefreshTokenUnderLock($refreshToken, $loginId, $loginType, false);
        } finally {
            $this->releaseLock($credentialLockKey);
        }
    }

    protected function deleteRefreshTokenUnderLock(
        string $refreshToken,
        ?string $expectedLoginId = null,
        ?string $expectedLoginType = null,
        bool $removeAccountIndex = true
    ): void {
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return;
        }
        $dao = $this->getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
            throw new SaTokenException('DAO 不支持 RefreshToken 的原子比较删除');
        }
        $refreshKey = self::REFRESH_TOKEN_PREFIX . $refreshToken;
        $snapshot = $dao->get($refreshKey);
        if ($snapshot === null) {
            return;
        }
        $data = $this->decodeRefreshTokenRecord($refreshToken, $snapshot);
        if ($expectedLoginId !== null && $expectedLoginType !== null
            && (($data['loginId'] ?? null) !== $expectedLoginId || ($data['loginType'] ?? null) !== $expectedLoginType)) {
            return;
        }
        if (!$dao->compareAndDelete($refreshKey, $snapshot)) {
            return;
        }
        // A lease may expire during the conditional delete. Leave stale
        // indexes behind rather than letting an old owner clean metadata
        // belonging to a newly issued credential with the same value.
        if (!$this->renewLock('refresh-credential:' . hash('sha256', $refreshToken), 30) || $data === null) {
            return;
        }

        $loginId = is_string($data['loginId'] ?? null) ? $data['loginId'] : '';
        $loginType = is_string($data['loginType'] ?? null) ? $data['loginType'] : '';
        $accessToken = is_string($data['accessToken'] ?? null) ? $data['accessToken'] : '';
        if ($loginId !== '' && $accessToken !== '') {
            $mapKey = self::buildRefreshTokenMapKey($loginId, $loginType, $accessToken);
            $mapped = $dao->get($mapKey);
            if ($mapped !== null && $this->decryptValue($mapped) === $refreshToken
                && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
                $dao->compareAndSet($mapKey, $mapped, null);
            }
        }
        if ($removeAccountIndex && $loginId !== '' && $loginType !== '') {
            $this->removeRefreshTokenFromAccountIndex($loginId, $loginType, $refreshToken);
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
        $loginLockKey = 'login:' . $loginType . ':' . hash('sha256', $loginId);
        if (!$this->renewLock($loginLockKey, 30)) {
            throw new SaTokenException('账号会话锁租约已失效，请重试');
        }

        $key = self::buildRefreshTokenAccountKey($loginId, $loginType);
        $snapshot = $dao->get($key);
        // The account lock may expire while the backing DAO is reading this
        // index. Revalidate ownership before trusting the snapshot: otherwise
        // a stale logout could read and delete RefreshTokens registered by a
        // newer login that took over the lease during that read.
        if (!$this->renewLock($loginLockKey, 30)) {
            throw new SaTokenException('账号会话锁租约已失效，请重试');
        }
        if ($snapshot === null) {
            return;
        }
        $decoded = SaFoxUtil::fromJson($this->decryptValue($snapshot));
        if (!is_array($decoded)) {
            throw new SaTokenException('RefreshToken 账号索引格式无效');
        }

        foreach ($decoded as $refreshToken) {
            if (!$this->renewLock($loginLockKey, 30)) {
                throw new SaTokenException('账号会话锁租约已失效，请重试');
            }
            if (!is_string($refreshToken) || $refreshToken === '') {
                continue;
            }
            $this->deleteRefreshTokenIfOwned($refreshToken, $loginId, $loginType);
        }

        if (!$this->renewLock($loginLockKey, 30)) {
            throw new SaTokenException('账号会话锁租约已失效，请重试');
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
                && $dao->compareAndSet($key, null, $this->encryptBoundValue($key, $json), $listTimeout)) {
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
        if (!$this->isTokenValueWithinLimit($refreshToken)) {
            return false;
        }
        return $this->getDao()->exists(self::REFRESH_TOKEN_PREFIX . $refreshToken);
    }

    public function saveFingerprint(string $tokenValue, string $fingerprint, ?int $timeout = null): void
    {
        $this->validateTokenValueLength($tokenValue);
        $effectiveTimeout = ($timeout === -1) ? null : $timeout;
        $key = self::FINGERPRINT_PREFIX . $tokenValue;
        $this->getDao()->set($key, $this->encryptBoundValue($key, $fingerprint), $effectiveTimeout);
    }

    public function getFingerprint(string $tokenValue): ?string
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return null;
        }
        $key = self::FINGERPRINT_PREFIX . $tokenValue;
        $value = $this->getDao()->get($key);
        if ($value === null) {
            return null;
        }
        try {
            return $this->decryptBoundValue($key, $value);
        } catch (SaTokenException) {
            return null;
        }
    }

    public function deleteFingerprint(string $tokenValue): void
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return;
        }
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
        $this->validateTokenValueLength($tokenValue);
        $this->getDao()->set(self::BLACKLIST_PREFIX . $tokenValue, '1', ($timeout !== null && $timeout > 0) ? $timeout : null);
    }

    public function isBlacklisted(string $tokenValue): bool
    {
        if ($tokenValue === '' || strlen($tokenValue) > self::MAX_TOKEN_VALUE_BYTES) {
            return false;
        }
        return $this->getDao()->exists(self::BLACKLIST_PREFIX . $tokenValue);
    }

    protected function validateTokenValueLength(string $tokenValue): void
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            throw new SaTokenException('Token 长度无效，最大为 ' . self::MAX_TOKEN_VALUE_BYTES . ' 字节');
        }
    }

    protected function isTokenValueWithinLimit(string $tokenValue): bool
    {
        return $tokenValue !== '' && strlen($tokenValue) <= self::MAX_TOKEN_VALUE_BYTES;
    }

    public function revokeStatelessTokensByLoginId(string $loginId, string $loginType): void
    {
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginId);
        if (!$this->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }
        try {
            $this->advanceStatelessTokenGenerationLocked($loginId, $loginType);

            // Keep the timestamp watermark for tokens issued by older versions;
            // current tokens use the monotonic generation and do not depend on
            // synchronized clocks across application nodes.
            $key = 'satoken:jwt:revoked-before:' . $loginType . ':' . hash('sha256', $loginId);
            $current = $this->getDao()->get($key);
            $cutoff = microtime(true);
            if ($current !== null) {
                $currentCutoff = $this->decryptBoundValue($key, $current);
                if (is_numeric($currentCutoff) && is_finite((float) $currentCutoff)) {
                    $cutoff = max($cutoff, (float) $currentCutoff);
                }
            }
            // 保留水位而不设置 TTL，避免无过期 JWT 在缓存过期后重新有效。
            $this->getDao()->set($key, $this->encryptBoundValue($key, sprintf('%.6F', $cutoff)));
            $this->deleteRefreshTokensByLoginIdLocked($loginId, $loginType);
        } finally {
            $this->releaseLock($lockKey);
        }
    }

    /** Caller must hold the account login lock. */
    protected function advanceStatelessTokenGenerationLocked(string $loginId, string $loginType): void
    {
        $generationKey = self::buildStatelessTokenGenerationKey($loginId, $loginType);
        $currentGeneration = $this->getStatelessTokenGeneration($loginId, $loginType);
        if ($currentGeneration === PHP_INT_MAX) {
            throw new SaTokenException('无状态 JWT 账号会话版本更新失败');
        }
        $nextGeneration = (string) ($currentGeneration + 1);
        if (!$this->getEncryptor()->isEnabled()) {
            if ($this->getDao()->increment($generationKey) !== $currentGeneration + 1) {
                throw new SaTokenException('无状态 JWT 账号会话版本更新失败');
            }
            return;
        }

        $dao = $this->getDao();
        $currentRaw = $dao->get($generationKey);
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
            || !$dao->compareAndSet(
                $generationKey,
                $currentRaw,
                $this->encryptBoundValue($generationKey, $nextGeneration)
            )) {
            throw new SaTokenException('无状态 JWT 账号会话版本更新失败');
        }
    }

    public function isStatelessTokenRevokedByLoginId(
        string $loginId,
        string $loginType,
        mixed $issuedAt,
        mixed $tokenGeneration = null
    ): bool {
        try {
            $currentGeneration = $this->getStatelessTokenGeneration($loginId, $loginType);
        } catch (SaTokenException) {
            return true;
        }
        if ($tokenGeneration !== null) {
            return !is_int($tokenGeneration) || $tokenGeneration < 0 || $tokenGeneration !== $currentGeneration;
        }
        // A legacy token without the generation claim cannot be proven to have
        // been minted after a versioned account logout.
        if ($currentGeneration > 0) {
            return true;
        }

        $key = 'satoken:jwt:revoked-before:' . $loginType . ':' . hash('sha256', $loginId);
        $storedCutoff = $this->getDao()->get($key);
        if ($storedCutoff === null) {
            return false;
        }
        try {
            $cutoff = $this->decryptBoundValue($key, $storedCutoff);
        } catch (SaTokenException) {
            return true;
        }
        if (!is_numeric($cutoff)
            || !is_finite((float) $cutoff)
            || (float) $cutoff <= 0
            || (!is_int($issuedAt) && !is_float($issuedAt))
            || (is_float($issuedAt) && !is_finite($issuedAt))) {
            return true;
        }

        // Equal timestamps are ambiguous at the storage precision: the token
        // may have been issued just before logout in the same microsecond.
        // Fail closed so the revocation boundary cannot leave that token live.
        return (float) $issuedAt <= (float) $cutoff;
    }

    public function removeFromBlacklist(string $tokenValue): void
    {
        if (!$this->isTokenValueWithinLimit($tokenValue)) {
            return;
        }
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

    /**
     * 仅在当前请求上下文仍持有同一租约时续期。
     *
     * @phpstan-impure
     */
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
