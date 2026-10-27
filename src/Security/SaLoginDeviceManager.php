<?php

declare(strict_types=1);

namespace SaToken\Security;

use SaToken\Data\SaLoginDevice;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\StpLogic;
use SaToken\Util\SaFoxUtil;
use SaToken\Util\SaTokenContext;
use SaToken\Util\SaTokenEncryptor;

class SaLoginDeviceManager
{
    protected static string $keyPrefix = 'satoken:security:device:';

    public static function setKeyPrefix(string $prefix): void
    {
        self::$keyPrefix = $prefix;
    }

    public static function getKeyPrefix(): string
    {
        return self::$keyPrefix;
    }

    public static function getKey(mixed $loginId, string $loginType = 'login'): string
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        return self::$keyPrefix . 'v2:' . \SaToken\TokenManager::encodeKeyComponent($loginType) . ':' . hash('sha256', $loginIdStr);
    }

    public static function registerDevice(mixed $loginId, string $loginType = 'login', ?SaLoginDevice $device = null, ?string $tokenValue = null, ?StpLogic $logicInstance = null): SaLoginDevice
    {
        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }

        $dao = SaToken::getDao();

        if ($device === null) {
            $device = new SaLoginDevice();
            $device->setDeviceType(self::detectDeviceType());
            $device->setDeviceName(self::detectDeviceName());
            $device->setOs(self::detectOs());
            $device->setBrowser(self::detectBrowser());
        }

        $device->setLoginType($loginType);
        $device->setLoginTime(time());

        if ($tokenValue !== null) {
            $device->setTokenValue($tokenValue);
        }

        $config = SaToken::getConfig();
        $timeout = $config->getTimeout();
        if ($timeout > 0) {
            $device->setExpireAt(time() + $timeout);
        }

        $key = self::getKey($loginId, $loginType);
        $key .= ':' . $device->getDeviceId();

        $loginIdStr = (string) $loginId;
        $logic = $logicInstance ?? SaToken::getStpLogic($loginType);
        if ($logic->getLoginType() !== $loginType) {
            throw new SaTokenException('设备管理 loginType 与 StpLogic 实例不匹配');
        }
        $tokenManager = $logic->getTokenManager();
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        $kickoutEvents = [];
        try {
            $tokenValues = [];
            $expectedRecord = $dao->get($key);
            if ($expectedRecord === null) {
                // Keep device records written with the previous ID algorithm
                // usable after upgrading. The record key remains stable until
                // it is explicitly removed or replaced.
                foreach (self::loadDeviceRecords($loginId, $loginType, false) as $record) {
                    if ($record['device']->getDeviceId() === $device->getDeviceId()) {
                        $key = $record['key'];
                        $expectedRecord = $record['raw'];
                        break;
                    }
                }
            }
            foreach (self::loadDeviceTokenValues($key, $expectedRecord) as $existingToken) {
                if ($logic->getLoginIdByToken($existingToken) === $loginIdStr) {
                    $tokenValues[] = $existingToken;
                }
            }
            if ($tokenValue !== null && $tokenValue !== '') {
                if ($logic->getLoginIdByToken($tokenValue) !== $loginIdStr) {
                    throw new SaTokenException('设备 Token 与账号不匹配');
                }
                $tokenValues[] = $tokenValue;
            }
            $tokenValues = array_values(array_unique($tokenValues));

            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                || !$dao->compareAndSet(
                    $key,
                    $expectedRecord,
                    self::encodeDevice($device, $tokenValues),
                    $timeout > 0 ? $timeout + 60 : null
                )) {
                throw new SaTokenException('设备记录已并发变更或 DAO 不支持原子条件写入，请重试');
            }
        } finally {
            $tokenManager->releaseLock($lockKey);
        }

        return $device;
    }

    /**
     * @return array<SaLoginDevice>
     */
    public static function getDeviceList(mixed $loginId, string $loginType = 'login'): array
    {
        return self::loadDeviceList($loginId, $loginType, false);
    }

    /**
     * @return array<SaLoginDevice>
     */
    protected static function loadDeviceList(mixed $loginId, string $loginType, bool $includeToken): array
    {
        return array_map(
            static fn (array $record): SaLoginDevice => $record['device'],
            self::loadDeviceRecords($loginId, $loginType, $includeToken)
        );
    }

    /** @return array<array{device: SaLoginDevice, key: string, raw: string}> */
    protected static function loadDeviceRecords(mixed $loginId, string $loginType, bool $includeToken): array
    {
        $dao = SaToken::getDao();
        $keyPrefix = self::getKey($loginId, $loginType) . ':';
        // Take one stable key snapshot. Offset pagination can become stale when
        // an expiring record disappears between pages and abort a bulk
        // kickout/cleanup after only part of the operation has completed.
        $keys = $dao->searchKeys($keyPrefix, '', 0, PHP_INT_MAX);

        $devices = [];
        foreach ($keys as $key) {
            if (!is_string($key) || !str_starts_with($key, $keyPrefix)) {
                continue;
            }
            $value = $dao->get($key);
            if ($value === null || $value === '') {
                continue;
            }
            $data = @json_decode($value, true);
            if (!is_array($data)) {
                continue;
            }
            // A key prefix can contain another login type when callers use a
            // directly constructed StpLogic with a delimiter-bearing type.
            // Treat the stored type as the owner boundary before exposing metadata.
            if (($data['loginType'] ?? 'login') !== $loginType) {
                continue;
            }
            $data = self::decodeDeviceData($data, $includeToken);
            $device = new SaLoginDevice($data);
            if (!$includeToken) {
                $device->setTokenValue('');
            }
            $devices[] = ['device' => $device, 'key' => $key, 'raw' => $value];
        }

        usort($devices, fn ($a, $b) => $b['device']->getLoginTime() - $a['device']->getLoginTime());
        return $devices;
    }

    public static function getDeviceCount(mixed $loginId, string $loginType = 'login'): int
    {
        return count(self::getDeviceList($loginId, $loginType));
    }

    public static function kickoutDevice(mixed $loginId, string $deviceId, string $loginType = 'login', ?StpLogic $logicInstance = null): void
    {
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType) . ':' . $deviceId;

        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $logic = $logicInstance ?? SaToken::getStpLogic($loginType);
        if ($logic->getLoginType() !== $loginType) {
            throw new SaTokenException('设备管理 loginType 与 StpLogic 实例不匹配');
        }
        $tokenManager = $logic->getTokenManager();
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        $kickoutEvents = [];
        $lastRenewal = hrtime(true);
        try {
            // A caller-supplied device ID can contain delimiters and address a
            // nested login type's key. Verify the stored owner before revoking
            // any tokens or deleting the record.
            $expectedRecord = $dao->get($key);
            if ($expectedRecord === null) {
                $record = self::findDeviceRecordById($loginId, $deviceId, $loginType);
                if ($record !== null) {
                    $key = $record['key'];
                    $expectedRecord = $record['raw'];
                }
            }
            if ($expectedRecord === null) {
                return;
            }
            $deviceData = @json_decode($expectedRecord, true);
            if (!is_array($deviceData) || ($deviceData['loginType'] ?? 'login') !== $loginType) {
                return;
            }

            // 同一设备标识可能在 isShare=false 时关联多个有效登录 Token。
            // 全部撤销后再删除记录，避免只踢掉最近一次登录而留下旧会话。
            foreach (self::loadDeviceTokenValues($key, $expectedRecord) as $tokenValue) {
                if (hrtime(true) - $lastRenewal >= 10_000_000_000) {
                    if (!$tokenManager->renewLock($lockKey, 30)) {
                        throw new SaTokenException('账号会话锁租约已失效，请重试');
                    }
                    $lastRenewal = hrtime(true);
                }
                if ($logic->getLoginIdByToken($tokenValue) !== $loginIdStr) {
                    continue;
                }
                $eventLoginId = $logic->kickoutByTokenValue($tokenValue, false);
                if ($eventLoginId !== null) {
                    $kickoutEvents[] = [$eventLoginId, $tokenValue];
                }
            }

            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                || !$dao->compareAndSet($key, $expectedRecord, null)) {
                throw new SaTokenException('设备记录已并发变更或 DAO 不支持原子条件写入，请重试');
            }
        } finally {
            $tokenManager->releaseLock($lockKey);
            foreach ($kickoutEvents as [$eventLoginId, $tokenValue]) {
                SaToken::getEvent()->onKickout($loginType, $eventLoginId, $tokenValue);
            }
        }
    }

    public static function kickoutAllDevices(mixed $loginId, string $loginType = 'login', ?string $exceptToken = null): int
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        if (SaToken::getConfig()->isJwtStateless() && $exceptToken !== null
            && !SaToken::getConfig()->isDeviceManagement()) {
            throw new SaTokenException('无状态 JWT 保留指定 Token 踢出需要启用设备管理，才能枚举并撤销其他令牌');
        }
        $logic = SaToken::getStpLogic($loginType);
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        $tokenManager = $logic->getTokenManager();
        if (!$tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        $kickoutEvents = [];
        $lastRenewal = hrtime(true);
        $renewAccountLock = static function () use ($tokenManager, $lockKey, &$lastRenewal): void {
            if (hrtime(true) - $lastRenewal < 10_000_000_000) {
                return;
            }
            if (!$tokenManager->renewLock($lockKey, 30)) {
                throw new SaTokenException('账号会话锁租约已失效，请重试');
            }
            $lastRenewal = hrtime(true);
        };
        try {
            if (SaToken::getConfig()->isJwtStateless()) {
                if ($exceptToken === null) {
                    $logic->kickout($loginId);
                    $devices = self::loadDeviceRecords($loginId, $loginType, true);
                    foreach ($devices as $record) {
                        $renewAccountLock();
                        $dao = SaToken::getDao();
                        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                            || !$dao->compareAndSet($record['key'], $record['raw'], null)) {
                            throw new SaTokenException('设备记录已并发变更或 DAO 不支持原子条件写入，请重试');
                        }
                    }
                    return count($devices);
                }

                $devices = self::loadDeviceRecords($loginId, $loginType, true);
                $count = 0;
                foreach ($devices as $record) {
                    $renewAccountLock();
                    $device = $record['device'];
                    $deviceKey = $record['key'];
                    $remainingTokens = [];
                    $revokedToken = false;
                    foreach (self::loadDeviceTokenValues($deviceKey, $record['raw']) as $tokenValue) {
                        $renewAccountLock();
                        if ($tokenValue === $exceptToken) {
                            $remainingTokens[] = $tokenValue;
                            continue;
                        }
                        if ($logic->getLoginIdByToken($tokenValue) !== $loginIdStr) {
                            continue;
                        }
                        $eventLoginId = $logic->kickoutByTokenValue($tokenValue, false);
                        if ($eventLoginId !== null) {
                            $kickoutEvents[] = [$eventLoginId, $tokenValue];
                            $revokedToken = true;
                        }
                    }

                    if ($remainingTokens !== []) {
                        // A device can hold several non-shared tokens. Preserve only
                        // the explicitly exempted bearer, not every token on that device.
                        $device->setTokenValue($exceptToken);
                        $updated = SaToken::getDao() instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                            && SaToken::getDao()->compareAndSet(
                                $deviceKey,
                                $record['raw'],
                                self::encodeDevice($device, $remainingTokens)
                            );
                    } else {
                        $updated = SaToken::getDao() instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                            && SaToken::getDao()->compareAndSet($deviceKey, $record['raw'], null);
                    }
                    if (!$updated) {
                        throw new SaTokenException('设备记录已并发变更或 DAO 不支持原子条件写入，请重试');
                    }
                    if ($revokedToken) {
                        $count++;
                    }
                }
                return $count;
            }

            // The session list is the authoritative index for stateful logins;
            // DAO search is optional and unavailable in PSR-16 adapters.
            $tokenManager = $logic->getTokenManager();
            $sessions = $tokenManager->getTokenListByLoginId($loginId, $loginType);
            $count = 0;
            foreach ($sessions as $session) {
                $renewAccountLock();
                $tokenValue = is_string($session['tokenValue'] ?? null) ? $session['tokenValue'] : '';
                if ($tokenValue === '' || ($exceptToken !== null && $tokenValue === $exceptToken)
                    || !$tokenManager->isTokenValid($tokenValue)) {
                    continue;
                }
                $eventLoginId = $logic->kickoutByTokenValue($tokenValue, false);
                if ($eventLoginId !== null) {
                    $kickoutEvents[] = [$eventLoginId, $tokenValue];
                    $count++;
                }
            }

            // Cleanup metadata only after the authoritative sessions are revoked;
            // adapters without key search and damaged device records must not
            // prevent the security operation itself.
            $devices = self::loadDeviceRecords($loginId, $loginType, true);
            $deviceCount = 0;
            foreach ($devices as $record) {
                $renewAccountLock();
                $device = $record['device'];
                $remainingTokens = [];
                if ($exceptToken !== null) {
                    foreach (self::loadDeviceTokenValues($record['key'], $record['raw']) as $tokenValue) {
                        if ($tokenValue === $exceptToken) {
                            $remainingTokens[] = $tokenValue;
                        }
                    }
                }
                $dao = SaToken::getDao();
                $remainingToken = $remainingTokens[0] ?? null;
                $hasRemainingToken = $remainingToken !== null;
                if ($hasRemainingToken) {
                    // A device may own several stateful sessions. Preserve the
                    // explicitly exempted bearer even when it is not the
                    // record's primary tokenValue.
                    $device->setTokenValue($remainingToken);
                    $newRecord = self::encodeDevice($device, $remainingTokens);
                } else {
                    $newRecord = null;
                }
                if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface
                    || !$dao->compareAndSet($record['key'], $record['raw'], $newRecord)) {
                    throw new SaTokenException('设备记录已并发变更或 DAO 不支持原子条件写入，请重试');
                }
                if (!$hasRemainingToken) {
                    $deviceCount++;
                }
            }

            return max($count, $deviceCount);
        } finally {
            $logic->getTokenManager()->releaseLock($lockKey);
            foreach ($kickoutEvents as [$eventLoginId, $tokenValue]) {
                SaToken::getEvent()->onKickout($loginType, $eventLoginId, $tokenValue);
            }
        }
    }

    public static function findDevice(mixed $loginId, string $deviceId, string $loginType = 'login'): ?SaLoginDevice
    {
        return self::loadDevice($loginId, $deviceId, $loginType, false);
    }

    protected static function loadDevice(mixed $loginId, string $deviceId, string $loginType, bool $includeToken): ?SaLoginDevice
    {
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType) . ':' . $deviceId;
        $data = $dao->get($key);

        if ($data === null) {
            $record = self::findDeviceRecordById($loginId, $deviceId, $loginType);
            if ($record === null) {
                return null;
            }
            $data = $record['raw'];
        }

        $decoded = @json_decode($data, true);
        if (!is_array($decoded)) {
            return null;
        }
        if (($decoded['loginType'] ?? 'login') !== $loginType) {
            return null;
        }

        $decoded = self::decodeDeviceData($decoded, $includeToken);
        $device = new SaLoginDevice($decoded);
        if (!$includeToken) {
            $device->setTokenValue('');
        }
        return $device;
    }

    /**
     * @param  array<mixed, mixed>  $data
     * @return array<string, mixed>
     */
    protected static function decodeDeviceData(array $data, bool $includeToken): array
    {
        $normalized = [];
        foreach ($data as $key => $value) {
            if (is_string($key)) {
                $normalized[$key] = $value;
            }
        }

        $data = $normalized;
        if ($includeToken && ($data['tokenValueEncrypted'] ?? false) === true) {
            $encryptedToken = $data['tokenValue'] ?? null;
            if (!is_string($encryptedToken)) {
                throw new SaTokenException('设备记录中的 Token 密文无效');
            }
            $tokenValue = self::getEncryptor()->decryptChecked($encryptedToken);
            if ($tokenValue === null) {
                throw new SaTokenException('设备记录中的 Token 密文校验失败');
            }
            $data['tokenValue'] = $tokenValue;
        }
        unset($data['tokenValueEncrypted']);
        return $data;
    }

    public static function updateLastActive(mixed $loginId, string $deviceId, string $loginType = 'login'): void
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $logic = SaToken::getStpLogic($loginType);
        $tokenManager = $logic->getTokenManager();
        $lockKey = 'login:' . $loginType . ':' . hash('sha256', $loginIdStr);
        if (!$tokenManager->acquireLock($lockKey, 30)) {
            throw new SaTokenException('同账号会话正在处理中，请稍后重试');
        }

        try {
            $dao = SaToken::getDao();
            $key = self::getKey($loginId, $loginType) . ':' . $deviceId;
            $expectedRecord = $dao->get($key);
            if ($expectedRecord === null) {
                $record = self::findDeviceRecordById($loginId, $deviceId, $loginType);
                if ($record !== null) {
                    $key = $record['key'];
                    $expectedRecord = $record['raw'];
                }
            }
            if ($expectedRecord === null) {
                return;
            }

            $data = @json_decode($expectedRecord, true);
            if (!is_array($data) || ($data['loginType'] ?? 'login') !== $loginType) {
                return;
            }
            $device = new SaLoginDevice(self::decodeDeviceData($data, true));

            $device->setLastActiveTime(time());
            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndUpdateInterface
                || !$dao->compareAndUpdate(
                    $key,
                    $expectedRecord,
                    self::encodeDevice($device, self::loadDeviceTokenValues($key, $expectedRecord))
                )) {
                throw new SaTokenException('设备记录已并发变更或 DAO 不支持原子条件更新，请重试');
            }
        } finally {
            $tokenManager->releaseLock($lockKey);
        }
    }

    /** @return array{device: SaLoginDevice, key: string, raw: string}|null */
    protected static function findDeviceRecordById(mixed $loginId, string $deviceId, string $loginType): ?array
    {
        foreach (self::loadDeviceRecords($loginId, $loginType, false) as $record) {
            if ($record['device']->getDeviceId() === $deviceId) {
                return $record;
            }
        }

        return null;
    }

    /**
     * @param array<string> $tokenValues
     */
    protected static function encodeDevice(SaLoginDevice $device, array $tokenValues = []): string
    {
        $data = $device->toArray();
        $config = SaToken::getConfig();
        $tokenValue = $data['tokenValue'] ?? '';
        if ($config->isTokenEncrypt() && is_string($tokenValue) && $tokenValue !== '') {
            $data['tokenValue'] = self::getEncryptor()->encrypt($tokenValue);
            $data['tokenValueEncrypted'] = true;
        }

        $tokenValues = array_values(array_unique(array_filter($tokenValues, static fn (string $value): bool => $value !== '')));
        if ($config->isTokenEncrypt()) {
            $tokenValues = array_map(static fn (string $value): string => self::getEncryptor()->encrypt($value), $tokenValues);
        }
        $data['managedTokenValues'] = $tokenValues;
        $data['managedTokenValuesEncrypted'] = $config->isTokenEncrypt();

        return SaFoxUtil::toJson($data);
    }

    /**
     * @return array<string>
     */
    protected static function loadDeviceTokenValues(string $key, ?string $snapshot = null): array
    {
        $json = $snapshot ?? SaToken::getDao()->get($key);
        if ($json === null) {
            return [];
        }

        $data = @json_decode($json, true);
        if (!is_array($data)) {
            return [];
        }

        $data = self::decodeDeviceData($data, true);
        $tokens = [];
        $managedValues = $data['managedTokenValues'] ?? null;
        if (is_array($managedValues)) {
            foreach ($managedValues as $value) {
                if (!is_string($value) || $value === '') {
                    continue;
                }
                if (($data['managedTokenValuesEncrypted'] ?? false) === true) {
                    $value = self::getEncryptor()->decryptChecked($value);
                    if ($value === null) {
                        throw new SaTokenException('设备记录中的 Token 列表密文校验失败');
                    }
                }
                $tokens[] = $value;
            }
        }

        $legacyToken = $data['tokenValue'] ?? null;
        if (is_string($legacyToken) && $legacyToken !== '') {
            $tokens[] = $legacyToken;
        }

        return array_values(array_unique($tokens));
    }

    protected static function getEncryptor(): SaTokenEncryptor
    {
        $config = SaToken::getConfig();
        $key = $config->getTokenEncryptKey() ?: $config->getAesKey();
        if ($config->getCryptoType() === 'sm') {
            $key = $config->getTokenEncryptKey() ?: $config->getSm4Key();
        }

        return new SaTokenEncryptor($config->isTokenEncrypt(), $key, $config->getCryptoType());
    }

    protected static function detectDeviceType(): string
    {
        $ua = SaTokenContext::getHeader('User-Agent') ?? '';
        if (preg_match('/mobile|android|iphone|ipad|phone/i', $ua)) {
            if (preg_match('/ipad/i', $ua)) {
                return 'tablet';
            }
            return 'mobile';
        }
        return 'pc';
    }

    protected static function detectDeviceName(): string
    {
        $ua = SaTokenContext::getHeader('User-Agent') ?? '';
        if (preg_match('/MicroMessenger\/([\d.]+)/i', $ua, $m)) {
            return '微信 ' . $m[1];
        }
        if (preg_match('/DingTalk\/([\d.]+)/i', $ua, $m)) {
            return '钉钉 ' . $m[1];
        }
        if (preg_match('/AlipayClient\/([\d.]+)/i', $ua, $m)) {
            return '支付宝 ' . $m[1];
        }
        return 'Web Browser';
    }

    protected static function detectOs(): string
    {
        $ua = SaTokenContext::getHeader('User-Agent') ?? '';
        if (preg_match('/Windows NT 10/i', $ua)) {
            return 'Windows 10/11';
        }
        if (preg_match('/Windows NT 6.3/i', $ua)) {
            return 'Windows 8.1';
        }
        if (preg_match('/Mac OS X/i', $ua)) {
            return 'macOS';
        }
        if (preg_match('/iPhone/i', $ua)) {
            return 'iOS';
        }
        if (preg_match('/Android/i', $ua)) {
            return 'Android';
        }
        if (preg_match('/Linux/i', $ua)) {
            return 'Linux';
        }
        return 'Unknown';
    }

    protected static function detectBrowser(): string
    {
        $ua = SaTokenContext::getHeader('User-Agent') ?? '';
        if (preg_match('/Edg\/([\d.]+)/i', $ua, $m)) {
            return 'Edge ' . $m[1];
        }
        if (preg_match('/Chrome\/([\d.]+)/i', $ua, $m)) {
            return 'Chrome ' . $m[1];
        }
        if (preg_match('/Firefox\/([\d.]+)/i', $ua, $m)) {
            return 'Firefox ' . $m[1];
        }
        if (preg_match('/Safari\/([\d.]+)/i', $ua, $m)) {
            return 'Safari ' . $m[1];
        }
        if (preg_match('/MicroMessenger\/([\d.]+)/i', $ua, $m)) {
            return '微信内置浏览器 ' . $m[1];
        }
        return 'Unknown';
    }

    public static function reset(): void
    {
        self::$keyPrefix = 'satoken:security:device:';
    }
}
