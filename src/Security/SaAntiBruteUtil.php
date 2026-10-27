<?php

declare(strict_types=1);

namespace SaToken\Security;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

class SaAntiBruteUtil
{
    protected static string $keyPrefix = 'satoken:security:brute:';

    protected const SOURCE_RESERVATIONS_ATTRIBUTE = 'sa-token:anti-brute:source-reservations';

    public static function setKeyPrefix(string $prefix): void
    {
        self::$keyPrefix = $prefix;
    }

    public static function getKeyPrefix(): string
    {
        return self::$keyPrefix;
    }

    public static function getKey(string $account, string $loginType = 'login'): string
    {
        // Account IDs are attacker-controlled in many integrations. MD5 chosen-
        // prefix collisions can make two distinct accounts share lockout state.
        // Version the namespace so legacy MD5 counters are not trusted as the
        // owner of a new account's security state.
        return self::$keyPrefix . 'v2:'
            . \SaToken\TokenManager::encodeKeyComponent($loginType) . ':'
            . hash('sha256', $account);
    }

    protected static function getLockKey(string $account, string $loginType = 'login'): string
    {
        return self::getKey($account, $loginType) . ':lock';
    }

    protected static function getEpochKey(string $account, string $loginType = 'login'): string
    {
        return self::getKey($account, $loginType) . ':epoch';
    }

    protected static function getIpEpochKey(string $account, string $loginType, int $epoch): string
    {
        return self::getKey($account, $loginType) . ':ip-epoch:' . $epoch . ':' . self::getIpSuffix();
    }

    protected static function getEpoch(string $account, string $loginType = 'login'): int
    {
        $epoch = SaToken::getDao()->get(self::getEpochKey($account, $loginType));
        return $epoch !== null && ctype_digit($epoch) ? (int) $epoch : 0;
    }

    protected static function getIpEpoch(string $account, string $loginType, int $epoch): int
    {
        $value = SaToken::getDao()->get(self::getIpEpochKey($account, $loginType, $epoch));
        return $value !== null && ctype_digit($value) ? (int) $value : 0;
    }

    protected static function getIpSuffix(): string
    {
        $ip = SaTokenContext::getClientIp();
        return hash('sha256', $ip !== null && $ip !== '' ? $ip : 'unknown');
    }

    protected static function getSourceIdentity(string $loginType): ?string
    {
        $ip = SaTokenContext::getClientIp();
        if ($ip === null || $ip === '') {
            // A shared "unknown" bucket would let an unauthenticated caller
            // lock out every request whose adapter cannot resolve a source IP.
            return null;
        }

        return hash('sha256', $loginType . "\0" . $ip);
    }

    protected static function getSourceFailureKey(string $identity): string
    {
        return self::$keyPrefix . 'source-fail:' . $identity;
    }

    protected static function getSourceLockKey(string $identity): string
    {
        return self::$keyPrefix . 'source-lock:' . $identity;
    }

    protected static function getSourceAttemptKey(string $identity): string
    {
        return self::$keyPrefix . 'source-attempt:' . $identity;
    }

    protected static function getIpCountPrefix(string $account, string $loginType = 'login'): string
    {
        return self::getKey($account, $loginType) . ':ip-count:';
    }

    protected static function getIpAttemptKey(
        string $account,
        string $loginType = 'login',
        ?int $epoch = null,
        ?int $ipEpoch = null
    ): string {
        $epoch ??= self::getEpoch($account, $loginType);
        $ipEpoch ??= self::getIpEpoch($account, $loginType, $epoch);
        return self::getKey($account, $loginType) . ':ip-attempt:' . $epoch . ':' . $ipEpoch . ':' . self::getIpSuffix();
    }

    protected static function getIpLockPrefix(string $account, string $loginType = 'login'): string
    {
        return self::getKey($account, $loginType) . ':ip-lock:';
    }

    protected static function getIpCountKey(
        string $account,
        string $loginType = 'login',
        ?int $epoch = null,
        ?int $ipEpoch = null
    ): string {
        $epoch ??= self::getEpoch($account, $loginType);
        $ipEpoch ??= self::getIpEpoch($account, $loginType, $epoch);
        return self::getIpCountPrefix($account, $loginType) . $epoch . ':' . $ipEpoch . ':' . self::getIpSuffix();
    }

    protected static function getIpLockKey(
        string $account,
        string $loginType = 'login',
        ?int $epoch = null,
        ?int $ipEpoch = null
    ): string {
        $epoch ??= self::getEpoch($account, $loginType);
        $ipEpoch ??= self::getIpEpoch($account, $loginType, $epoch);
        return self::getIpLockPrefix($account, $loginType) . $epoch . ':' . $ipEpoch . ':' . self::getIpSuffix();
    }

    protected static function createSourceAttemptReservation(string $counterKey, int $timeout): string
    {
        $reservationKey = $counterKey . ':reservation:' . bin2hex(random_bytes(16));
        if (!SaToken::getDao()->setIfNotExists($reservationKey, '1', $timeout)) {
            throw new SaTokenException('无法创建来源并发认证租约，请重试');
        }

        return $reservationKey;
    }

    protected static function storeSourceAttemptReservation(string $account, string $loginType, string $reservationKey): void
    {
        $reservations = SaTokenContext::getRequestScopedValue(self::SOURCE_RESERVATIONS_ATTRIBUTE, []);
        if (!is_array($reservations)) {
            $reservations = [];
        }

        $ownerKey = hash('sha256', $loginType . "\0" . $account);
        $ownerReservations = $reservations[$ownerKey] ?? [];
        if (!is_array($ownerReservations)) {
            $ownerReservations = [];
        }
        $ownerReservations[] = $reservationKey;
        $reservations[$ownerKey] = $ownerReservations;
        SaTokenContext::setRequestScopedValue(self::SOURCE_RESERVATIONS_ATTRIBUTE, $reservations);
    }

    protected static function releaseSourceAttemptReservation(
        string $account,
        string $loginType,
        string $sourceIdentity,
        int $timeout
    ): void {
        $reservations = SaTokenContext::getRequestScopedValue(self::SOURCE_RESERVATIONS_ATTRIBUTE, []);
        if (!is_array($reservations)) {
            $reservations = [];
        }
        $ownerKey = hash('sha256', $loginType . "\0" . $account);
        $ownerReservations = is_array($reservations[$ownerKey] ?? null)
            ? $reservations[$ownerKey]
            : [];
        $reservationKey = array_shift($ownerReservations);
        if (!is_string($reservationKey)) {
            return;
        }

        if ($ownerReservations === []) {
            unset($reservations[$ownerKey]);
        } else {
            $reservations[$ownerKey] = $ownerReservations;
        }
        if ($reservations === []) {
            SaTokenContext::removeRequestScopedValue(self::SOURCE_RESERVATIONS_ATTRIBUTE);
        } else {
            SaTokenContext::setRequestScopedValue(self::SOURCE_RESERVATIONS_ATTRIBUTE, $reservations);
        }

        $dao = SaToken::getDao();
        // An expired marker means this request's lease is already gone. Do not
        // decrement a counter that may now represent newer requests.
        if ($dao->getAndDelete($reservationKey) === null) {
            return;
        }

        self::decrementSourceAttemptCounter(self::getSourceAttemptKey($sourceIdentity), $timeout);
    }

    protected static function decrementSourceAttemptCounter(string $counterKey, int $timeout): void
    {
        $dao = SaToken::getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
            throw new SaTokenException('DAO 必须实现安全比较设置接口才能释放来源并发限流');
        }

        for ($attempt = 0; $attempt < 16; $attempt++) {
            $current = $dao->get($counterKey);
            if ($current === null || !ctype_digit($current) || (int) $current <= 0) {
                return;
            }

            if ($dao->compareAndSet($counterKey, $current, (string) ((int) $current - 1), $timeout)) {
                return;
            }
        }

        throw new SaTokenException('来源并发限流状态竞争过多，请重试');
    }

    protected static function getLockUntil(string $key): int
    {
        $value = SaToken::getDao()->get($key);
        return $value !== null && ctype_digit($value) ? (int) $value : 0;
    }

    public static function isAccountLocked(string $account, string $loginType = 'login'): bool
    {
        $lockUntil = max(
            self::getLockUntil(self::getLockKey($account, $loginType)),
            self::getLockUntil(self::getIpLockKey($account, $loginType))
        );
        return $lockUntil > time();
    }

    public static function getRemainingLockTime(string $account, string $loginType = 'login'): int
    {
        $lockUntil = max(
            self::getLockUntil(self::getLockKey($account, $loginType)),
            self::getLockUntil(self::getIpLockKey($account, $loginType))
        );
        $remaining = $lockUntil - time();
        return $remaining > 0 ? $remaining : 0;
    }

    public static function recordFailure(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $config = SaToken::getConfig();
        $maxFailures = $config->getAntiBruteMaxFailures();
        $lockDuration = $config->getAntiBruteLockDuration();
        // Keep one generation for the whole failure operation. If an admin
        // unlocks while the counter write is in flight, this stale operation
        // may only write its lock into the old generation, never the fresh one.
        $epoch = self::getEpoch($account, $loginType);
        $ipEpoch = self::getIpEpoch($account, $loginType, $epoch);

        $sourceIdentity = self::getSourceIdentity($loginType);
        $sourceMax = $config->getAntiBruteIpMaxFailures();
        $sourceProtectionEnabled = $sourceMax > 0 && $lockDuration > 0;
        if ($sourceIdentity === null && (($maxFailures > 0 && $lockDuration > 0) || $sourceProtectionEnabled)) {
            throw new SaTokenException('无法识别客户端 IP，拒绝处理认证失败以避免共享未知来源锁');
        }

        // Account+IP counters alone let an attacker create a fresh persistent key
        // for every guessed username. Bound that key growth with one counter per
        // source and login type; after the cap, reject new attempts before they
        // can allocate another account counter. This must happen before writing
        // the account counter because concurrent requests may all pass
        // checkAndThrow() before any of them records its failed credential.
        $sourceProtectionEnabled = $sourceProtectionEnabled && $sourceIdentity !== null;
        if ($sourceIdentity !== null) {
            // Release only the slot reserved by this request. A shared counter
            // alone lets a slow request whose lease expired decrement a newer
            // request's live reservation.
            self::releaseSourceAttemptReservation($account, $loginType, $sourceIdentity, $lockDuration);
        }
        if ($sourceProtectionEnabled && $sourceIdentity !== null) {
            $sourceCount = $dao->increment(self::getSourceFailureKey($sourceIdentity), 1, $lockDuration);
            if ($sourceCount >= $sourceMax) {
                $dao->set(
                    self::getSourceLockKey($sourceIdentity),
                    (string) (time() + $lockDuration),
                    $lockDuration + 60
                );
                return;
            }
        }

        // Limit account+source-IP counters to avoid letting one known account
        // be locked from unrelated source addresses. Distributed protection
        // still requires a shared DAO and any global rate limits at the edge.
        $failCount = $dao->increment(self::getIpCountKey($account, $loginType, $epoch, $ipEpoch), 1, 86400);

        if ($maxFailures > 0 && $lockDuration > 0 && $failCount >= $maxFailures) {
            $dao->set(
                self::getIpLockKey($account, $loginType, $epoch, $ipEpoch),
                (string) (time() + $lockDuration),
                $lockDuration + 60
            );
        }
    }

    /** Release this request's reserved source slot without changing failure counters. */
    public static function releaseCurrentSourceAttempt(string $account, string $loginType = 'login'): void
    {
        $sourceIdentity = self::getSourceIdentity($loginType);
        if ($sourceIdentity === null) {
            return;
        }

        self::releaseSourceAttemptReservation(
            $account,
            $loginType,
            $sourceIdentity,
            SaToken::getConfig()->getAntiBruteLockDuration()
        );
    }

    public static function checkAndThrow(string $account, string $loginType = 'login'): void
    {
        $config = SaToken::getConfig();
        $sourceIdentity = self::getSourceIdentity($loginType);
        $accountProtectionEnabled = $config->getAntiBruteMaxFailures() > 0
            && $config->getAntiBruteLockDuration() > 0;
        $sourceProtectionEnabled = $config->getAntiBruteIpMaxFailures() > 0
            && $config->getAntiBruteLockDuration() > 0;
        if ($sourceIdentity === null && ($accountProtectionEnabled || $sourceProtectionEnabled)) {
            throw new SaTokenException('无法识别客户端 IP，拒绝认证以避免暴力破解和共享未知来源锁');
        }

        if ($sourceIdentity !== null) {
            $sourceLockUntil = self::getLockUntil(self::getSourceLockKey($sourceIdentity));
            if ($sourceLockUntil > time()) {
                $remaining = $sourceLockUntil - time();
                throw new SaTokenException('当前来源失败次数过多，请 ' . $remaining . ' 秒后重试', -10);
            }
        }

        if (self::isAccountLocked($account, $loginType)) {
            $remaining = self::getRemainingLockTime($account, $loginType);
            throw new SaTokenException(
                '账号已被锁定，请 ' . $remaining . ' 秒后重试',
                -10
            );
        }

        $sourceSlotReserved = false;
        if ($sourceProtectionEnabled && $sourceIdentity !== null) {
            $dao = SaToken::getDao();
            if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
                throw new SaTokenException('DAO 必须实现安全比较设置接口才能维护来源并发限流');
            }

            $sourceAttemptKey = self::getSourceAttemptKey($sourceIdentity);
            $reservationKey = self::createSourceAttemptReservation($sourceAttemptKey, $config->getAntiBruteLockDuration());
            $sourceAttemptCount = $dao->increment($sourceAttemptKey, 1, $config->getAntiBruteLockDuration());
            if ($sourceAttemptCount > $config->getAntiBruteIpMaxFailures()) {
                if ($dao->getAndDelete($reservationKey) !== null) {
                    self::decrementSourceAttemptCounter($sourceAttemptKey, $config->getAntiBruteLockDuration());
                }
                throw new SaTokenException('当前来源并发认证尝试过多，请稍后重试', -10);
            }
            self::storeSourceAttemptReservation($account, $loginType, $reservationKey);
            $sourceSlotReserved = true;
        }

        // Reserve the account/IP attempt before credential validation. A
        // read-only precheck lets an arbitrary number of concurrent guesses
        // enter a slow password verifier before any failure is recorded.
        if ($accountProtectionEnabled) {
            $epoch = self::getEpoch($account, $loginType);
            $ipEpoch = self::getIpEpoch($account, $loginType, $epoch);
            $attemptKey = self::getIpAttemptKey($account, $loginType, $epoch, $ipEpoch);
            $attemptCount = SaToken::getDao()->increment($attemptKey, 1, $config->getAntiBruteLockDuration());
            if ($attemptCount >= $config->getAntiBruteMaxFailures()) {
                SaToken::getDao()->set(
                    self::getIpLockKey($account, $loginType, $epoch, $ipEpoch),
                    (string) (time() + $config->getAntiBruteLockDuration()),
                    $config->getAntiBruteLockDuration() + 60
                );
            }
            if ($attemptCount > $config->getAntiBruteMaxFailures()) {
                // Roll back only this rejected reservation. The attempt counter
                // is atomic, so this cannot free a slot already held by a
                // concurrent request.
                SaToken::getDao()->increment($attemptKey, -1, $config->getAntiBruteLockDuration());
                if ($sourceSlotReserved && $sourceIdentity !== null) {
                    self::releaseSourceAttemptReservation(
                        $account,
                        $loginType,
                        $sourceIdentity,
                        $config->getAntiBruteLockDuration()
                    );
                }
                throw new SaTokenException(
                    '账号已达到当前来源的尝试次数上限，请稍后重试',
                    -10
                );
            }
        }
    }

    public static function lock(string $account, string $loginType = 'login', int $durationSeconds = 600): void
    {
        $dao = SaToken::getDao();
        $dao->set(
            self::getLockKey($account, $loginType),
            (string) (time() + $durationSeconds),
            $durationSeconds + 60
        );
    }

    public static function unlock(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $dao->delete(self::getLockKey($account, $loginType));
        $dao->increment(self::getEpochKey($account, $loginType));
    }

    public static function clearFailures(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $dao->delete(self::getLockKey($account, $loginType));
        $dao->increment(self::getEpochKey($account, $loginType));
    }

    public static function clearCurrentSourceFailures(string $account, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $sourceIdentity = self::getSourceIdentity($loginType);
        if ($sourceIdentity !== null) {
            self::releaseSourceAttemptReservation(
                $account,
                $loginType,
                $sourceIdentity,
                SaToken::getConfig()->getAntiBruteLockDuration()
            );
        }
        $epoch = self::getEpoch($account, $loginType);
        $ipEpoch = self::getIpEpoch($account, $loginType, $epoch);
        // Advance before deleting old keys. A failure operation already in
        // flight may still write into the old generation after this cleanup,
        // but lock checks and counters now resolve only the new generation.
        $dao->increment(self::getIpEpochKey($account, $loginType, $epoch));
        $dao->delete(self::getIpCountKey($account, $loginType, $epoch, $ipEpoch));
        $dao->delete(self::getIpAttemptKey($account, $loginType, $epoch, $ipEpoch));
        $dao->delete(self::getIpLockKey($account, $loginType, $epoch, $ipEpoch));
    }

    public static function getFailCount(string $account, string $loginType = 'login'): int
    {
        $dao = SaToken::getDao();
        $count = $dao->get(self::getIpCountKey($account, $loginType));

        return $count !== null ? (int) $count : 0;
    }

    /**
     * @return array{failCount: int, isLocked: bool, remainingLockTime: int, firstFailureTime: int, lockedUntil: int}
     */
    public static function getSecurityInfo(string $account, string $loginType = 'login'): array
    {
        $lockedUntilInt = max(
            self::getLockUntil(self::getLockKey($account, $loginType)),
            self::getLockUntil(self::getIpLockKey($account, $loginType))
        );

        return [
            'failCount' => self::getFailCount($account, $loginType),
            'isLocked' => self::isAccountLocked($account, $loginType),
            'remainingLockTime' => self::getRemainingLockTime($account, $loginType),
            'firstFailureTime' => 0,
            'lockedUntil' => $lockedUntilInt,
        ];
    }

    public static function reset(): void
    {
        self::$keyPrefix = 'satoken:security:brute:';
    }
}
