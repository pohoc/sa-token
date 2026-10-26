<?php

declare(strict_types=1);

namespace SaToken\Security;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

class SaAntiBruteUtil
{
    protected static string $keyPrefix = 'satoken:security:brute:';

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

    protected static function getEpoch(string $account, string $loginType = 'login'): int
    {
        $epoch = SaToken::getDao()->get(self::getEpochKey($account, $loginType));
        return $epoch !== null && ctype_digit($epoch) ? (int) $epoch : 0;
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

    protected static function getIpCountPrefix(string $account, string $loginType = 'login'): string
    {
        return self::getKey($account, $loginType) . ':ip-count:';
    }

    protected static function getIpLockPrefix(string $account, string $loginType = 'login'): string
    {
        return self::getKey($account, $loginType) . ':ip-lock:';
    }

    protected static function getIpCountKey(string $account, string $loginType = 'login', ?int $epoch = null): string
    {
        return self::getIpCountPrefix($account, $loginType) . ($epoch ?? self::getEpoch($account, $loginType)) . ':' . self::getIpSuffix();
    }

    protected static function getIpLockKey(string $account, string $loginType = 'login', ?int $epoch = null): string
    {
        return self::getIpLockPrefix($account, $loginType) . ($epoch ?? self::getEpoch($account, $loginType)) . ':' . self::getIpSuffix();
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
        $failCount = $dao->increment(self::getIpCountKey($account, $loginType, $epoch), 1, 86400);

        if ($maxFailures > 0 && $lockDuration > 0 && $failCount >= $maxFailures) {
            $dao->set(
                self::getIpLockKey($account, $loginType, $epoch),
                (string) (time() + $lockDuration),
                $lockDuration + 60
            );
        }
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
        $epoch = self::getEpoch($account, $loginType);
        $dao->delete(self::getIpCountKey($account, $loginType, $epoch));
        $dao->delete(self::getIpLockKey($account, $loginType, $epoch));
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
