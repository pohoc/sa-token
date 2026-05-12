<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Data\SaLoginDevice;
use SaToken\Exception\DisableServiceException;
use SaToken\Exception\NotLoginException;
use SaToken\Exception\NotSafeException;
use SaToken\Security\SaAntiBruteUtil;
use SaToken\Security\SaAuditLog;
use SaToken\Security\SaIpAnomalyDetector;
use SaToken\Security\SaLoginDeviceManager;
use SaToken\Security\SaSensitiveVerify;

trait StpLogicSecurityTrait
{
    public function disable(mixed $loginId, string $service, int $level = 1, int $time = -1): void
    {
        $this->tokenManager->disable($loginId, $service, $level, $time, $this->loginType);
        $this->getEvent()->onBlock($this->loginType, $loginId, $service, $level, $time);

        SaAuditLog::logDisable($loginId, $this->loginType, $service . ':' . $level . ':' . $time);
    }

    public function isDisable(mixed $loginId, string $service): bool
    {
        return $this->tokenManager->isDisable($loginId, $service, $this->loginType);
    }

    public function checkDisable(mixed $loginId, string $service): void
    {
        if ($this->isDisable($loginId, $service)) {
            $level = $this->tokenManager->getDisableLevel($loginId, $service, $this->loginType);
            $remainingTime = $this->tokenManager->getDisableTime($loginId, $service, $this->loginType);
            throw new DisableServiceException($service, $level, $remainingTime);
        }
    }

    public function getDisableLevel(mixed $loginId, string $service): int
    {
        return $this->tokenManager->getDisableLevel($loginId, $service, $this->loginType);
    }

    public function untieDisable(mixed $loginId, string $service): void
    {
        $this->tokenManager->untieDisable($loginId, $service, $this->loginType);

        SaAuditLog::logUndisable($loginId, $this->loginType);
    }

    public function openSafe(int $safeTime, string $service = 'default'): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            throw new NotLoginException('未登录，请先登录', NotLoginException::NOT_LOGIN);
        }
        $this->tokenManager->openSafe($tokenValue, $service, $safeTime, $this->loginType);
    }

    public function checkSafe(string $service = 'default'): void
    {
        if (!$this->isSafe($service)) {
            throw new NotSafeException();
        }
    }

    public function isSafe(string $service = 'default'): bool
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return false;
        }
        return $this->tokenManager->isSafe($tokenValue, $service, $this->loginType);
    }

    public function closeSafe(string $service = 'default'): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return;
        }
        $this->tokenManager->closeSafe($tokenValue, $service, $this->loginType);
    }

    public function switchTo(mixed $loginId): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            throw new NotLoginException('未登录，请先登录', NotLoginException::NOT_LOGIN);
        }
        $currentLoginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($currentLoginId === null) {
            throw new NotLoginException('Token 已失效', NotLoginException::TOKEN_TIMEOUT);
        }

        $this->tokenManager->setSwitchTo($tokenValue, $loginId, $this->loginType);
        $this->getEvent()->onSwitch($this->loginType, $currentLoginId, $loginId, $tokenValue);

        SaAuditLog::logSwitchTo($currentLoginId, $loginId, $this->loginType);
    }

    public function endSwitch(): void
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return;
        }
        $this->tokenManager->clearSwitch($tokenValue, $this->loginType);
        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId !== null) {
            $this->getEvent()->onSwitchBack($this->loginType, $loginId, $tokenValue);
        }
    }

    public function isSwitch(): bool
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return false;
        }
        return $this->tokenManager->getSwitchTo($tokenValue, $this->loginType) !== null;
    }

    public function checkAntiBrute(string $account): void
    {
        $config = $this->getConfig();
        $maxFailures = $config->getAntiBruteMaxFailures();

        if ($maxFailures <= 0) {
            return;
        }

        SaAntiBruteUtil::checkAndThrow($account, $this->loginType);
    }

    public function recordAntiBruteFailure(string $account): void
    {
        $config = $this->getConfig();
        $maxFailures = $config->getAntiBruteMaxFailures();

        if ($maxFailures <= 0) {
            return;
        }

        SaAntiBruteUtil::recordFailure($account, $this->loginType);

        if (SaAntiBruteUtil::getFailCount($account, $this->loginType) >= $maxFailures) {
            $lockDuration = $config->getAntiBruteLockDuration();
            SaAntiBruteUtil::lock($account, $this->loginType, $lockDuration);
        }
    }

    protected function clearAntiBruteFailures(mixed $loginId): void
    {
        $config = $this->getConfig();
        if ($config->getAntiBruteMaxFailures() <= 0) {
            return;
        }

        SaAntiBruteUtil::clearFailures(is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : ''), $this->loginType);
    }

    public function isAccountLocked(string $account): bool
    {
        return SaAntiBruteUtil::isAccountLocked($account, $this->loginType);
    }

    public function getRemainingLockTime(string $account): int
    {
        return SaAntiBruteUtil::getRemainingLockTime($account, $this->loginType);
    }

    public function unlockAccount(string $account): void
    {
        SaAntiBruteUtil::unlock($account, $this->loginType);
    }

    /**
     * @return array{failCount: int, isLocked: bool, remainingLockTime: int, firstFailureTime: int, lockedUntil: int}
     */
    public function getAntiBruteInfo(string $account): array
    {
        return SaAntiBruteUtil::getSecurityInfo($account, $this->loginType);
    }

    public function getAnomalyCount(mixed $loginId): int
    {
        return SaIpAnomalyDetector::getAnomalyCount($loginId, $this->loginType);
    }

    /**
     * @return array<array<string, mixed>>
     */
    public function getIpHistory(mixed $loginId): array
    {
        return SaIpAnomalyDetector::getIpHistory($loginId, $this->loginType);
    }

    /**
     * @return array{currentIp: ?string, lastLoginIp: ?string, lastLoginTime: ?int, anomalyCount: int}
     */
    public function getLoginInfo(mixed $loginId): array
    {
        return SaIpAnomalyDetector::getLoginInfo($loginId, $this->loginType);
    }

    public function clearLoginHistory(mixed $loginId): void
    {
        SaIpAnomalyDetector::clearHistory($loginId, $this->loginType);
    }

    public function openSensitiveVerify(string $scene, int $validSeconds = 600): string
    {
        $loginId = $this->getLoginIdAsNotNull();
        return SaSensitiveVerify::createSafeToken($scene, $loginId, $this->loginType, $validSeconds);
    }

    public function checkSensitiveVerify(string $scene, string $token): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        SaSensitiveVerify::verifySafeTokenAndThrow($scene, $token, $loginId, $this->loginType);
    }

    public function generateOtpCode(string $scene): string
    {
        $loginId = $this->getLoginIdAsNotNull();
        return SaSensitiveVerify::generateCode($scene, $loginId, $this->loginType);
    }

    public function sendOtpCode(string $scene): string
    {
        $loginId = $this->getLoginIdAsNotNull();
        return SaSensitiveVerify::sendCode($scene, $loginId, $this->loginType);
    }

    public function verifyOtpCode(string $scene, string $code): void
    {
        $loginId = $this->getLoginIdAsNotNull();
        SaSensitiveVerify::verifyCodeAndThrow($scene, $code, $loginId, $this->loginType);
    }

    public function isSensitiveVerified(string $scene): bool
    {
        $loginId = $this->getLoginId();
        if ($loginId === null) {
            return false;
        }
        return SaSensitiveVerify::isVerified($scene, $loginId, $this->loginType);
    }

    public function clearSensitiveVerify(string $scene): void
    {
        $loginId = $this->getLoginId();
        if ($loginId !== null) {
            SaSensitiveVerify::clearVerified($scene, $loginId, $this->loginType);
        }
    }

    public function getSensitiveVerifyRemainingAttempts(string $scene): int
    {
        $loginId = $this->getLoginId();
        if ($loginId === null) {
            return SaSensitiveVerify::getRemainingAttempts($scene, 0, $this->loginType);
        }
        return SaSensitiveVerify::getRemainingAttempts($scene, $loginId, $this->loginType);
    }

    public function getAuditLogs(int $limit = 50): array
    {
        $loginId = $this->getLoginId();
        if ($loginId === null) {
            return [];
        }
        return SaAuditLog::getLogsByLoginId($loginId, $this->loginType, $limit);
    }

    public function getAuditLog(string $id): ?array
    {
        return SaAuditLog::getLog($id, $this->loginType);
    }

    /**
     * @return array<SaLoginDevice>
     */
    public function getDeviceList(mixed $loginId): array
    {
        return SaLoginDeviceManager::getDeviceList($loginId, $this->loginType);
    }

    public function getDeviceCount(mixed $loginId): int
    {
        return SaLoginDeviceManager::getDeviceCount($loginId, $this->loginType);
    }

    public function kickoutDevice(mixed $loginId, string $deviceId): void
    {
        SaLoginDeviceManager::kickoutDevice($loginId, $deviceId, $this->loginType);
    }

    public function kickoutAllDevices(mixed $loginId, ?string $exceptToken = null): int
    {
        return SaLoginDeviceManager::kickoutAllDevices($loginId, $this->loginType, $exceptToken);
    }

    public function findDevice(mixed $loginId, string $deviceId): ?SaLoginDevice
    {
        return SaLoginDeviceManager::findDevice($loginId, $deviceId, $this->loginType);
    }

    public function getLoginDeviceType(): string
    {
        $tokenValue = $this->getTokenValue();
        if ($tokenValue === null) {
            return '';
        }

        $loginId = $this->tokenManager->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            return '';
        }

        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        foreach ($tokens as $item) {
            $itemTokenValue = is_string($item['tokenValue'] ?? null) ? $item['tokenValue'] : '';
            if ($itemTokenValue === $tokenValue) {
                $deviceType = $item['deviceType'] ?? '';
                return is_string($deviceType) ? $deviceType : '';
            }
        }

        return '';
    }

    /**
     * @return array<SaTerminalInfo>
     */
    public function getTerminalListByLoginId(mixed $loginId): array
    {
        $tokens = $this->tokenManager->getTokenListByLoginId($loginId, $this->loginType);
        $result = [];
        foreach ($tokens as $item) {
            $deviceType = $item['deviceType'] ?? '';
            $itemTokenValue = $item['tokenValue'] ?? '';
            $createTime = $item['createTime'] ?? 0;
            $result[] = new SaTerminalInfo([
                'deviceType' => is_string($deviceType) ? $deviceType : '',
                'tokenValue' => is_string($itemTokenValue) ? $itemTokenValue : '',
                'createTime' => is_int($createTime) ? $createTime : 0,
            ]);
        }
        return $result;
    }
}
