<?php

declare(strict_types=1);

namespace SaToken\Security;

use SaToken\Exception\NotSafeException;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;

class SaSensitiveVerify
{
    protected static string $keyPrefix = 'satoken:sensitive:';
    protected static int $codeLength = 6;
    protected static int $validSeconds = 300;
    protected static int $maxAttempts = 3;
    protected static int $sendInterval = 60;

    public static function setCodeLength(int $length): void
    {
        if ($length < 6 || $length > 12) {
            throw new SaTokenException('验证码长度必须在 6-12 位之间');
        }
        self::$codeLength = $length;
    }

    public static function setValidSeconds(int $seconds): void
    {
        self::validateLifetime($seconds);
        self::$validSeconds = $seconds;
    }

    protected static function validateLifetime(int $seconds): void
    {
        if ($seconds <= 0 || $seconds > PHP_INT_MAX - time() - 60) {
            throw new SaTokenException('敏感验证有效期必须是可表示的正整数秒数');
        }
    }

    public static function setMaxAttempts(int $max): void
    {
        if ($max < 1) {
            throw new SaTokenException('验证码最大尝试次数必须是正整数');
        }
        self::$maxAttempts = $max;
    }

    public static function setSendInterval(int $seconds): void
    {
        self::$sendInterval = max(0, $seconds);
    }

    public static function getSendInterval(): int
    {
        return self::$sendInterval;
    }

    public static function getKey(string $scene, mixed $loginId, string $loginType = 'login'): string
    {
        $loginIdStr = self::normalizeLoginId($loginId);
        return self::$keyPrefix
            . \SaToken\TokenManager::encodeKeyComponent($loginType) . ':'
            . \SaToken\TokenManager::encodeKeyComponent($scene) . ':'
            . hash('sha256', $loginIdStr);
    }

    protected static function normalizeLoginId(mixed $loginId): string
    {
        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('敏感验证 loginId 不能为空且必须是非布尔标量');
        }

        return (string) $loginId;
    }

    public static function generateCode(string $scene, mixed $loginId, string $loginType = 'login'): string
    {
        $dao = SaToken::getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
            throw new SaTokenException('DAO 必须实现安全比较设置接口才能生成验证码');
        }
        $key = self::getKey($scene, $loginId, $loginType);
        $lockValue = self::acquireStateLock($key);

        try {
            $currentRecord = $dao->get($key);
            if ($dao->get($key . ':state-lock') !== $lockValue) {
                throw new SaTokenException('验证码状态锁已过期，请重试');
            }

            $code = self::generateRandomCode();
            $codeHash = password_hash($code, PASSWORD_DEFAULT);

            $data = [
                'codeHash' => $codeHash,
                'createdAt' => time(),
                'expiresAt' => time() + self::$validSeconds,
                'attempts' => 0,
                'verified' => false,
            ];

            $newRecord = self::encodeSensitiveState($data, $key);
            // A lock is a lease: if a storage write stalls past its TTL, a
            // later request may already have replaced the OTP. Compare the
            // snapshot atomically so a resumed stale worker cannot restore
            // the previous generation over a newer code.
            if ($dao->get($key . ':state-lock') !== $lockValue
                || !$dao->compareAndSet($key, $currentRecord, $newRecord, self::$validSeconds + 60)) {
                throw new SaTokenException('验证码状态已并发更新，请重试');
            }
            $dao->delete($key . ':att');
            $dao->delete($key . ':verified');

            return $code;
        } finally {
            self::releaseStateLock($key, $lockValue);
        }
    }

    protected static function generateRandomCode(): string
    {
        $code = '';
        for ($i = 0; $i < self::$codeLength; $i++) {
            $code .= random_int(0, 9);
        }
        return $code;
    }

    /** Send an OTP through the configured callback without exposing it to the caller. */
    public static function sendCode(string $scene, mixed $loginId, string $loginType = 'login'): void
    {
        $sendCallback = SaToken::getConfig()->getSensitiveVerifyCallback();
        if (!is_callable($sendCallback)) {
            throw new SaTokenException('验证码发送回调未配置，拒绝生成未投递的验证码');
        }

        // 发送频控：同一 scene+loginId 默认 60 秒内只允许发送一次。
        // 没有频控的验证码下发等于向任意手机号/邮箱发起短信/邮件轰炸
        $dao = SaToken::getDao();
        $rateKey = self::getKey($scene, $loginId, $loginType) . ':sent';
        $rateOwner = null;
        if (self::$sendInterval > 0) {
            $rateOwner = bin2hex(random_bytes(16));
            if (!$dao->setIfNotExists($rateKey, $rateOwner, self::$sendInterval)) {
                throw new SaTokenException('验证码发送过于频繁，请 ' . self::$sendInterval . ' 秒后再试');
            }
        }

        $key = self::getKey($scene, $loginId, $loginType);
        try {
            $code = self::generateCode($scene, $loginId, $loginType);
        } catch (SaTokenException $e) {
            $dao = SaToken::getDao();
            if ($rateOwner !== null && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
                $dao->compareAndDelete($rateKey, $rateOwner);
            }
            throw $e;
        }

        try {
            self::sendNotification($scene, $code, $loginId);
        } catch (\Throwable $e) {
            // A delivery failure must not leave an OTP that the caller believes
            // was never sent. Delete only this exact generation so a concurrent
            // resend cannot be invalidated by this stale failure handler.
            $currentRecord = $dao->get($key);
            if ($currentRecord !== null && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
                $info = self::decodeSensitiveState($currentRecord, $key);
                $codeHash = $info['codeHash'] ?? null;
                if (is_string($codeHash) && password_verify($code, $codeHash)) {
                    $dao->compareAndSet($key, $currentRecord, null);
                }
            }
            if ($rateOwner !== null && $dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
                $dao->compareAndDelete($rateKey, $rateOwner);
            }
            throw $e;
        }
    }

    protected static function sendNotification(string $scene, string $code, mixed $loginId): void
    {
        $config = SaToken::getConfig();
        $sendCallback = $config->getSensitiveVerifyCallback();

        if ($sendCallback !== null && is_callable($sendCallback)) {
            call_user_func($sendCallback, $scene, $code, $loginId);
        }
    }

    public static function verifyCode(string $scene, string $code, mixed $loginId, string $loginType = 'login'): bool
    {
        $dao = SaToken::getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndUpdateInterface
            || !$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
            throw new SaTokenException('DAO 必须实现安全比较更新接口才能验证验证码');
        }
        $key = self::getKey($scene, $loginId, $loginType);
        $lockValue = self::acquireStateLock($key);
        try {
            // The lock is a lease and may expire while a DAO call is stalled.
            // CAS keeps concurrent workers from overwriting each other's
            // authenticated attempt count even after that lease expires.
            for ($retry = 0; $retry < 16; $retry++) {
                $record = $dao->get($key);
                if ($record === null) {
                    return false;
                }
                if ($dao->exists($key . ':verified')) {
                    return false;
                }

                $info = self::decodeSensitiveState($record, $key);
                if (!is_array($info) || ($info['verified'] ?? false) === true) {
                    return false;
                }

                $expiresAt = $info['expiresAt'] ?? null;
                if (!is_int($expiresAt) || $expiresAt <= time()) {
                    if ($dao->compareAndSet($key, $record, null)) {
                        $dao->delete($key . ':att');
                    }
                    return false;
                }

                $attempts = is_int($info['attempts'] ?? null) ? $info['attempts'] + 1 : 1;
                if ($attempts > self::$maxAttempts) {
                    if (!$dao->compareAndSet($key, $record, null)) {
                        continue;
                    }
                    $dao->delete($key . ':att');
                    $dao->delete($key . ':verified');
                    throw new SaTokenException('验证码尝试次数过多，请重新获取', -1);
                }

                $info['attempts'] = $attempts;
                $attemptRecord = self::encodeSensitiveState($info, $key);
                if (!$dao->compareAndUpdate($key, $record, $attemptRecord)) {
                    continue;
                }

                $codeHash = $info['codeHash'] ?? null;
                if (!is_string($codeHash) || !password_verify($code, $codeHash)) {
                    return false;
                }

                // Mark success with another CAS. If another attempt changed
                // the record, retry only while this exact OTP generation is
                // still current; never write a stale snapshot over new state.
                for ($successRetry = 0; $successRetry < 16; $successRetry++) {
                    $currentRecord = $dao->get($key);
                    if ($currentRecord === null) {
                        return false;
                    }
                    $current = self::decodeSensitiveState($currentRecord, $key);
                    if (!is_array($current)
                        || ($current['verified'] ?? false) === true
                        || ($current['codeHash'] ?? null) !== $codeHash
                        || !is_int($current['expiresAt'] ?? null)
                        || $current['expiresAt'] <= time()) {
                        return false;
                    }

                    $current['verified'] = true;
                    $current['verifiedAt'] = time();
                    if ($dao->compareAndUpdate($key, $currentRecord, self::encodeSensitiveState($current, $key))) {
                        $dao->delete($key . ':att');
                        $dao->delete($key . ':verified');
                        return true;
                    }
                }

                return false;
            }

            throw new SaTokenException('验证码状态竞争过多，请重试');
        } finally {
            self::releaseStateLock($key, $lockValue);
        }
    }

    public static function verifyCodeAndThrow(string $scene, string $code, mixed $loginId, string $loginType = 'login'): void
    {
        if (!self::verifyCode($scene, $code, $loginId, $loginType)) {
            throw new NotSafeException('敏感操作验证失败');
        }
    }

    public static function isVerified(string $scene, mixed $loginId, string $loginType = 'login'): bool
    {
        $dao = SaToken::getDao();
        $key = self::getKey($scene, $loginId, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return false;
        }

        $info = self::decodeSensitiveState($data, $key);
        if (!is_array($info)) {
            return false;
        }

        $expiresAt = $info['expiresAt'] ?? null;
        return ($info['verified'] ?? false) === true
            && is_int($expiresAt)
            && $expiresAt > time();
    }

    /** Issue a one-time safe token only after consuming a successful OTP verification. */
    public static function createSafeTokenAfterVerified(string $scene, mixed $loginId, string $loginType = 'login', int $validSeconds = 600): string
    {
        self::validateLifetime($validSeconds);
        if (!self::consumeVerified($scene, $loginId, $loginType)) {
            throw new NotSafeException('请先完成该场景的一次性验证码验证');
        }

        return self::createSafeToken($scene, $loginId, $loginType, $validSeconds);
    }

    /** Atomically consume a successful OTP verification before issuing a safe token. */
    protected static function consumeVerified(string $scene, mixed $loginId, string $loginType): bool
    {
        $dao = SaToken::getDao();
        $key = self::getKey($scene, $loginId, $loginType);
        $lockValue = self::acquireStateLock($key);
        try {
            // The distributed lock is a lease and can expire while storage is
            // stalled. Consume the proof atomically so an old lock owner cannot
            // issue a second safe token after another worker consumes it.
            $data = $dao->getAndDelete($key);
            if ($data === null) {
                return false;
            }

            $info = self::decodeSensitiveState($data, $key);
            $expiresAt = is_array($info) ? ($info['expiresAt'] ?? null) : null;
            if (!is_array($info)
                || ($info['verified'] ?? false) !== true
                || !is_int($expiresAt)
                || $expiresAt <= time()) {
                return false;
            }

            $dao->delete($key . ':att');
            $dao->delete($key . ':verified');
            return true;
        } finally {
            self::releaseStateLock($key, $lockValue);
        }
    }

    public static function clearVerified(string $scene, mixed $loginId, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndSetInterface) {
            throw new SaTokenException('DAO 必须实现安全比较设置接口才能清除验证码');
        }
        $key = self::getKey($scene, $loginId, $loginType);
        $lockValue = self::acquireStateLock($key);
        try {
            // The state lock is a lease. A paused worker must not delete an
            // OTP generation written after that lease expired.
            $currentRecord = $dao->get($key);
            if (!$dao->compareAndSet($key, $currentRecord, null)) {
                throw new SaTokenException('验证码状态已并发更新，请重试');
            }
            $dao->delete($key . ':att');
            $dao->delete($key . ':verified');
        } finally {
            self::releaseStateLock($key, $lockValue);
        }
    }

    protected static function acquireStateLock(string $key): string
    {
        $lockValue = bin2hex(random_bytes(16));
        if (!\SaToken\Dao\SaTokenDaoLock::acquire(SaToken::getDao(), $key . ':state-lock', $lockValue, 30)) {
            throw new SaTokenException('敏感验证码状态正在更新，请重试');
        }
        return $lockValue;
    }

    protected static function releaseStateLock(string $key, string $lockValue): void
    {
        $dao = SaToken::getDao();
        \SaToken\Dao\SaTokenDaoLock::release($dao, $key . ':state-lock', $lockValue);
    }

    public static function getRemainingAttempts(string $scene, mixed $loginId, string $loginType = 'login'): int
    {
        $dao = SaToken::getDao();
        $data = $dao->get(self::getKey($scene, $loginId, $loginType));
        if ($data === null) {
            return max(0, self::$maxAttempts);
        }

        $key = self::getKey($scene, $loginId, $loginType);
        $info = self::decodeSensitiveState($data, $key);
        if (!is_array($info)) {
            return 0;
        }
        $attempts = is_int($info['attempts'] ?? null) ? $info['attempts'] : 0;

        return max(0, self::$maxAttempts - $attempts);
    }

    /** @param array<string, mixed> $data */
    protected static function encodeSensitiveState(array $data, string $key): string
    {
        $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new SaTokenException('敏感验证状态序列化失败');
        }

        $payload = base64_encode($json);
        $record = json_encode([
            'payload' => $payload,
            'mac' => hash_hmac('sha256', self::stateMacInput($payload, $key), self::getStateMacKey()),
        ]);
        if (!is_string($record)) {
            throw new SaTokenException('敏感验证状态序列化失败');
        }

        return $record;
    }

    /** @return array<string, mixed>|null */
    protected static function decodeSensitiveState(string $record, string $key): ?array
    {
        $envelope = json_decode($record, true);
        if (!is_array($envelope)
            || !is_string($envelope['payload'] ?? null)
            || !is_string($envelope['mac'] ?? null)) {
            return null;
        }

        $expectedMac = hash_hmac('sha256', self::stateMacInput($envelope['payload'], $key), self::getStateMacKey());
        if (!hash_equals($expectedMac, $envelope['mac'])) {
            return null;
        }

        $json = base64_decode($envelope['payload'], true);
        if ($json === false) {
            return null;
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return null;
        }

        $normalized = [];
        foreach ($data as $field => $value) {
            if (!is_string($field)) {
                return null;
            }
            $normalized[$field] = $value;
        }

        return $normalized;
    }

    protected static function stateMacInput(string $payload, string $key): string
    {
        return "sa-token-sensitive-state:v1\0" . pack('N', strlen($key)) . $key . $payload;
    }

    protected static function getStateMacKey(): string
    {
        $signKey = SaToken::getConfig()->getSignKey();
        if (strlen($signKey) < 32) {
            throw new SaTokenException('敏感验证状态保护需要配置至少 32 字节的 signKey');
        }

        return hash_hkdf('sha256', $signKey, 32, 'sa-token-sensitive-verify-state', '');
    }

    public static function createSafeToken(string $scene, mixed $loginId, string $loginType = 'login', int $validSeconds = 600): string
    {
        self::validateLifetime($validSeconds);
        $token = bin2hex(random_bytes(32));
        $loginIdStr = self::normalizeLoginId($loginId);
        $key = self::$keyPrefix . \SaToken\TokenManager::encodeKeyComponent($loginType)
            . ':safe-token:' . \SaToken\TokenManager::encodeKeyComponent($scene)
            . ':' . hash('sha256', $loginIdStr) . ':' . substr($token, 0, 16);

        $dao = SaToken::getDao();
        $data = [
            'scene' => $scene,
            'loginId' => $loginIdStr,
            'loginType' => $loginType,
            'createdAt' => time(),
            'expiresAt' => time() + $validSeconds,
            'tokenHash' => hash('sha256', $token),
        ];

        $dao->set($key, self::encodeSensitiveState($data, $key), $validSeconds + 60);

        return $token;
    }

    public static function verifySafeToken(string $scene, string $token, mixed $loginId, string $loginType = 'login'): bool
    {
        $loginIdStr = self::normalizeLoginId($loginId);
        $key = self::$keyPrefix . \SaToken\TokenManager::encodeKeyComponent($loginType)
            . ':safe-token:' . \SaToken\TokenManager::encodeKeyComponent($scene)
            . ':' . hash('sha256', $loginIdStr) . ':' . substr($token, 0, 16);
        $dao = SaToken::getDao();
        $data = $dao->get($key);

        if ($data === null) {
            return false;
        }

        $info = self::decodeSensitiveState($data, $key);
        if (!is_array($info)) {
            return false;
        }

        if (($info['scene'] ?? null) !== $scene
            || ($info['loginId'] ?? null) !== $loginIdStr
            || ($info['loginType'] ?? null) !== $loginType) {
            return false;
        }

        $expiresAt = $info['expiresAt'] ?? null;
        if (!is_int($expiresAt) || $expiresAt <= time()) {
            return false;
        }

        // 存储键只含 token 前 16 个 hex 字符，必须用完整 token 哈希校验。
        // 缺少哈希的旧记录 fail closed，不能退回到仅 64 bit 前缀校验。
        $tokenHash = $info['tokenHash'] ?? null;
        if (!is_string($tokenHash) || !hash_equals($tokenHash, hash('sha256', $token))) {
            return false;
        }

        // 读取和删除必须作为一次原子消费；消费后再核对载荷，防止同一前缀下
        // 并发重发或新令牌覆盖时，两个请求都拿到成功结果。
        $consumed = $dao->getAndDelete($key);
        if ($consumed === null) {
            return false;
        }
        $consumedInfo = self::decodeSensitiveState($consumed, $key);
        if (!is_array($consumedInfo)
            || ($consumedInfo['scene'] ?? null) !== $scene
            || ($consumedInfo['loginId'] ?? null) !== $loginIdStr
            || ($consumedInfo['loginType'] ?? null) !== $loginType
            || !is_int($consumedInfo['expiresAt'] ?? null)
            || $consumedInfo['expiresAt'] <= time()) {
            return false;
        }
        $consumedHash = $consumedInfo['tokenHash'] ?? null;
        return is_string($consumedHash) && hash_equals($consumedHash, hash('sha256', $token));
    }

    public static function verifySafeTokenAndThrow(string $scene, string $token, mixed $loginId, string $loginType = 'login'): void
    {
        if (!self::verifySafeToken($scene, $token, $loginId, $loginType)) {
            throw new NotSafeException('安全验证令牌无效或已过期');
        }
    }

    public static function reset(): void
    {
        self::$keyPrefix = 'satoken:sensitive:';
        self::$codeLength = 6;
        self::$validSeconds = 300;
        self::$maxAttempts = 3;
        self::$sendInterval = 60;
    }
}
