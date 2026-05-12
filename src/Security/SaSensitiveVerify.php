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

    public static function setCodeLength(int $length): void
    {
        self::$codeLength = $length;
    }

    public static function setValidSeconds(int $seconds): void
    {
        self::$validSeconds = $seconds;
    }

    public static function setMaxAttempts(int $max): void
    {
        self::$maxAttempts = $max;
    }

    public static function getKey(string $scene, mixed $loginId, string $loginType = 'login'): string
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        return self::$keyPrefix . $loginType . ':' . $scene . ':' . md5($loginIdStr);
    }

    public static function generateCode(string $scene, mixed $loginId, string $loginType = 'login'): string
    {
        $dao = SaToken::getDao();
        $key = self::getKey($scene, $loginId, $loginType);

        $code = self::generateRandomCode();

        $data = [
            'code' => $code,
            'createdAt' => time(),
            'expiresAt' => time() + self::$validSeconds,
            'attempts' => 0,
            'verified' => false,
        ];

        $jsonStr = json_encode($data);
        $dao->set($key, $jsonStr !== false ? $jsonStr : '{}', self::$validSeconds + 60);

        return $code;
    }

    protected static function generateRandomCode(): string
    {
        $code = '';
        for ($i = 0; $i < self::$codeLength; $i++) {
            $code .= random_int(0, 9);
        }
        return $code;
    }

    public static function sendCode(string $scene, mixed $loginId, string $loginType = 'login'): string
    {
        $code = self::generateCode($scene, $loginId, $loginType);

        self::sendNotification($scene, $code, $loginId);

        return $code;
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
        $key = self::getKey($scene, $loginId, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return false;
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return false;
        }

        if (($info['verified'] ?? false) === true) {
            return false;
        }

        $expiresAt = $info['expiresAt'] ?? 0;
        if ($expiresAt > 0 && $expiresAt < time()) {
            $dao->delete($key);
            return false;
        }

        $attempts = $info['attempts'] ?? 0;
        $attemptsInt = is_int($attempts) ? $attempts : 0;
        $attemptsInt = $attemptsInt + 1;
        if ($attemptsInt > self::$maxAttempts) {
            $dao->delete($key);
            throw new SaTokenException('验证码尝试次数过多，请重新获取', -1);
        }

        $codeStr = $info['code'] ?? '';
        if (!hash_equals(is_string($codeStr) ? $codeStr : (is_scalar($codeStr) ? (string) $codeStr : ''), $code)) {
            $info['attempts'] = $attemptsInt;
            $jsonStr = json_encode($info);
            $expiresAtInt = is_int($expiresAt) ? $expiresAt : 0;
            $dao->set($key, $jsonStr !== false ? $jsonStr : '{}', $expiresAtInt > 0 ? ($expiresAtInt - time() + 60) : null);
            return false;
        }

        $info['verified'] = true;
        $info['verifiedAt'] = time();
        $jsonStr = json_encode($info);
        $dao->set($key, $jsonStr !== false ? $jsonStr : '{}', 60);

        return true;
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

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return false;
        }

        return ($info['verified'] ?? false) === true;
    }

    public static function clearVerified(string $scene, mixed $loginId, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $key = self::getKey($scene, $loginId, $loginType);
        $dao->delete($key);
    }

    public static function getRemainingAttempts(string $scene, mixed $loginId, string $loginType = 'login'): int
    {
        $dao = SaToken::getDao();
        $key = self::getKey($scene, $loginId, $loginType);
        $data = $dao->get($key);

        if ($data === null) {
            return self::$maxAttempts;
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return self::$maxAttempts;
        }

        $attempts = $info['attempts'] ?? 0;
        return max(0, self::$maxAttempts - (is_int($attempts) ? $attempts : 0));
    }

    public static function createSafeToken(string $scene, mixed $loginId, string $loginType = 'login', int $validSeconds = 600): string
    {
        $token = bin2hex(random_bytes(32));
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::$keyPrefix . $loginType . ':safe-token:' . $scene . ':' . md5($loginIdStr) . ':' . substr($token, 0, 16);

        $dao = SaToken::getDao();
        $data = [
            'scene' => $scene,
            'loginId' => $loginIdStr,
            'loginType' => $loginType,
            'createdAt' => time(),
            'expiresAt' => time() + $validSeconds,
        ];

        $jsonStr = json_encode($data);
        $dao->set($key, $jsonStr !== false ? $jsonStr : '{}', $validSeconds + 60);

        return $token;
    }

    public static function verifySafeToken(string $scene, string $token, mixed $loginId, string $loginType = 'login'): bool
    {
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $key = self::$keyPrefix . $loginType . ':safe-token:' . $scene . ':' . md5($loginIdStr) . ':' . substr($token, 0, 16);
        $dao = SaToken::getDao();
        $data = $dao->get($key);

        if ($data === null) {
            return false;
        }

        $info = @json_decode($data, true);
        if (!is_array($info)) {
            return false;
        }

        $expiresAt = $info['expiresAt'] ?? 0;
        if ($expiresAt > 0 && $expiresAt < time()) {
            $dao->delete($key);
            return false;
        }

        $dao->delete($key);
        return true;
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
    }
}
