<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Config\SaTokenConfig;
use SaToken\Util\SaFoxUtil;
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

    protected ?SaTokenEncryptor $encryptor = null;

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

    protected function encryptValue(string $value): string
    {
        return $this->getEncryptor()->encrypt($value);
    }

    protected function decryptValue(string $value): string
    {
        return $this->getEncryptor()->decrypt($value);
    }

    public function createTokenValue(mixed $loginId, string $loginType): string
    {
        $action = SaToken::getAction();
        if ($action !== null) {
            $customToken = $action->generateTokenValue($loginId, $loginType);
            if ($customToken !== null) {
                return $customToken;
            }
        }

        $style = $this->getConfig()->getTokenStyle();
        return match ($style) {
            'uuid'          => SaFoxUtil::uuid(),
            'simple-random' => SaFoxUtil::randomString(32),
            'random-64'     => SaFoxUtil::randomString(64),
            'random-128'    => SaFoxUtil::randomString(128),
            'random-256'    => SaFoxUtil::randomString(256),
            'tiket'         => SaFoxUtil::randomNumber(20),
            default         => SaFoxUtil::uuid(),
        };
    }

    public function saveToken(string $tokenValue, mixed $loginId, string $loginType, string $deviceType = '', ?int $timeout = null): void
    {
        $config = $this->getConfig();
        $timeout = $timeout ?? $config->getTimeout();
        $effectiveTimeout = ($timeout === -1) ? null : $timeout;

        $this->getDao()->set(self::TOKEN_PREFIX . $tokenValue, $this->encryptValue((string) $loginId), $effectiveTimeout);

        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginId;
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
                    if ($item['deviceType'] === $deviceType && !$this->isTokenValid($item['tokenValue'])) {
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
    }

    public function getLoginIdByToken(string $tokenValue): ?string
    {
        $value = $this->getDao()->get(self::TOKEN_PREFIX . $tokenValue);
        if ($value === null) {
            return null;
        }
        return $this->decryptValue($value);
    }

    public function getTokenListByLoginId(mixed $loginId, string $loginType): array
    {
        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginId;
        $json = $this->getDao()->get($loginIdKey);
        if ($json === null) {
            return [];
        }
        $decrypted = $this->decryptValue($json);
        $list = SaFoxUtil::fromJson($decrypted);
        return is_array($list) ? $list : [];
    }

    public function deleteToken(string $tokenValue, mixed $loginId, string $loginType): void
    {
        $this->getDao()->delete(self::TOKEN_PREFIX . $tokenValue);

        $loginIdKey = self::LOGIN_ID_PREFIX . $loginType . ':' . $loginId;
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
        $this->getDao()->delete(self::SESSION_PREFIX . $loginType . ':' . $loginId);

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
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        $data = SaFoxUtil::toJson([
            'level'   => $level,
            'disable' => true,
            'time'    => $time,
        ]);
        $this->getDao()->set($key, $this->encryptValue($data), $time > 0 ? $time : null);
    }

    public function isDisable(mixed $loginId, string $service, string $loginType): bool
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        $json = $this->getDao()->get($key);
        if ($json === null) {
            return false;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        return isset($data['disable']) && $data['disable'] === true;
    }

    public function getDisableLevel(mixed $loginId, string $service, string $loginType): int
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        $json = $this->getDao()->get($key);
        if ($json === null) {
            return -1;
        }
        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        return $data['level'] ?? -1;
    }

    public function getDisableTime(mixed $loginId, string $service, string $loginType): int
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
        return $this->getDao()->getTimeout($key);
    }

    public function untieDisable(mixed $loginId, string $service, string $loginType): void
    {
        $key = self::DISABLE_PREFIX . $loginType . ':' . $loginId . ':' . $service;
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
        $this->getDao()->set($key, $this->encryptValue(SaFoxUtil::toString($switchToId)));
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

    public function searchTokenValue(string $keyword, int $start, int $size): array
    {
        return $this->getDao()->search(self::TOKEN_PREFIX, $keyword, $start, $size);
    }

    public function searchSessionId(string $keyword, int $start, int $size): array
    {
        return $this->getDao()->search(self::SESSION_PREFIX, $keyword, $start, $size);
    }

    public function searchTokenSessionId(string $keyword, int $start, int $size): array
    {
        return $this->getDao()->search(self::TOKEN_SESSION_PREFIX, $keyword, $start, $size);
    }

    public function resetEncryptor(): void
    {
        $this->encryptor = null;
    }
}
