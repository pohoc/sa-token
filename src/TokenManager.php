<?php

declare(strict_types=1);

namespace SaToken;

use SaToken\Config\SaTokenConfig;
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

    public function createTokenValue(mixed $loginId, string $loginType, string $prefix = 'sat_'): string
    {
        $action = SaToken::getAction();
        if ($action !== null) {
            $customToken = $action->generateTokenValue($loginId, $loginType);
            if ($customToken !== null) {
                return $customToken;
            }
        }

        $style = $this->getConfig()->getTokenStyle();
        $raw = match ($style) {
            'uuid'          => SaFoxUtil::uuid(),
            'simple-random' => SaFoxUtil::randomString(32),
            'random-64'     => SaFoxUtil::randomString(64),
            'random-128'    => SaFoxUtil::randomString(128),
            'random-256'    => SaFoxUtil::randomString(256),
            'tiket'         => SaFoxUtil::randomNumber(20),
            default         => SaFoxUtil::uuid(),
        };
        return $prefix . $raw;
    }

    public function saveToken(string $tokenValue, mixed $loginId, string $loginType, string $deviceType = '', ?int $timeout = null): void
    {
        $config = $this->getConfig();
        $timeout = $timeout ?? $config->getTimeout();
        $effectiveTimeout = ($timeout === -1) ? null : $timeout;

        if ($config->getJwtMode() === 'mixed') {
            $tokenValue = $this->getJwtInstance()->createMixedToken($loginId, $loginType, $effectiveTimeout);
        }

        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $this->getDao()->set(self::TOKEN_PREFIX . $tokenValue, $this->encryptValue($loginIdStr), $effectiveTimeout);

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
    }

    public function getLoginIdByToken(string $tokenValue): ?string
    {
        $value = $this->getDao()->get(self::TOKEN_PREFIX . $tokenValue);
        if ($value !== null) {
            return $this->decryptValue($value);
        }

        $config = $this->getConfig();
        if ($config->getJwtMode() === 'mixed') {
            $loginId = $this->getJwtInstance()->getLoginId($tokenValue);
            if ($loginId !== null) {
                $daoValue = $this->getDao()->get(self::TOKEN_PREFIX . $tokenValue);
                if ($daoValue !== null) {
                    return $this->decryptValue($daoValue);
                }
                return $loginId;
            }
        }

        return null;
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
        return $data;
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

    public function addToBlacklist(string $tokenValue, int $timeout): void
    {
        $this->getDao()->set(self::BLACKLIST_PREFIX . $tokenValue, '1', $timeout > 0 ? $timeout : null);
    }

    public function isBlacklisted(string $tokenValue): bool
    {
        return $this->getDao()->exists(self::BLACKLIST_PREFIX . $tokenValue);
    }

    public function removeFromBlacklist(string $tokenValue): void
    {
        $this->getDao()->delete(self::BLACKLIST_PREFIX . $tokenValue);
    }
}
