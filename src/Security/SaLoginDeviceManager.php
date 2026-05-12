<?php

declare(strict_types=1);

namespace SaToken\Security;

use SaToken\Data\SaLoginDevice;
use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

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
        return self::$keyPrefix . $loginType . ':' . md5($loginIdStr);
    }

    public static function registerDevice(mixed $loginId, string $loginType = 'login', ?SaLoginDevice $device = null, ?string $tokenValue = null): SaLoginDevice
    {
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

        $jsonStr = json_encode($device->toArray());
        $dao->set($key, $jsonStr !== false ? $jsonStr : '{}', $timeout > 0 ? $timeout + 60 : null);

        return $device;
    }

    /**
     * @return array<SaLoginDevice>
     */
    public static function getDeviceList(mixed $loginId, string $loginType = 'login'): array
    {
        $dao = SaToken::getDao();
        $keyPrefix = self::getKey($loginId, $loginType) . ':';
        $results = $dao->search($keyPrefix, '', 0, 100);

        $devices = [];
        foreach ($results as $value) {
            if ($value === '') {
                continue;
            }
            $data = @json_decode($value, true);
            if (!is_array($data)) {
                continue;
            }
            /** @var array<string, mixed> $data */
            $devices[] = new SaLoginDevice($data);
        }

        usort($devices, fn ($a, $b) => $b->getLoginTime() - $a->getLoginTime());
        return $devices;
    }

    public static function getDeviceCount(mixed $loginId, string $loginType = 'login'): int
    {
        return count(self::getDeviceList($loginId, $loginType));
    }

    public static function kickoutDevice(mixed $loginId, string $deviceId, string $loginType = 'login'): void
    {
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType) . ':' . $deviceId;
        $dao->delete($key);
    }

    public static function kickoutAllDevices(mixed $loginId, string $loginType = 'login', ?string $exceptToken = null): int
    {
        $devices = self::getDeviceList($loginId, $loginType);
        $count = 0;

        foreach ($devices as $device) {
            if ($exceptToken !== null && $device->getTokenValue() === $exceptToken) {
                continue;
            }
            self::kickoutDevice($loginId, $device->getDeviceId(), $loginType);
            $count++;
        }

        return $count;
    }

    public static function findDevice(mixed $loginId, string $deviceId, string $loginType = 'login'): ?SaLoginDevice
    {
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType) . ':' . $deviceId;
        $data = $dao->get($key);

        if ($data === null) {
            return null;
        }

        $decoded = @json_decode($data, true);
        if (!is_array($decoded)) {
            return null;
        }

        /** @var array<string, mixed> $decoded */
        return new SaLoginDevice($decoded);
    }

    public static function updateLastActive(mixed $loginId, string $deviceId, string $loginType = 'login'): void
    {
        $device = self::findDevice($loginId, $deviceId, $loginType);
        if ($device === null) {
            return;
        }

        $device->setLastActiveTime(time());
        $dao = SaToken::getDao();
        $key = self::getKey($loginId, $loginType) . ':' . $deviceId;
        $jsonStr = json_encode($device->toArray());
        $dao->set($key, $jsonStr !== false ? $jsonStr : '{}', null);
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
