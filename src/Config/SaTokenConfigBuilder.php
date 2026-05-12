<?php

declare(strict_types=1);

namespace SaToken\Config;

/**
 * Sa-Token 配置构建器
 *
 * 提供流式API配置Sa-Token
 * 使用示例：
 *
 *   $config = SaTokenConfigBuilder::create()
 *       ->tokenName('satoken')
 *       ->timeout(86400)
 *       ->tokenStyle('uuid')
 *       ->build();
 */
class SaTokenConfigBuilder
{
    protected array $config = [];

    public static function create(): self
    {
        return new self();
    }

    public function tokenName(string $name): self
    {
        $this->config['tokenName'] = $name;
        return $this;
    }

    public function tokenPrefix(string $prefix): self
    {
        $this->config['tokenPrefix'] = $prefix;
        return $this;
    }

    public function tokenStyle(string $style): self
    {
        $this->config['tokenStyle'] = $style;
        return $this;
    }

    public function timeout(int $timeout): self
    {
        $this->config['timeout'] = $timeout;
        return $this;
    }

    public function activityTimeout(int $timeout): self
    {
        $this->config['activityTimeout'] = $timeout;
        return $this;
    }

    public function concurrent(bool $concurrent): self
    {
        $this->config['concurrent'] = $concurrent;
        return $this;
    }

    public function isShare(bool $isShare): self
    {
        $this->config['isShare'] = $isShare;
        return $this;
    }

    public function maxLoginCount(int $count): self
    {
        $this->config['maxLoginCount'] = $count;
        return $this;
    }

    public function isReadHeader(bool $read): self
    {
        $this->config['isReadHeader'] = $read;
        return $this;
    }

    public function isReadCookie(bool $read): self
    {
        $this->config['isReadCookie'] = $read;
        return $this;
    }

    public function isReadBody(bool $read): self
    {
        $this->config['isReadBody'] = $read;
        return $this;
    }

    public function isWriteCookie(bool $write): self
    {
        $this->config['isWriteCookie'] = $write;
        return $this;
    }

    public function isWriteHeader(bool $write): self
    {
        $this->config['isWriteHeader'] = $write;
        return $this;
    }

    public function cookieDomain(string $domain): self
    {
        $this->config['cookieDomain'] = $domain;
        return $this;
    }

    public function cookiePath(string $path): self
    {
        $this->config['cookiePath'] = $path;
        return $this;
    }

    public function cookieSecure(bool $secure): self
    {
        $this->config['cookieSecure'] = $secure;
        return $this;
    }

    public function cookieHttpOnly(bool $httpOnly): self
    {
        $this->config['cookieHttpOnly'] = $httpOnly;
        return $this;
    }

    public function cookieSameSite(string $sameSite): self
    {
        $this->config['cookieSameSite'] = $sameSite;
        return $this;
    }

    public function cryptoType(string $type): self
    {
        $this->config['cryptoType'] = $type;
        return $this;
    }

    public function aesKey(string $key): self
    {
        $this->config['aesKey'] = $key;
        return $this;
    }

    public function rsaPrivateKey(string $key): self
    {
        $this->config['rsaPrivateKey'] = $key;
        return $this;
    }

    public function rsaPublicKey(string $key): self
    {
        $this->config['rsaPublicKey'] = $key;
        return $this;
    }

    public function hmacKey(string $key): self
    {
        $this->config['hmacKey'] = $key;
        return $this;
    }

    public function sm2PrivateKey(string $key): self
    {
        $this->config['sm2PrivateKey'] = $key;
        return $this;
    }

    public function sm2PublicKey(string $key): self
    {
        $this->config['sm2PublicKey'] = $key;
        return $this;
    }

    public function sm4Key(string $key): self
    {
        $this->config['sm4Key'] = $key;
        return $this;
    }

    public function jwtSecretKey(string $key): self
    {
        $this->config['jwtSecretKey'] = $key;
        return $this;
    }

    public function jwtStateless(bool $stateless): self
    {
        $this->config['jwtStateless'] = $stateless;
        return $this;
    }

    public function jwtMode(string $mode): self
    {
        $this->config['jwtMode'] = $mode;
        return $this;
    }

    public function tokenEncrypt(bool $encrypt): self
    {
        $this->config['tokenEncrypt'] = $encrypt;
        return $this;
    }

    public function tokenEncryptKey(string $key): self
    {
        $this->config['tokenEncryptKey'] = $key;
        return $this;
    }

    public function signKey(string $key): self
    {
        $this->config['signKey'] = $key;
        return $this;
    }

    public function signTimestampGap(int $gap): self
    {
        $this->config['signTimestampGap'] = $gap;
        return $this;
    }

    public function signAlg(string $alg): self
    {
        $this->config['signAlg'] = $alg;
        return $this;
    }

    public function antiBruteMaxFailures(int $count): self
    {
        $this->config['antiBruteMaxFailures'] = $count;
        return $this;
    }

    public function antiBruteLockDuration(int $seconds): self
    {
        $this->config['antiBruteLockDuration'] = $seconds;
        return $this;
    }

    public function deviceManagement(bool $enabled): self
    {
        $this->config['deviceManagement'] = $enabled;
        return $this;
    }

    public function ipAnomalyDetection(bool $enabled): self
    {
        $this->config['ipAnomalyDetection'] = $enabled;
        return $this;
    }

    public function ipAnomalySensitivity(int $sensitivity): self
    {
        $this->config['ipAnomalySensitivity'] = $sensitivity;
        return $this;
    }

    public function auditLog(bool $enabled): self
    {
        $this->config['auditLog'] = $enabled;
        return $this;
    }

    public function auditLogMaxEntries(int $count): self
    {
        $this->config['auditLogMaxEntries'] = $count;
        return $this;
    }

    public function auditLogTtlDays(int $days): self
    {
        $this->config['auditLogTtlDays'] = $days;
        return $this;
    }

    public function refreshToken(bool $enabled): self
    {
        $this->config['refreshToken'] = $enabled;
        return $this;
    }

    public function refreshTokenTimeout(int $timeout): self
    {
        $this->config['refreshTokenTimeout'] = $timeout;
        return $this;
    }

    public function refreshTokenRotation(bool $rotation): self
    {
        $this->config['refreshTokenRotation'] = $rotation;
        return $this;
    }

    public function tokenFingerprint(bool $enabled): self
    {
        $this->config['tokenFingerprint'] = $enabled;
        return $this;
    }

    /**
     * @param array<string, mixed> $ssoConfig
     */
    public function sso(array $ssoConfig): self
    {
        $this->config['sso'] = $ssoConfig;
        return $this;
    }

    /**
     * @param array<string, mixed> $oauth2Config
     */
    public function oauth2(array $oauth2Config): self
    {
        $this->config['oauth2'] = $oauth2Config;
        return $this;
    }

    public function apiKeyHeader(string $header): self
    {
        $this->config['apiKeyHeader'] = $header;
        return $this;
    }

    public function build(): SaTokenConfig
    {
        /** @var array<string, mixed> $config */
        $config = $this->config;
        return new SaTokenConfig($config);
    }
}
