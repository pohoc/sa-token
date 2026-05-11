<?php

declare(strict_types=1);

namespace SaToken\Config;

/**
 * Sa-Token 核心配置类
 *
 * 支持数组初始化和链式设置，包含所有配置项
 *
 * 使用示例：
 *   $config = new SaTokenConfig(['tokenName' => 'my-token', 'timeout' => 7200]);
 *   $config->setTokenName('satoken')->setTimeout(86400);
 */
class SaTokenConfig
{
    // Token 名称（同时也是 Cookie 名称、提交参数名、Header 名称）
    protected string $tokenName = 'satoken';

    // Token 前缀（如 'Bearer'，提交时格式为 Bearer xxx）
    protected string $tokenPrefix = '';

    // Token 风格（uuid / simple-random / custom）
    protected string $tokenStyle = 'uuid';

    // Token 有效期（秒），-1 代表永不过期
    protected int $timeout = 86400;

    // Token 最低活动频率（秒），-1 代表不限制
    protected int $activityTimeout = -1;

    // 是否允许同一账号多地同时登录
    protected bool $concurrent = true;

    // 在每次登录时是否产生新的 Token
    protected bool $isShare = true;

    // 同一账号最大登录数量，-1 代表不限制
    protected int $maxLoginCount = 12;

    // 在每次创建 Token 时的最高循环次数
    protected int $maxTryTimes = 12;

    // 是否从 Header 中读取 Token
    protected bool $isReadHeader = true;

    // 是否从 Cookie 中读取 Token
    protected bool $isReadCookie = true;

    // 是否从请求体里读取 Token
    protected bool $isReadBody = false;

    // 登录后是否将 Token 写入 Cookie
    protected bool $isWriteCookie = true;

    // 登录后是否将 Token 写入响应头
    protected bool $isWriteHeader = false;

    // Cookie 作用域
    protected string $cookieDomain = '';

    // Cookie 路径
    protected string $cookiePath = '/';

    // Cookie 是否仅 HTTPS 传输
    protected bool $cookieSecure = false;

    // Cookie 是否 HttpOnly
    protected bool $cookieHttpOnly = false;

    // Cookie SameSite 策略（Strict / Lax / None）
    protected string $cookieSameSite = 'Lax';

    // 加密类型：intl / sm
    protected string $cryptoType = 'intl';

    // AES 密钥
    protected string $aesKey = '';

    // RSA 私钥
    protected string $rsaPrivateKey = '';

    // RSA 公钥
    protected string $rsaPublicKey = '';

    // HMAC 密钥
    protected string $hmacKey = '';

    // 国密 SM2 私钥
    protected string $sm2PrivateKey = '';

    // 国密 SM2 公钥
    protected string $sm2PublicKey = '';

    // 国密 SM4 密钥
    protected string $sm4Key = '';

    // JWT 密钥
    protected string $jwtSecretKey = '';

    // JWT 无状态模式
    protected bool $jwtStateless = false;

    // JWT 模式（simple / mixed / stateless）
    protected string $jwtMode = 'simple';

    // 是否开启 Token 内容加密
    protected bool $tokenEncrypt = false;

    // Token 内容加密密钥（为空时自动使用 aesKey）
    protected string $tokenEncryptKey = '';

    // 是否在登录后将 Token 信息写入 Session
    protected bool $tokenSessionCheckLogin = true;

    // 是否启用独立 Redis
    protected bool $separateRedis = false;

    // 独立 Redis 连接配置（host, port, db, password, timeout）
    protected array $separateRedisConfig = [];

    // 签名密钥
    protected string $signKey = '';

    // 签名时间戳容差（秒）
    protected int $signTimestampGap = 600;

    // 签名算法（md5 / sha256）
    protected string $signAlg = 'md5';

    // SSO 配置
    protected array $sso = [
        'loginUrl'          => '',
        'authUrl'           => '',
        'backUrl'           => '',
        'checkTicketUrl'    => '',
        'sloUrl'            => '',
        'mode'              => 'same-domain',
        'clientId'          => '',
        'clientSecret'      => '',
        'allowDomains'      => [],
        'crossRedis'        => false,
        'crossRedisCheckUrl' => '',
    ];

    // OAuth2 配置
    protected array $oauth2 = [
        'grantTypes'           => ['authorization_code'],
        'codeTimeout'          => 60,
        'accessTokenTimeout'   => 7200,
        'refreshTokenTimeout'  => -1,
        'isNewRefreshToken'    => false,
        'openIdMode'           => false,
        'issuer'               => '',
    ];

    // API Key 请求头名称
    protected string $apiKeyHeader = 'api-key';

    // API Secret 请求头名称
    protected string $apiSecretHeader = 'api-secret';

    /**
     * @param array $config 配置数组
     */
    public function __construct(array $config = [])
    {
        $this->initFromArray($config);
    }

    /**
     * 从数组初始化配置
     *
     * @param  array  $config 配置数组
     * @return static
     */
    public function initFromArray(array $config): static
    {
        foreach ($config as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->$method($value);
            }
        }
        return $this;
    }

    /**
     * 转换为数组
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'tokenName'              => $this->tokenName,
            'tokenPrefix'            => $this->tokenPrefix,
            'tokenStyle'             => $this->tokenStyle,
            'timeout'                => $this->timeout,
            'activityTimeout'        => $this->activityTimeout,
            'concurrent'             => $this->concurrent,
            'isShare'                => $this->isShare,
            'maxLoginCount'          => $this->maxLoginCount,
            'maxTryTimes'            => $this->maxTryTimes,
            'isReadHeader'           => $this->isReadHeader,
            'isReadCookie'           => $this->isReadCookie,
            'isReadBody'             => $this->isReadBody,
            'isWriteCookie'          => $this->isWriteCookie,
            'isWriteHeader'          => $this->isWriteHeader,
            'cookieDomain'           => $this->cookieDomain,
            'cookiePath'             => $this->cookiePath,
            'cookieSecure'           => $this->cookieSecure,
            'cookieHttpOnly'         => $this->cookieHttpOnly,
            'cookieSameSite'         => $this->cookieSameSite,
            'cryptoType'             => $this->cryptoType,
            'aesKey'                 => $this->aesKey,
            'rsaPrivateKey'          => $this->rsaPrivateKey,
            'rsaPublicKey'           => $this->rsaPublicKey,
            'hmacKey'                => $this->hmacKey,
            'sm2PrivateKey'          => $this->sm2PrivateKey,
            'sm2PublicKey'           => $this->sm2PublicKey,
            'sm4Key'                 => $this->sm4Key,
            'jwtSecretKey'           => $this->jwtSecretKey,
            'jwtStateless'           => $this->jwtStateless,
            'jwtMode'                => $this->jwtMode,
            'tokenEncrypt'           => $this->tokenEncrypt,
            'tokenEncryptKey'        => $this->tokenEncryptKey,
            'tokenSessionCheckLogin' => $this->tokenSessionCheckLogin,
            'separateRedis'          => $this->separateRedis,
            'separateRedisConfig'    => $this->separateRedisConfig,
            'signKey'                => $this->signKey,
            'signTimestampGap'       => $this->signTimestampGap,
            'signAlg'                => $this->signAlg,
            'sso'                    => $this->sso,
            'oauth2'                 => $this->oauth2,
            'apiKeyHeader'           => $this->apiKeyHeader,
            'apiSecretHeader'        => $this->apiSecretHeader,
        ];
    }

    // ---- Getter / Setter ----

    public function getTokenName(): string
    {
        return $this->tokenName;
    }

    public function setTokenName(string $tokenName): static
    {
        $this->tokenName = $tokenName;
        return $this;
    }

    public function getTokenPrefix(): string
    {
        return $this->tokenPrefix;
    }

    public function setTokenPrefix(string $tokenPrefix): static
    {
        $this->tokenPrefix = $tokenPrefix;
        return $this;
    }

    public function getTokenStyle(): string
    {
        return $this->tokenStyle;
    }

    public function setTokenStyle(string $tokenStyle): static
    {
        $this->tokenStyle = $tokenStyle;
        return $this;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    public function setTimeout(int $timeout): static
    {
        $this->timeout = $timeout;
        return $this;
    }

    public function getActivityTimeout(): int
    {
        return $this->activityTimeout;
    }

    public function setActivityTimeout(int $activityTimeout): static
    {
        $this->activityTimeout = $activityTimeout;
        return $this;
    }

    public function isConcurrent(): bool
    {
        return $this->concurrent;
    }

    public function setConcurrent(bool $concurrent): static
    {
        $this->concurrent = $concurrent;
        return $this;
    }

    public function isShare(): bool
    {
        return $this->isShare;
    }

    public function setIsShare(bool $isShare): static
    {
        $this->isShare = $isShare;
        return $this;
    }

    public function getMaxLoginCount(): int
    {
        return $this->maxLoginCount;
    }

    public function setMaxLoginCount(int $maxLoginCount): static
    {
        $this->maxLoginCount = $maxLoginCount;
        return $this;
    }

    public function getMaxTryTimes(): int
    {
        return $this->maxTryTimes;
    }

    public function setMaxTryTimes(int $maxTryTimes): static
    {
        $this->maxTryTimes = $maxTryTimes;
        return $this;
    }

    public function isReadHeader(): bool
    {
        return $this->isReadHeader;
    }

    public function setIsReadHeader(bool $isReadHeader): static
    {
        $this->isReadHeader = $isReadHeader;
        return $this;
    }

    public function isReadCookie(): bool
    {
        return $this->isReadCookie;
    }

    public function setIsReadCookie(bool $isReadCookie): static
    {
        $this->isReadCookie = $isReadCookie;
        return $this;
    }

    public function isReadBody(): bool
    {
        return $this->isReadBody;
    }

    public function setIsReadBody(bool $isReadBody): static
    {
        $this->isReadBody = $isReadBody;
        return $this;
    }

    public function isWriteCookie(): bool
    {
        return $this->isWriteCookie;
    }

    public function setIsWriteCookie(bool $isWriteCookie): static
    {
        $this->isWriteCookie = $isWriteCookie;
        return $this;
    }

    public function isWriteHeader(): bool
    {
        return $this->isWriteHeader;
    }

    public function setIsWriteHeader(bool $isWriteHeader): static
    {
        $this->isWriteHeader = $isWriteHeader;
        return $this;
    }

    public function getCookieDomain(): string
    {
        return $this->cookieDomain;
    }

    public function setCookieDomain(string $cookieDomain): static
    {
        $this->cookieDomain = $cookieDomain;
        return $this;
    }

    public function getCookiePath(): string
    {
        return $this->cookiePath;
    }

    public function setCookiePath(string $cookiePath): static
    {
        $this->cookiePath = $cookiePath;
        return $this;
    }

    public function isCookieSecure(): bool
    {
        return $this->cookieSecure;
    }

    public function setCookieSecure(bool $cookieSecure): static
    {
        $this->cookieSecure = $cookieSecure;
        return $this;
    }

    public function isCookieHttpOnly(): bool
    {
        return $this->cookieHttpOnly;
    }

    public function setCookieHttpOnly(bool $cookieHttpOnly): static
    {
        $this->cookieHttpOnly = $cookieHttpOnly;
        return $this;
    }

    public function getCookieSameSite(): string
    {
        return $this->cookieSameSite;
    }

    public function setCookieSameSite(string $cookieSameSite): static
    {
        $this->cookieSameSite = $cookieSameSite;
        return $this;
    }

    public function getCryptoType(): string
    {
        return $this->cryptoType;
    }

    public function setCryptoType(string $cryptoType): static
    {
        $this->cryptoType = $cryptoType;
        return $this;
    }

    public function getAesKey(): string
    {
        return $this->aesKey;
    }

    public function setAesKey(string $aesKey): static
    {
        $this->aesKey = $aesKey;
        return $this;
    }

    public function getRsaPrivateKey(): string
    {
        return $this->rsaPrivateKey;
    }

    public function setRsaPrivateKey(string $rsaPrivateKey): static
    {
        $this->rsaPrivateKey = $rsaPrivateKey;
        return $this;
    }

    public function getRsaPublicKey(): string
    {
        return $this->rsaPublicKey;
    }

    public function setRsaPublicKey(string $rsaPublicKey): static
    {
        $this->rsaPublicKey = $rsaPublicKey;
        return $this;
    }

    public function getHmacKey(): string
    {
        return $this->hmacKey;
    }

    public function setHmacKey(string $hmacKey): static
    {
        $this->hmacKey = $hmacKey;
        return $this;
    }

    public function getSm2PrivateKey(): string
    {
        return $this->sm2PrivateKey;
    }

    public function setSm2PrivateKey(string $sm2PrivateKey): static
    {
        $this->sm2PrivateKey = $sm2PrivateKey;
        return $this;
    }

    public function getSm2PublicKey(): string
    {
        return $this->sm2PublicKey;
    }

    public function setSm2PublicKey(string $sm2PublicKey): static
    {
        $this->sm2PublicKey = $sm2PublicKey;
        return $this;
    }

    public function getSm4Key(): string
    {
        return $this->sm4Key;
    }

    public function setSm4Key(string $sm4Key): static
    {
        $this->sm4Key = $sm4Key;
        return $this;
    }

    public function getJwtSecretKey(): string
    {
        return $this->jwtSecretKey;
    }

    public function setJwtSecretKey(string $jwtSecretKey): static
    {
        $this->jwtSecretKey = $jwtSecretKey;
        return $this;
    }

    public function isJwtStateless(): bool
    {
        return $this->jwtStateless;
    }

    public function setJwtStateless(bool $jwtStateless): static
    {
        $this->jwtStateless = $jwtStateless;
        return $this;
    }

    public function getJwtMode(): string
    {
        return $this->jwtMode;
    }

    public function setJwtMode(string $jwtMode): static
    {
        $this->jwtMode = $jwtMode;
        return $this;
    }

    public function isTokenEncrypt(): bool
    {
        return $this->tokenEncrypt;
    }

    public function setTokenEncrypt(bool $tokenEncrypt): static
    {
        $this->tokenEncrypt = $tokenEncrypt;
        return $this;
    }

    public function getTokenEncryptKey(): string
    {
        return $this->tokenEncryptKey;
    }

    public function setTokenEncryptKey(string $tokenEncryptKey): static
    {
        $this->tokenEncryptKey = $tokenEncryptKey;
        return $this;
    }

    public function isTokenSessionCheckLogin(): bool
    {
        return $this->tokenSessionCheckLogin;
    }

    public function setTokenSessionCheckLogin(bool $tokenSessionCheckLogin): static
    {
        $this->tokenSessionCheckLogin = $tokenSessionCheckLogin;
        return $this;
    }

    public function isSeparateRedis(): bool
    {
        return $this->separateRedis;
    }

    public function setSeparateRedis(bool $separateRedis): static
    {
        $this->separateRedis = $separateRedis;
        return $this;
    }

    public function getSeparateRedisConfig(): array
    {
        return $this->separateRedisConfig;
    }

    public function setSeparateRedisConfig(array $separateRedisConfig): static
    {
        $this->separateRedisConfig = $separateRedisConfig;
        return $this;
    }

    public function getSignKey(): string
    {
        return $this->signKey;
    }

    public function setSignKey(string $signKey): static
    {
        $this->signKey = $signKey;
        return $this;
    }

    public function getSignTimestampGap(): int
    {
        return $this->signTimestampGap;
    }

    public function setSignTimestampGap(int $signTimestampGap): static
    {
        $this->signTimestampGap = $signTimestampGap;
        return $this;
    }

    public function getSignAlg(): string
    {
        return $this->signAlg;
    }

    public function setSignAlg(string $signAlg): static
    {
        $this->signAlg = $signAlg;
        return $this;
    }

    public function getSso(): array
    {
        return $this->sso;
    }

    public function setSso(array $sso): static
    {
        $this->sso = array_merge($this->sso, $sso);
        return $this;
    }

    /**
     * 获取 SSO 配置项
     *
     * @param  string $key     配置键名
     * @param  mixed  $default 默认值
     * @return mixed
     */
    public function getSsoValue(string $key, mixed $default = null): mixed
    {
        return $this->sso[$key] ?? $default;
    }

    public function getOauth2(): array
    {
        return $this->oauth2;
    }

    public function setOauth2(array $oauth2): static
    {
        $this->oauth2 = array_merge($this->oauth2, $oauth2);
        return $this;
    }

    /**
     * 获取 OAuth2 配置项
     *
     * @param  string $key     配置键名
     * @param  mixed  $default 默认值
     * @return mixed
     */
    public function getOauth2Value(string $key, mixed $default = null): mixed
    {
        return $this->oauth2[$key] ?? $default;
    }

    public function getApiKeyHeader(): string
    {
        return $this->apiKeyHeader;
    }

    public function setApiKeyHeader(string $apiKeyHeader): static
    {
        $this->apiKeyHeader = $apiKeyHeader;
        return $this;
    }

    public function getApiSecretHeader(): string
    {
        return $this->apiSecretHeader;
    }

    public function setApiSecretHeader(string $apiSecretHeader): static
    {
        $this->apiSecretHeader = $apiSecretHeader;
        return $this;
    }
}
