<?php

// Sa-Token 配置文件
// 在项目根目录 config/sa_token.php 中返回此数组即可，SaToken::init() 会自动加载

return [
    // Token 名称（同时也是 Cookie 名称、提交参数名、Header 名称）
    'tokenName'             => 'satoken',
    // Token 前缀（如 'Bearer'，提交时格式为 Bearer xxx）
    'tokenPrefix'           => '',
    // Token 风格（uuid / simple-random / custom）
    'tokenStyle'            => 'uuid',
    // Token 有效期（秒），-1 代表永不过期
    'timeout'               => 86400,
    // Token 最低活动频率（秒），-1 代表不限制
    // 超过此时间没有活动则视为 Token 过期
    'activityTimeout'       => -1,
    // 是否允许同一账号多地同时登录（为 true 时允许，为 false 时新登录挤掉旧登录）
    'concurrent'            => true,
    // 在每次登录时是否产生新的 Token（为 false 时同端互斥登录会复用已有 Token）
    'isShare'               => true,
    // 同一账号最大登录数量，-1 代表不限制
    'maxLoginCount'         => 12,
    // 在每次创建 Token 时的最高循环次数（用于保证 Token 唯一性）
    'maxTryTimes'           => 12,

    // 是否从 Header 中读取 Token
    'isReadHeader'          => true,
    // 是否从 Cookie 中读取 Token
    'isReadCookie'          => true,
    // 是否从请求体里读取 Token
    'isReadBody'            => false,

    // 登录后是否将 Token 写入 Cookie
    'isWriteCookie'         => true,
    // 登录后是否将 Token 写入响应头
    'isWriteHeader'         => false,

    // Cookie 作用域
    'cookieDomain'          => '',
    // Cookie 路径
    'cookiePath'            => '/',
    // Cookie 是否仅 HTTPS 传输
    'cookieSecure'          => true,
    // Cookie 是否 HttpOnly
    'cookieHttpOnly'        => true,
    // Cookie SameSite 策略（Strict / Lax / None）
    'cookieSameSite'        => 'Strict',

    // 加密类型：intl（国际算法 AES/RSA/HMAC-SHA256） / sm（国密算法 SM2/SM3/SM4）
    'cryptoType'            => 'intl',
    // AES 密钥（16/24/32 字节对应 AES-128/192/256）
    'aesKey'                => '',
    // RSA 私钥（PEM 格式或文件路径）
    'rsaPrivateKey'         => '',
    // RSA 公钥（PEM 格式或文件路径）
    'rsaPublicKey'          => '',
    // HMAC 密钥
    'hmacKey'               => '',
    // 国密 SM2 私钥
    'sm2PrivateKey'         => '',
    // 国密 SM2 公钥
    'sm2PublicKey'          => '',
    // 国密 SM4 密钥（16 字节）
    'sm4Key'                => '',

    // JWT 密钥
    'jwtSecretKey'          => '',

    // 是否在登录后将 Token 信息写入 Session
    'tokenSessionCheckLogin'=> true,

    'sso'                   => [
        // SSO 登录地址
        'loginUrl'          => '',
        // SSO 认证中心 URL
        'authUrl'           => '',
        // SSO 回调地址
        'backUrl'           => '',
        // SSO ticket 校验地址
        'checkTicketUrl'    => '',
        // SSO 单点注销地址
        'sloUrl'            => '',
        // SSO 模式（same-domain / cross-domain / front-separate）
        'mode'              => 'same-domain',
        // SSO Client ID
        'clientId'          => '',
        // SSO Client Secret
        'clientSecret'      => '',
    ],

    'oauth2'                => [
        // 支持的授权模式
        'grantTypes'        => ['authorization_code'],
        // 授权码有效期（秒）
        'codeTimeout'       => 60,
        // Access Token 有效期（秒）
        'accessTokenTimeout'=> 7200,
        // Refresh Token 有效期（秒），-1 代表不刷新
        'refreshTokenTimeout' => -1,
        // 是否每次生成新的 Refresh Token
        'isNewRefreshToken' => false,
    ],
];
