<?php

declare(strict_types=1);

namespace SaToken\Plugin;

use CryptoSm\SM3\HmacSm3;
use SaToken\Exception\SaTokenException;
use SaToken\TokenManager;
use SaToken\Util\SaTokenCryptoType;
use SaToken\Util\SaTokenTimeout;

class SaTokenJwt
{
    /** Bound JWT parsing and claim payloads at all authentication entry points. */
    private const MAX_TOKEN_BYTES = 65536;

    protected string $secretKey = '';

    protected string $cryptoType = 'intl';

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [])
    {
        $secretKey = $config['jwtSecretKey'] ?? '';
        $this->secretKey = is_string($secretKey) ? $secretKey : '';
        $cryptoType = $config['cryptoType'] ?? 'intl';
        if (!is_string($cryptoType)) {
            throw new SaTokenException('JWT 加密类型必须为 intl 或 sm');
        }
        $this->cryptoType = SaTokenCryptoType::validate($cryptoType);
    }

    /**
     * @param array<string, mixed> $extraClaims
     */
    public function createToken(
        mixed $loginId,
        string $loginType,
        ?int $timeout = null,
        array $extraClaims = [],
        ?int $statelessGeneration = null
    ): string {
        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }

        if ($timeout !== null) {
            SaTokenTimeout::validate($timeout, 'JWT');
        }

        if ($this->secretKey === '') {
            throw new SaTokenException('JWT 密钥未配置');
        }
        if (strlen($this->secretKey) < 32) {
            throw new SaTokenException('JWT 密钥长度不足，至少需要 32 字节');
        }

        $now = time();
        // Fractional NumericDate lets account-wide revocation distinguish a
        // token issued immediately after logout from an older token minted in
        // the same wall-clock second.
        $issuedAt = microtime(true);
        $header = [
            'typ' => 'JWT',
            'alg' => $this->cryptoType === 'sm' ? 'SM3' : 'HS256',
        ];

        $payload = [
            'iat'  => $issuedAt,
            'jti'  => bin2hex(random_bytes(16)),
            'sub'  => (string) $loginId,
            'type' => $loginType,
        ];

        if ($timeout !== null && $timeout > 0) {
            $payload['exp'] = $now + $timeout;
        }

        // 身份与有效期声明只能由签发器生成；调用方扩展数据不得改变主体、
        // 登录类型、有效期或令牌唯一标识，避免 session/业务数据覆盖安全声明。
        $reservedClaims = ['sub', 'type', 'exp', 'iat', 'jti', 'nbf', 'iss', 'aud', 'satoken_gen'];
        $safeExtraClaims = array_diff_key($extraClaims, array_flip($reservedClaims));
        $payload = array_merge($payload, $safeExtraClaims);
        if ($statelessGeneration !== null) {
            if ($statelessGeneration < 0) {
                throw new SaTokenException('无状态 JWT 账号会话版本无效');
            }
            $payload['satoken_gen'] = $statelessGeneration;
        }

        try {
            $headerJson = json_encode($header, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $payloadJson = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new SaTokenException('JWT Header 或 Payload 无法编码为 JSON', 0, $exception);
        }

        $headerB64 = $this->base64UrlEncode($headerJson);
        $payloadB64 = $this->base64UrlEncode($payloadJson);
        $signingInput = $headerB64 . '.' . $payloadB64;

        if ($this->cryptoType === 'sm') {
            $signature = HmacSm3::hmac($this->secretKey, $signingInput);
        } else {
            $signature = hash_hmac('sha256', $signingInput, $this->secretKey);
        }

        $signatureBin = hex2bin($signature);
        if ($signatureBin === false) {
            throw new SaTokenException('JWT 签名失败');
        }

        $token = $signingInput . '.' . $this->base64UrlEncode($signatureBin);
        if (strlen($token) > self::MAX_TOKEN_BYTES) {
            throw new SaTokenException('JWT Token 超过最大允许长度');
        }

        return $token;
    }

    /**
     * @param array<string, mixed> $extraClaims
     */
    public function createMixedToken(mixed $loginId, string $loginType, ?int $timeout = null, array $extraClaims = []): string
    {
        if ($this->secretKey === '') {
            throw new SaTokenException('JWT 密钥未配置');
        }

        $jti = bin2hex(random_bytes(16));

        $mixedClaims = array_merge($extraClaims, [
            'jti' => $jti,
        ]);

        return $this->createToken($loginId, $loginType, $timeout, $mixedClaims);
    }

    /**
     * @param  bool                 $allowExpired Allow expiry checks to be deferred while retaining signature and claim validation.
     * @return array<string, mixed>
     */
    public function parseToken(string $token, bool $allowExpired = false): array
    {
        if ($token === '' || strlen($token) > self::MAX_TOKEN_BYTES) {
            throw new SaTokenException('JWT Token 长度无效');
        }

        if ($this->secretKey === '') {
            throw new SaTokenException('JWT 密钥未配置');
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new SaTokenException('JWT Token 格式无效');
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $header = json_decode($this->base64UrlDecode($headerB64), true);
        if (!is_array($header)) {
            throw new SaTokenException('JWT Token Header 无效');
        }

        if (!array_key_exists('alg', $header) || !is_string($header['alg'])) {
            throw new SaTokenException('JWT Header alg 字段必须为字符串');
        }
        $alg = $header['alg'];
        $expectedAlg = $this->cryptoType === 'sm' ? 'SM3' : 'HS256';
        if ($alg !== $expectedAlg) {
            throw new SaTokenException('JWT 算法与当前 cryptoType 配置不匹配');
        }
        if (strlen($this->secretKey) < 32) {
            throw new SaTokenException('JWT 密钥长度不足，至少需要 32 字节');
        }

        $signingInput = $headerB64 . '.' . $payloadB64;
        $signatureBin = $this->base64UrlDecode($signatureB64);
        $signature = bin2hex($signatureBin);

        if ($alg === 'SM3') {
            $expected = HmacSm3::hmac($this->secretKey, $signingInput);
        } else {
            $expected = hash_hmac('sha256', $signingInput, $this->secretKey);
        }

        if (!hash_equals($expected, $signature)) {
            throw new SaTokenException('JWT Token 签名无效');
        }

        $payload = json_decode($this->base64UrlDecode($payloadB64), true);
        if (!is_array($payload)) {
            throw new SaTokenException('JWT Token Payload 无效');
        }

        if (array_key_exists('exp', $payload)) {
            $expiresAt = $payload['exp'];
            if ((!is_int($expiresAt) && !is_float($expiresAt)) || !is_finite((float) $expiresAt)) {
                throw new SaTokenException('JWT Token exp 字段无效');
            }
            if (!$allowExpired && $expiresAt <= time()) {
                throw new SaTokenException('JWT Token 已过期');
            }
        }

        if (array_key_exists('nbf', $payload)) {
            $notBefore = $payload['nbf'];
            if ((!is_int($notBefore) && !is_float($notBefore)) || !is_finite((float) $notBefore)) {
                throw new SaTokenException('JWT Token nbf 字段无效');
            }
            if ($notBefore > time()) {
                throw new SaTokenException('JWT Token 尚未生效');
            }
        }

        /** @var array<string, mixed> $payload */
        return $payload;
    }

    public function getLoginId(string $token): ?string
    {
        try {
            $payload = $this->parseToken($token);
            $sub = $payload['sub'] ?? null;
            return is_string($sub) ? $sub : null;
        } catch (SaTokenException) {
            return null;
        }
    }

    public function getLoginType(string $token): string
    {
        try {
            $payload = $this->parseToken($token);
            $type = $payload['type'] ?? '';
            return is_string($type) ? $type : '';
        } catch (SaTokenException) {
            return '';
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function getExtraClaims(string $token): array
    {
        $payload = $this->parseToken($token);
        $standardKeys = ['iat', 'jti', 'sub', 'type', 'exp', 'satoken_gen'];
        return array_diff_key($payload, array_flip($standardKeys));
    }

    /**
     * @param array<string, mixed> $extraClaims
     */
    public function createStatelessToken(mixed $loginId, string $loginType, ?int $timeout = null, array $extraClaims = []): string
    {
        $sessionData = [];
        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
        $sessionId = \SaToken\TokenManager::buildSessionId($loginType, $loginIdStr);
        $session = \SaToken\SaSession::getBySessionId($sessionId);
        if ($session !== null) {
            $sessionData = $session->getDataMap();
        }

        // 剥离 session 数据中的保留 claims（sub/exp/iat/type/jti 等）：
        // 保留字段是身份与有效性的权威来源，一旦可被 session 数据覆盖，
        // 任何能写 session 顶层键的输入都能伪造登录身份或延长有效期。
        // 额外参数同样不允许碰保留字段
        $reservedKeys = ['sub', 'exp', 'iat', 'nbf', 'jti', 'iss', 'aud', 'type', 'satoken_gen'];
        $safeSessionData = array_diff_key($sessionData, array_flip($reservedKeys));
        $safeExtraClaims = array_diff_key($extraClaims, array_flip($reservedKeys));

        $statelessClaims = array_merge($safeSessionData, $safeExtraClaims);
        $generation = (new TokenManager())->getStatelessTokenGeneration($loginIdStr, $loginType);

        return $this->createToken($loginId, $loginType, $timeout, $statelessClaims, $generation);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function validateStatelessToken(string $token): ?array
    {
        try {
            $payload = $this->parseToken($token);
            return $payload;
        } catch (SaTokenException) {
            return null;
        }
    }

    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function base64UrlDecode(string $data): string
    {
        // JWT compact serialization uses the unpadded, canonical Base64URL
        // alphabet. Non-canonical final pad bits can decode to the same
        // signature bytes while changing the token string, bypassing
        // string-keyed revocation lists.
        if (preg_match('/^[A-Za-z0-9_-]*$/D', $data) !== 1) {
            return '';
        }

        $remainder = strlen($data) % 4;
        if ($remainder !== 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false || $this->base64UrlEncode($decoded) !== rtrim($data, '=')) {
            return '';
        }

        return $decoded;
    }
}
