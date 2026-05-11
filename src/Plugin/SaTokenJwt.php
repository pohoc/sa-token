<?php

declare(strict_types=1);

namespace SaToken\Plugin;

use CryptoSm\SM3\HmacSm3;
use SaToken\Exception\SaTokenException;

class SaTokenJwt
{
    protected string $secretKey = '';

    protected string $cryptoType = 'intl';

    public function __construct(array $config = [])
    {
        $this->secretKey = $config['jwtSecretKey'] ?? '';
        $this->cryptoType = $config['cryptoType'] ?? 'intl';
    }

    public function createToken(mixed $loginId, string $loginType, ?int $timeout = null, array $extraClaims = []): string
    {
        if ($this->secretKey === '') {
            throw new SaTokenException('JWT 密钥未配置');
        }

        $now = time();
        $header = [
            'typ' => 'JWT',
            'alg' => $this->cryptoType === 'sm' ? 'SM3' : 'HS256',
        ];

        $payload = [
            'iat'  => $now,
            'jti'  => bin2hex(random_bytes(16)),
            'sub'  => (string) $loginId,
            'type' => $loginType,
        ];

        if ($timeout !== null && $timeout > 0) {
            $payload['exp'] = $now + $timeout;
        }

        $payload = array_merge($payload, $extraClaims);

        $headerB64 = $this->base64UrlEncode(json_encode($header, JSON_UNESCAPED_UNICODE));
        $payloadB64 = $this->base64UrlEncode(json_encode($payload, JSON_UNESCAPED_UNICODE));
        $signingInput = $headerB64 . '.' . $payloadB64;

        if ($this->cryptoType === 'sm') {
            $signature = HmacSm3::hmac($this->secretKey, $signingInput);
        } else {
            if (strlen($this->secretKey) < 32) {
                throw new SaTokenException('JWT 密钥长度不足，HS256 至少需要 32 字节');
            }
            $signature = hash_hmac('sha256', $signingInput, $this->secretKey);
        }

        return $signingInput . '.' . $this->base64UrlEncode(hex2bin($signature));
    }

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

    public function parseToken(string $token): array
    {
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

        $alg = $header['alg'] ?? 'HS256';
        $signingInput = $headerB64 . '.' . $payloadB64;
        $signatureBin = $this->base64UrlDecode($signatureB64);
        $signature = bin2hex($signatureBin);

        if ($alg === 'SM3') {
            $expected = HmacSm3::hmac($this->secretKey, $signingInput);
        } else {
            if (strlen($this->secretKey) < 32) {
                throw new SaTokenException('JWT 密钥长度不足，HS256 至少需要 32 字节');
            }
            $expected = hash_hmac('sha256', $signingInput, $this->secretKey);
        }

        if (!hash_equals($expected, $signature)) {
            throw new SaTokenException('JWT Token 签名无效');
        }

        $payload = json_decode($this->base64UrlDecode($payloadB64), true);
        if (!is_array($payload)) {
            throw new SaTokenException('JWT Token Payload 无效');
        }

        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new SaTokenException('JWT Token 已过期');
        }

        return $payload;
    }

    public function getLoginId(string $token): ?string
    {
        try {
            $payload = $this->parseToken($token);
            return $payload['sub'] ?? null;
        } catch (SaTokenException) {
            return null;
        }
    }

    public function getLoginType(string $token): string
    {
        try {
            $payload = $this->parseToken($token);
            return $payload['type'] ?? '';
        } catch (SaTokenException) {
            return '';
        }
    }

    public function getExtraClaims(string $token): array
    {
        $payload = $this->parseToken($token);
        $standardKeys = ['iat', 'jti', 'sub', 'type', 'exp'];
        return array_diff_key($payload, array_flip($standardKeys));
    }

    public function createStatelessToken(mixed $loginId, string $loginType, ?int $timeout = null, array $extraClaims = []): string
    {
        $sessionData = [];
        $sessionId = \SaToken\TokenManager::SESSION_PREFIX . $loginType . ':' . $loginId;
        $session = \SaToken\SaSession::getBySessionId($sessionId);
        if ($session !== null) {
            $sessionData = $session->getDataMap();
        }

        $statelessClaims = array_merge($extraClaims, $sessionData);

        return $this->createToken($loginId, $loginType, $timeout, $statelessClaims);
    }

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
        $remainder = strlen($data) % 4;
        if ($remainder !== 0) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'), true);
    }
}
