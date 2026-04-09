<?php

declare(strict_types=1);

namespace SaToken\Plugin;

use SaToken\Exception\SaTokenException;

/**
 * JWT 插件
 *
 * 基于 firebase/php-jwt 提供 JWT Token 生成和校验
 *
 * 使用示例：
 *   $jwt = new SaTokenJwt(['jwtSecretKey' => 'my-secret']);
 *   $token = $jwt->createToken(10001, 'login');
 *   $payload = $jwt->parseToken($token);
 */
class SaTokenJwt
{
    /**
     * JWT 密钥
     */
    protected string $secretKey = '';

    /**
     * @param array $config 配置数组（jwtSecretKey）
     */
    public function __construct(array $config = [])
    {
        $this->secretKey = $config['jwtSecretKey'] ?? '';
    }

    /**
     * 创建 JWT Token
     *
     * @param  mixed            $loginId   登录 ID
     * @param  string           $loginType 登录类型
     * @param  int|null         $timeout   超时时间（秒）
     * @return string           JWT Token
     * @throws SaTokenException
     */
    public function createToken(mixed $loginId, string $loginType, ?int $timeout = null): string
    {
        if ($this->secretKey === '') {
            throw new SaTokenException('JWT 密钥未配置');
        }

        if (strlen($this->secretKey) < 32) {
            throw new SaTokenException('JWT 密钥长度不足，HS256 至少需要 32 字节');
        }

        $now = time();
        $payload = [
            'iat'  => $now,
            'jti'  => bin2hex(random_bytes(16)),
            'sub'  => (string) $loginId,
            'type' => $loginType,
        ];

        if ($timeout !== null && $timeout > 0) {
            $payload['exp'] = $now + $timeout;
        }

        try {
            return \Firebase\JWT\JWT::encode($payload, $this->secretKey, 'HS256');
        } catch (\Throwable $e) {
            throw new SaTokenException('JWT Token 创建失败：' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 解析 JWT Token
     *
     * @param  string           $token JWT Token
     * @return array            解析后的载荷数据
     * @throws SaTokenException
     */
    public function parseToken(string $token): array
    {
        if ($this->secretKey === '') {
            throw new SaTokenException('JWT 密钥未配置');
        }

        if (strlen($this->secretKey) < 32) {
            throw new SaTokenException('JWT 密钥长度不足，HS256 至少需要 32 字节');
        }

        try {
            $decoded = \Firebase\JWT\JWT::decode($token, new \Firebase\JWT\Key($this->secretKey, 'HS256'));
            return (array) $decoded;
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new SaTokenException('JWT Token 已过期', 0, $e);
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw new SaTokenException('JWT Token 签名无效', 0, $e);
        } catch (\Throwable $e) {
            throw new SaTokenException('JWT Token 解析失败：' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 获取登录 ID
     *
     * @param  string      $token JWT Token
     * @return string|null
     */
    public function getLoginId(string $token): ?string
    {
        try {
            $payload = $this->parseToken($token);
            return $payload['sub'] ?? null;
        } catch (SaTokenException) {
            return null;
        }
    }

    /**
     * 获取登录类型
     *
     * @param  string $token JWT Token
     * @return string
     */
    public function getLoginType(string $token): string
    {
        try {
            $payload = $this->parseToken($token);
            return $payload['type'] ?? '';
        } catch (SaTokenException) {
            return '';
        }
    }

}
