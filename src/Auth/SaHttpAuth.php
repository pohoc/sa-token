<?php

declare(strict_types=1);

namespace SaToken\Auth;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Security\SaAntiBruteUtil;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaHttpAuth
{
    protected const DIGEST_NONCE_TTL = 300;

    protected const DIGEST_NONCE_SECRET_KEY = 'satoken:auth:digest:nonce-secret';

    /** @var callable(string, string): mixed|null */
    protected $basicValidator = null;

    /** @var callable(string): mixed|null */
    protected $digestValidator = null;

    public function checkBasic(string $realm = 'Sa-Token'): void
    {
        $this->denyAuthenticationFallback();

        if (SaTokenContext::hasMultipleHeaderValues('Authorization')) {
            $this->sendChallenge($realm);
            throw new SaTokenException('Basic Authorization Header 存在多个值');
        }

        $authHeader = SaTokenContext::getHeader('Authorization');

        if ($authHeader === null || preg_match('/^basic\s+/i', $authHeader) !== 1) {
            $this->sendChallenge($realm);
            throw new SaTokenException('未提供有效的 Basic 认证信息');
        }

        $encoded = trim(substr($authHeader, 6));
        $decoded = base64_decode($encoded, true);
        if ($decoded === false) {
            $this->sendChallenge($realm);
            throw new SaTokenException('Basic 认证信息解码失败');
        }

        $parts = explode(':', $decoded, 2);
        if (count($parts) !== 2) {
            $this->sendChallenge($realm);
            throw new SaTokenException('Basic 认证信息格式无效');
        }

        [$username, $password] = $parts;

        if ($this->basicValidator === null) {
            throw new SaTokenException('未设置 Basic 认证校验器');
        }

        SaAntiBruteUtil::checkAndThrow($username);

        try {
            $loginId = ($this->basicValidator)($username, $password);
        } catch (\Throwable $exception) {
            SaAntiBruteUtil::recordFailure($username);
            throw $exception;
        }

        if ($loginId === null || is_bool($loginId) || !is_scalar($loginId) || $loginId === '') {
            SaAntiBruteUtil::recordFailure($username);
            $this->sendChallenge($realm);
            throw new SaTokenException('Basic 认证失败');
        }

        SaAntiBruteUtil::clearCurrentSourceFailures($username);
        $result = StpUtil::login($loginId);
        SaTokenContext::setTokenOverride(StpUtil::getStpLogic()->getLoginType(), $result->getAccessToken());
    }

    public function checkDigest(string $realm = 'Sa-Token'): void
    {
        $this->denyAuthenticationFallback();

        if (SaTokenContext::hasMultipleHeaderValues('Authorization')) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest Authorization Header 存在多个值');
        }

        $authHeader = SaTokenContext::getHeader('Authorization');

        if ($authHeader === null || preg_match('/^digest\s+/i', $authHeader) !== 1) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('未提供有效的 Digest 认证信息');
        }

        $params = $this->parseDigestHeader($authHeader);

        $username = $params['username'] ?? null;
        $nonce = $params['nonce'] ?? null;
        $nc = $params['nc'] ?? null;
        $cnonce = $params['cnonce'] ?? null;
        $qop = $params['qop'] ?? null;
        $uri = $params['uri'] ?? null;
        $response = $params['response'] ?? null;

        if ($username === null || $nonce === null || $uri === null || $response === null
            || ($params['realm'] ?? null) !== $realm
            || $qop !== 'auth'
            || !is_string($nc) || preg_match('/^[0-9a-fA-F]{8}$/D', $nc) !== 1
            || !is_string($cnonce) || $cnonce === '') {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest 认证信息不完整或与服务端挑战不匹配');
        }

        // nonce 必须是服务端签发的（RFC 2617 允许 nonce 未过期期间复用，
        // 因此先校验有效性、凭证校验通过后再原子消费）：
        // 无 nonce 状态机的 Digest 等于可无限重放的永久凭据
        if (!$this->isDigestNonceIssued($nonce)) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest nonce 无效或已使用，可能遭受重放攻击');
        }

        if ($this->digestValidator === null) {
            throw new SaTokenException('未设置 Digest 认证校验器');
        }

        $request = SaTokenContext::getRequest();
        if (!is_object($request) || !method_exists($request, 'getMethod')) {
            throw new SaTokenException('无法读取当前 HTTP 请求方法，拒绝 Digest 认证');
        }
        $requestMethod = $request->getMethod();
        if (!is_string($requestMethod) || $requestMethod === '') {
            throw new SaTokenException('当前 HTTP 请求方法无效，拒绝 Digest 认证');
        }
        $requestTarget = $this->getDigestRequestTarget($request);
        if ($requestTarget === null || !hash_equals($requestTarget, $uri)) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest URI 与当前请求目标不匹配');
        }
        $method = strtoupper($requestMethod);

        SaAntiBruteUtil::checkAndThrow($username);

        try {
            $ha1 = ($this->digestValidator)($username);
        } catch (\Throwable $exception) {
            SaAntiBruteUtil::recordFailure($username);
            throw $exception;
        }

        // Digest HA1 is an MD5 hex digest in this implementation. Empty or
        // malformed validator sentinels must fail closed; otherwise an empty
        // HA1 lets callers forge a valid response for an unknown user.
        if (!is_string($ha1) || preg_match('/^[0-9a-fA-F]{32}$/D', $ha1) !== 1) {
            SaAntiBruteUtil::recordFailure($username);
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest 认证失败');
        }

        $ha2 = md5($method . ':' . $uri);

        $expected = md5($ha1 . ':' . $nonce . ':' . $nc . ':' . $cnonce . ':auth:' . $ha2);

        if (!hash_equals($expected, $response)) {
            SaAntiBruteUtil::recordFailure($username);
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest 认证失败');
        }

        // 凭证校验通过后原子消费 nonce：同一 nonce 的并发/后续重放在此被拒绝；
        // 校验失败不烧 nonce（RFC 允许客户端重试）
        if (!$this->consumeDigestNonce($nonce)) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest nonce 已使用，可能遭受重放攻击');
        }

        SaAntiBruteUtil::clearCurrentSourceFailures($username);
        $result = StpUtil::login($username);
        SaTokenContext::setTokenOverride(StpUtil::getStpLogic()->getLoginType(), $result->getAccessToken());
    }

    /** 获取实际请求目标，避免把为其他资源签发的 Digest 响应移用到当前路径。 */
    protected function getDigestRequestTarget(object $request): ?string
    {
        if (method_exists($request, 'getRequestTarget')) {
            $target = $request->getRequestTarget();
            return is_string($target) && $target !== '' ? $target : null;
        }

        // Symfony HttpFoundation 等常见适配器使用 getRequestUri()。
        if (method_exists($request, 'getRequestUri')) {
            $target = $request->getRequestUri();
            return is_string($target) && $target !== '' ? $target : null;
        }

        return null;
    }

    public function setBasicValidator(callable $validator): static
    {
        $this->basicValidator = $validator;
        return $this;
    }

    public function setDigestValidator(callable $validator): static
    {
        $this->digestValidator = $validator;
        return $this;
    }

    protected function denyAuthenticationFallback(): void
    {
        SaTokenContext::denyTokenFallback();
    }

    public function sendChallenge(string $realm): void
    {
        SaTokenContext::setHeader('WWW-Authenticate', 'Basic realm="' . $this->formatChallengeRealm($realm) . '"');
    }

    public function sendDigestChallenge(string $realm): void
    {
        $formattedRealm = $this->formatChallengeRealm($realm);
        $nonce = $this->generateNonce();
        $challenge = sprintf(
            'Digest realm="%s", nonce="%s", qop="auth"',
            $formattedRealm,
            $nonce
        );
        SaTokenContext::setHeader('WWW-Authenticate', $challenge);
    }

    protected function formatChallengeRealm(string $realm): string
    {
        if (preg_match('/[\x00-\x1F\x7F]/', $realm) === 1) {
            throw new SaTokenException('认证 realm 不能包含控制字符');
        }

        return str_replace(['\\', '"'], ['\\\\', '\\"'], $realm);
    }

    public function generateNonce(): string
    {
        $issuedAt = time();
        $nonceId = bin2hex(random_bytes(16));
        $payload = $issuedAt . ':' . $nonceId;
        $signature = hash_hmac('sha256', $payload, $this->getDigestNonceSecret());

        return $payload . ':' . $signature;
    }

    protected function getDigestNonceSecret(): string
    {
        $dao = SaToken::getDao();
        $secret = $dao->get(self::DIGEST_NONCE_SECRET_KEY);
        if ($secret !== null) {
            if (preg_match('/^[0-9a-f]{64}$/D', $secret) !== 1) {
                throw new SaTokenException('Digest nonce 密钥存储数据无效');
            }
            return hex2bin($secret) ?: throw new SaTokenException('Digest nonce 密钥存储数据无效');
        }

        $candidate = bin2hex(random_bytes(32));
        if (!$dao->setIfNotExists(self::DIGEST_NONCE_SECRET_KEY, $candidate, null)) {
            $secret = $dao->get(self::DIGEST_NONCE_SECRET_KEY);
            if ($secret === null || preg_match('/^[0-9a-f]{64}$/D', $secret) !== 1) {
                throw new SaTokenException('Digest nonce 密钥初始化失败');
            }
            $candidate = $secret;
        }

        return hex2bin($candidate) ?: throw new SaTokenException('Digest nonce 密钥初始化失败');
    }

    /** @return array{issuedAt: int, nonceId: string}|null */
    protected function parseIssuedDigestNonce(string $nonce): ?array
    {
        $parts = explode(':', $nonce);
        if (count($parts) !== 3
            || preg_match('/^[0-9]{10}$/D', $parts[0]) !== 1
            || preg_match('/^[0-9a-f]{32}$/D', $parts[1]) !== 1
            || preg_match('/^[0-9a-f]{64}$/D', $parts[2]) !== 1) {
            return null;
        }

        $issuedAt = (int) $parts[0];
        if ($issuedAt > time() || time() - $issuedAt > self::DIGEST_NONCE_TTL) {
            return null;
        }

        $payload = $parts[0] . ':' . $parts[1];
        $expected = hash_hmac('sha256', $payload, $this->getDigestNonceSecret());
        if (!hash_equals($expected, $parts[2])) {
            return null;
        }

        return ['issuedAt' => $issuedAt, 'nonceId' => $parts[1]];
    }

    protected function isDigestNonceIssued(string $nonce): bool
    {
        $parsed = $this->parseIssuedDigestNonce($nonce);
        if ($parsed === null) {
            return false;
        }

        return SaToken::getDao()->get('satoken:auth:digest:nonce:used:' . $parsed['nonceId']) === null;
    }

    /**
     * 原子消费服务端签发的 nonce：读取并立即删除，
     * 并发重放同一 nonce 时仅第一个请求成功
     */
    protected function consumeDigestNonce(string $nonce): bool
    {
        $parsed = $this->parseIssuedDigestNonce($nonce);
        if ($parsed === null) {
            return false;
        }

        $ttl = max(1, self::DIGEST_NONCE_TTL - (time() - $parsed['issuedAt']) + 1);
        return SaToken::getDao()->setIfNotExists(
            'satoken:auth:digest:nonce:used:' . $parsed['nonceId'],
            '1',
            $ttl
        );
    }

    /**
     * @return array<string, string>
     */
    public function parseDigestHeader(string $header): array
    {
        $headerPart = substr($header, 7) ?: '';
        if ($headerPart === '') {
            return [];
        }

        $result = [];
        $offset = 0;
        $length = strlen($headerPart);
        preg_match_all('/(\w+)\s*=\s*(?:"((?:\\\\.|[^"\\\\])*)"|([^,\s]+))/', $headerPart, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);

        foreach ($matches as $match) {
            $fieldOffset = $match[0][1];
            $separator = substr($headerPart, $offset, $fieldOffset - $offset);
            if (($offset === 0 && trim($separator) !== '')
                || ($offset > 0 && preg_match('/^\s*,\s*$/D', $separator) !== 1)) {
                return [];
            }

            $key = strtolower($match[1][0]);
            if (array_key_exists($key, $result)) {
                return [];
            }
            if (($match[2][1] ?? -1) >= 0) {
                $value = preg_replace_callback(
                    '/\\\\(.)/s',
                    static fn (array $escape): string => $escape[1],
                    $match[2][0]
                );
                if (!is_string($value)) {
                    return [];
                }
            } else {
                $value = $match[3][0] ?? '';
            }
            $result[$key] = $value;
            $offset = $fieldOffset + strlen($match[0][0]);
        }

        $trailing = substr($headerPart, $offset, $length - $offset);
        if ($matches === [] || trim($trailing) !== '') {
            return [];
        }
        return $result;
    }
}
