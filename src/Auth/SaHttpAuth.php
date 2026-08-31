<?php

declare(strict_types=1);

namespace SaToken\Auth;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaHttpAuth
{
    /** @var callable(string, string): mixed|null */
    protected $basicValidator = null;

    /** @var callable(string): mixed|null */
    protected $digestValidator = null;

    public function checkBasic(string $realm = 'Sa-Token'): void
    {
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

        $loginId = ($this->basicValidator)($username, $password);

        if ($loginId === null) {
            $this->sendChallenge($realm);
            throw new SaTokenException('Basic 认证失败');
        }

        StpUtil::login($loginId);
    }

    public function checkDigest(string $realm = 'Sa-Token'): void
    {
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

        if ($username === null || $nonce === null || $uri === null || $response === null) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest 认证信息不完整');
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

        $ha1 = ($this->digestValidator)($username);

        if ($ha1 === null) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest 认证失败');
        }

        $request = SaTokenContext::getRequest();
        $method = 'GET';
        if (is_object($request) && method_exists($request, 'getMethod')) {
            $m = $request->getMethod();
            $method = is_string($m) ? strtoupper($m) : 'GET';
        }

        $ha2 = md5($method . ':' . $uri);

        $ha1Str = is_string($ha1) ? $ha1 : (is_scalar($ha1) ? (string) $ha1 : '');

        if ($qop !== null && ($qop === 'auth' || $qop === 'auth-int')) {
            $expected = md5($ha1Str . ':' . $nonce . ':' . $nc . ':' . $cnonce . ':' . $qop . ':' . $ha2);
        } else {
            $expected = md5($ha1Str . ':' . $nonce . ':' . $ha2);
        }

        if (!hash_equals($expected, $response)) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest 认证失败');
        }

        // 凭证校验通过后原子消费 nonce：同一 nonce 的并发/后续重放在此被拒绝；
        // 校验失败不烧 nonce（RFC 允许客户端重试）
        if (!$this->consumeDigestNonce($nonce)) {
            $this->sendDigestChallenge($realm);
            throw new SaTokenException('Digest nonce 已使用，可能遭受重放攻击');
        }

        StpUtil::login($username);
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

    public function sendChallenge(string $realm): void
    {
        SaTokenContext::setHeader('WWW-Authenticate', 'Basic realm="' . $realm . '"');
    }

    public function sendDigestChallenge(string $realm): void
    {
        $nonce = $this->generateNonce();
        $challenge = sprintf(
            'Digest realm="%s", nonce="%s", qop="auth"',
            $realm,
            $nonce
        );
        SaTokenContext::setHeader('WWW-Authenticate', $challenge);
        $this->issueDigestNonce($nonce);
    }

    public function generateNonce(): string
    {
        return bin2hex(random_bytes(16));
    }

    protected function digestNonceKey(string $nonce): string
    {
        return 'satoken:auth:digest:nonce:' . hash('sha256', $nonce);
    }

    protected function issueDigestNonce(string $nonce): void
    {
        SaToken::getDao()->set($this->digestNonceKey($nonce), '1', 300);
    }

    protected function isDigestNonceIssued(string $nonce): bool
    {
        return SaToken::getDao()->get($this->digestNonceKey($nonce)) !== null;
    }

    /**
     * 原子消费服务端签发的 nonce：读取并立即删除，
     * 并发重放同一 nonce 时仅第一个请求成功
     */
    protected function consumeDigestNonce(string $nonce): bool
    {
        return SaToken::getDao()->getAndDelete($this->digestNonceKey($nonce)) !== null;
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

        preg_match_all('/(\w+)=(?:"([^"]*)"|([\w=\/+]+))/', $headerPart, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $key = $match[1];
            $value = ($match[2] ?? '') !== '' ? $match[2] : ($match[3] ?? '');
            $result[$key] = $value;
        }

        return $result;
    }
}
