<?php

declare(strict_types=1);

namespace SaToken\Auth;

use SaToken\Exception\SaTokenException;
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

        if ($authHeader === null || !str_starts_with($authHeader, 'Basic ')) {
            $this->sendChallenge($realm);
            throw new SaTokenException('未提供有效的 Basic 认证信息');
        }

        $encoded = substr($authHeader, 6);
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

        if ($authHeader === null || !str_starts_with($authHeader, 'Digest ')) {
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
    }

    public function generateNonce(): string
    {
        return md5(uniqid((string) mt_rand(), true) . ':' . time());
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
