<?php

declare(strict_types=1);

namespace SaToken\Rpc;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

class SaRpcContext
{
    protected static string $tokenHeaderName = 'X-Sa-Token';
    protected static string $loginIdHeaderName = 'X-Sa-Login-Id';
    protected static string $loginTypeHeaderName = 'X-Sa-Login-Type';

    public static function setTokenHeaderName(string $name): void
    {
        if (preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/D', $name) !== 1
            || strcasecmp($name, self::$loginIdHeaderName) === 0
            || strcasecmp($name, self::$loginTypeHeaderName) === 0) {
            throw new SaTokenException('RPC Token Header 名称无效或与保留身份头冲突');
        }

        self::$tokenHeaderName = $name;
    }

    public static function getTokenHeaderName(): string
    {
        return self::$tokenHeaderName;
    }

    /**
     * @param  array<string, string> $headers
     * @return array<string, string>
     */
    public static function attachToHeaders(array $headers = []): array
    {
        $headers = self::removeForwardedAuthHeaders($headers);
        $tokenValue = StpUtil::getTokenValue();
        if ($tokenValue !== null) {
            $headers[self::$tokenHeaderName] = $tokenValue;
        }
        $loginId = StpUtil::getLoginId();
        if ($loginId !== null) {
            $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
            $headers[self::$loginIdHeaderName] = $loginIdStr;
        }
        $headers[self::$loginTypeHeaderName] = StpUtil::TYPE;
        return $headers;
    }

    public static function attachToRequest(\Psr\Http\Message\RequestInterface $request): \Psr\Http\Message\RequestInterface
    {
        foreach (self::getForwardedAuthHeaderNames() as $headerName) {
            $request = $request->withoutHeader($headerName);
        }

        $tokenValue = StpUtil::getTokenValue();
        if ($tokenValue !== null) {
            $request = $request->withHeader(self::$tokenHeaderName, $tokenValue);
        }
        $loginId = StpUtil::getLoginId();
        if ($loginId !== null) {
            $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');
            $request = $request->withHeader(self::$loginIdHeaderName, $loginIdStr);
        }
        $request = $request->withHeader(self::$loginTypeHeaderName, StpUtil::TYPE);
        return $request;
    }

    /** @param array<string, string> $headers
     * @return array<string, string>
     */
    protected static function removeForwardedAuthHeaders(array $headers): array
    {
        $authHeaderNames = self::getForwardedAuthHeaderNames();
        foreach (array_keys($headers) as $headerName) {
            if (!is_string($headerName)) {
                continue;
            }
            foreach ($authHeaderNames as $authHeaderName) {
                if (strcasecmp($headerName, $authHeaderName) === 0) {
                    unset($headers[$headerName]);
                    break;
                }
            }
        }

        return $headers;
    }

    /** @return list<string> */
    protected static function getForwardedAuthHeaderNames(): array
    {
        return [self::$tokenHeaderName, self::$loginIdHeaderName, self::$loginTypeHeaderName];
    }

    public static function extractAndValidate(?string $expectedLoginType = null): void
    {
        foreach ([self::$tokenHeaderName, self::$loginIdHeaderName, self::$loginTypeHeaderName] as $headerName) {
            if (SaTokenContext::hasMultipleHeaderValues(
                $headerName,
                $headerName === self::$tokenHeaderName
            )) {
                throw new SaTokenException('RPC 认证 Header 存在多个值');
            }
        }

        $tokenValue = SaTokenContext::getHeader(self::$tokenHeaderName);
        if ($tokenValue === null) {
            throw new SaTokenException('RPC 请求缺少 Token 信息');
        }

        $forwardedLoginType = SaTokenContext::getHeader(self::$loginTypeHeaderName);
        if ($expectedLoginType !== null && $forwardedLoginType !== null && $forwardedLoginType !== $expectedLoginType) {
            throw new SaTokenException('RPC LoginType 与拦截器配置不匹配');
        }
        if ($expectedLoginType === null && $forwardedLoginType !== null
            && !SaToken::hasStpLogic($forwardedLoginType)) {
            // A login type from the network must not allocate a new StpLogic
            // before token validation. Otherwise arbitrary invalid RPC calls
            // can grow the long-lived process registry without bound.
            throw new SaTokenException('RPC LoginType 未注册');
        }
        $loginType = $expectedLoginType ?? $forwardedLoginType ?? 'login';
        $stpLogic = SaToken::getStpLogic($loginType);

        $loginId = $stpLogic->getLoginIdByToken($tokenValue);
        if ($loginId === null) {
            throw new SaTokenException('RPC Token 无效');
        }

        $forwardedLoginId = SaTokenContext::getHeader(self::$loginIdHeaderName);
        if ($forwardedLoginId !== null && (string) $loginId !== $forwardedLoginId) {
            throw new SaTokenException('RPC Token 与 LoginId 不匹配');
        }
    }

    public static function getForwardedLoginId(): ?string
    {
        if (SaTokenContext::hasMultipleHeaderValues(self::$loginIdHeaderName)) {
            return null;
        }
        return SaTokenContext::getHeader(self::$loginIdHeaderName);
    }

    public static function getForwardedToken(): ?string
    {
        if (SaTokenContext::hasMultipleHeaderValues(self::$tokenHeaderName, true)) {
            return null;
        }
        return SaTokenContext::getHeader(self::$tokenHeaderName);
    }

    public static function getForwardedLoginType(): ?string
    {
        if (SaTokenContext::hasMultipleHeaderValues(self::$loginTypeHeaderName)) {
            return null;
        }
        return SaTokenContext::getHeader(self::$loginTypeHeaderName);
    }

    public static function isRpcRequest(): bool
    {
        if (SaTokenContext::hasMultipleHeaderValues(self::$tokenHeaderName, true)) {
            return false;
        }
        return SaTokenContext::getHeader(self::$tokenHeaderName) !== null;
    }

    public static function reset(): void
    {
        self::$tokenHeaderName = 'X-Sa-Token';
        self::$loginIdHeaderName = 'X-Sa-Login-Id';
        self::$loginTypeHeaderName = 'X-Sa-Login-Type';
    }
}
