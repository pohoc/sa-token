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

    public static function extractAndValidate(): void
    {
        $tokenValue = SaTokenContext::getHeader(self::$tokenHeaderName);
        if ($tokenValue === null) {
            throw new SaTokenException('RPC 请求缺少 Token 信息');
        }

        $loginType = SaTokenContext::getHeader(self::$loginTypeHeaderName) ?? 'login';
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
        return SaTokenContext::getHeader(self::$loginIdHeaderName);
    }

    public static function getForwardedToken(): ?string
    {
        return SaTokenContext::getHeader(self::$tokenHeaderName);
    }

    public static function getForwardedLoginType(): ?string
    {
        return SaTokenContext::getHeader(self::$loginTypeHeaderName);
    }

    public static function isRpcRequest(): bool
    {
        return SaTokenContext::getHeader(self::$tokenHeaderName) !== null;
    }

    public static function reset(): void
    {
        self::$tokenHeaderName = 'X-Sa-Token';
        self::$loginIdHeaderName = 'X-Sa-Login-Id';
        self::$loginTypeHeaderName = 'X-Sa-Login-Type';
    }
}
