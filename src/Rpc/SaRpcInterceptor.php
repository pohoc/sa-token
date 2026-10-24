<?php

declare(strict_types=1);

namespace SaToken\Rpc;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Util\SaTokenContext;

class SaRpcInterceptor
{
    protected bool $validateToken = true;
    protected bool $autoLogin = false;
    protected string $loginType = 'login';

    public function setValidateToken(bool $validate): static
    {
        $this->validateToken = $validate;
        return $this;
    }

    public function setAutoLogin(bool $autoLogin): static
    {
        $this->autoLogin = $autoLogin;
        return $this;
    }

    public function setLoginType(string $loginType): static
    {
        $this->loginType = $loginType;
        return $this;
    }

    public function handleIncoming(): void
    {
        if (!SaRpcContext::isRpcRequest()) {
            throw new SaTokenException('RPC 请求缺少认证信息');
        }

        if ($this->validateToken) {
            SaRpcContext::extractAndValidate($this->loginType);
        }

        if ($this->autoLogin) {
            SaTokenContext::setTokenOverride($this->loginType, null);
            $tokenValue = SaRpcContext::getForwardedToken();
            $stpLogic = SaToken::getStpLogic($this->loginType);
            $loginId = $tokenValue !== null ? $stpLogic->getLoginIdByToken($tokenValue) : null;
            if ($loginId === null || $tokenValue === null) {
                // Keep a rejected RPC credential from falling through to a
                // different native token on the same request if the exception
                // is intercepted by application middleware.
                SaTokenContext::setTokenOverride($this->loginType, '');
                throw new SaTokenException('RPC Token 无效');
            }

            if (SaTokenContext::hasMultipleHeaderValues('X-Sa-Login-Id')
                || SaTokenContext::hasMultipleHeaderValues('X-Sa-Login-Type')) {
                SaTokenContext::setTokenOverride($this->loginType, '');
                throw new SaTokenException('RPC 认证 Header 存在多个值');
            }

            $forwardedLoginId = SaRpcContext::getForwardedLoginId();
            $forwardedLoginType = SaRpcContext::getForwardedLoginType();
            if (($forwardedLoginId !== null && $forwardedLoginId !== (string) $loginId)
                || ($forwardedLoginType !== null && $forwardedLoginType !== $this->loginType)) {
                SaTokenContext::setTokenOverride($this->loginType, '');
                throw new SaTokenException('RPC Token 与转发身份信息不匹配');
            }

            // Bind the validated upstream credential to this request's local
            // authentication API without issuing another token or trusting a
            // conflicting native satoken header.
            SaTokenContext::setTokenOverride($this->loginType, $tokenValue);
        }
    }

    /**
     * @param  array<string, string> $headers
     * @return array<string, string>
     */
    public function handleOutgoing(array $headers = []): array
    {
        return SaRpcContext::attachToHeaders($headers);
    }
}
