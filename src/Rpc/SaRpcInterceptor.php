<?php

declare(strict_types=1);

namespace SaToken\Rpc;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;

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
            SaRpcContext::extractAndValidate();
        }

        if ($this->autoLogin) {
            $tokenValue = SaRpcContext::getForwardedToken();
            if ($tokenValue !== null) {
                $stpLogic = SaToken::getStpLogic($this->loginType);
                $loginId = $stpLogic->getLoginIdByToken($tokenValue);
                if ($loginId !== null) {
                    $stpLogic->login($loginId);
                }
            }
        }
    }

    public function handleOutgoing(array $headers = []): array
    {
        return SaRpcContext::attachToHeaders($headers);
    }
}
