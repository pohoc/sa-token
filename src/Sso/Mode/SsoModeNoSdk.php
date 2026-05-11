<?php

declare(strict_types=1);

namespace SaToken\Sso\Mode;

use SaToken\Exception\SaTokenException;
use SaToken\Sso\SaSsoHandle;
use SaToken\Util\SaFoxUtil;

class SsoModeNoSdk
{
    public function __construct(protected SaSsoHandle $handle)
    {
    }

    public function buildLoginUrl(?string $redirect = null, ?string $currentUrl = null): string
    {
        return $this->handle->buildLoginUrl($redirect, $currentUrl);
    }

    public function validateTicket(string $ticket): mixed
    {
        if (SaFoxUtil::isEmpty($ticket)) {
            throw new SaTokenException('ticket 不能为空');
        }

        $config = $this->handle->getConfig();

        if ($config->isCrossRedis()) {
            $loginId = $this->handle->checkTicketCrossRedis($ticket);
        } else {
            $loginId = $this->handle->doLoginCallback($ticket);
        }

        if ($loginId === null) {
            throw new SaTokenException('SSO ticket 校验失败');
        }

        return $loginId;
    }

    public function doLoginByTicket(string $ticket): array
    {
        $loginId = $this->validateTicket($ticket);
        $redirect = $this->handle->restorePreLoginUrl();

        return [
            'loginId'  => $loginId,
            'redirect' => $redirect,
        ];
    }
}
