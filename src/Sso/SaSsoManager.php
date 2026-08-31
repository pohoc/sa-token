<?php

declare(strict_types=1);

namespace SaToken\Sso;

use SaToken\Sso\Mode\SsoModeCrossDomain;
use SaToken\Sso\Mode\SsoModeFrontSeparate;
use SaToken\Sso\Mode\SsoModeNoSdk;
use SaToken\Sso\Mode\SsoModeSameDomain;
use SaToken\StpUtil;

class SaSsoManager
{
    protected SaSsoConfig $config;

    protected SaSsoHandle $handle;

    protected SsoModeSameDomain|SsoModeCrossDomain|SsoModeFrontSeparate|SsoModeNoSdk|null $modeHandler = null;

    /**
     * @param SaSsoConfig|array<string, mixed>|null $config
     */
    public function __construct(SaSsoConfig|array|null $config = null)
    {
        if ($config instanceof SaSsoConfig) {
            $this->config = $config;
        } elseif (is_array($config)) {
            $this->config = new SaSsoConfig($config);
        } else {
            $ssoConfig = \SaToken\SaToken::getConfig()->getSso();
            $this->config = new SaSsoConfig($ssoConfig);
        }

        $this->handle = new SaSsoHandle($this->config);
        $this->initModeHandler();
    }

    protected function initModeHandler(): void
    {
        $mode = $this->config->getMode();
        $this->modeHandler = match ($mode) {
            'same-domain'    => new SsoModeSameDomain($this->config),
            'cross-domain'   => new SsoModeCrossDomain($this->config),
            'front-separate' => new SsoModeFrontSeparate($this->config),
            'no-sdk'         => new SsoModeNoSdk($this->handle),
            default          => new SsoModeCrossDomain($this->config),
        };
    }

    public function getModeHandler(): SsoModeSameDomain|SsoModeCrossDomain|SsoModeFrontSeparate|SsoModeNoSdk
    {
        if ($this->modeHandler === null) {
            $this->initModeHandler();
        }
        assert($this->modeHandler !== null);
        return $this->modeHandler;
    }

    public function buildLoginUrl(?string $redirect = null): string
    {
        return $this->handle->buildLoginUrl($redirect);
    }

    public function doLoginCallback(string $ticket, ?string $redirect = null, ?string $state = null): mixed
    {
        if ($this->config->isCrossRedis()) {
            // 跨 Redis 路径同样必须经过 state/redirect 校验，不能成为绕过防护的旁路
            $this->handle->validateCallbackRequest($redirect, $state);

            $loginId = $this->handle->checkTicketCrossRedis($ticket);
            if ($loginId !== null) {
                StpUtil::login($loginId);
            }
            return $loginId;
        }

        return $this->handle->doLoginCallback($ticket, $redirect, $state);
    }

    /**
     * @param array<string, mixed>|null $params
     */
    public function doSloCallback(mixed $loginId, ?array $params = null): void
    {
        $this->handle->doSloCallback($loginId, $params);
    }

    /**
     * 构建单点注销回调参数（认证中心侧使用，自动附带签名）
     *
     * @return array<string, string>
     */
    public function buildSloCallbackParams(mixed $loginId): array
    {
        return $this->handle->buildSloCallbackParams($loginId);
    }

    public function buildSloUrl(?string $redirect = null): string
    {
        return $this->handle->buildSloUrl($redirect);
    }

    public function getConfig(): SaSsoConfig
    {
        return $this->config;
    }

    public function getHandle(): SaSsoHandle
    {
        return $this->handle;
    }
}
