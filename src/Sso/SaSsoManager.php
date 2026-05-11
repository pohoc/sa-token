<?php

declare(strict_types=1);

namespace SaToken\Sso;

use SaToken\Sso\Mode\SsoModeCrossDomain;
use SaToken\Sso\Mode\SsoModeFrontSeparate;
use SaToken\Sso\Mode\SsoModeSameDomain;

class SaSsoManager
{
    protected SaSsoConfig $config;

    protected SaSsoHandle $handle;

    protected SsoModeSameDomain|SsoModeCrossDomain|SsoModeFrontSeparate|null $modeHandler = null;

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
            default          => new SsoModeCrossDomain($this->config),
        };
    }

    public function getModeHandler(): SsoModeSameDomain|SsoModeCrossDomain|SsoModeFrontSeparate
    {
        return $this->modeHandler;
    }

    public function buildLoginUrl(?string $redirect = null): string
    {
        return $this->handle->buildLoginUrl($redirect);
    }

    public function doLoginCallback(string $ticket): mixed
    {
        return $this->handle->doLoginCallback($ticket);
    }

    public function buildSloUrl(?string $redirect = null): string
    {
        return $this->handle->buildSloUrl($redirect);
    }

    public function doSloCallback(mixed $loginId): void
    {
        $this->handle->doSloCallback($loginId);
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
