<?php

declare(strict_types=1);

namespace SaToken\Sso\Mode;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Sso\SaSsoConfig;
use SaToken\Sso\SaSsoHandle;
use SaToken\StpUtil;
use SaToken\Util\SaTokenContext;

/**
 * SSO 模式一：同域 Cookie 共享
 *
 * 适用于子系统与认证中心在同一主域名下的场景
 * 通过共享 Cookie 实现单点登录，无需额外 ticket 校验
 *
 * 使用示例：
 *   $mode = new SsoModeSameDomain($ssoConfig);
 *   $loginId = $mode->doLogin();
 */
class SsoModeSameDomain
{
    protected SaSsoHandle $handle;

    public function __construct(SaSsoConfig $config)
    {
        $this->handle = new SaSsoHandle($config);
    }

    /**
     * 处理同域登录
     *
     * 检查共享 Cookie 中是否有有效的登录信息
     *
     * @return mixed            登录 ID
     * @throws SaTokenException
     */
    public function doLogin(): mixed
    {
        // 检查当前是否已登录
        if (StpUtil::isLogin()) {
            return StpUtil::getLoginId();
        }

        // 检查共享 Cookie 中的 token
        $tokenValue = SaTokenContext::getCookie(SaToken::getConfig()->getTokenName());
        if ($tokenValue !== null) {
            $loginId = SaToken::getStpLogic('login')->getTokenManager()
                ->getLoginIdByToken($tokenValue);
            if ($loginId !== null) {
                return $loginId;
            }
        }

        throw new SaTokenException('同域 SSO 登录失败：未检测到有效登录信息');
    }
}
