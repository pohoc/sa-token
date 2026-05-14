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
        if (StpUtil::isLogin()) {
            return StpUtil::getLoginId();
        }

        $tokenValue = SaTokenContext::getCookie(SaToken::getConfig()->getTokenName());
        if ($tokenValue !== null) {
            $csrfToken = SaTokenContext::getHeader('X-CSRF-Token') ?? SaTokenContext::getParam('_csrf');
            if ($csrfToken !== null) {
                $savedCsrf = SaTokenContext::getCookie('sso_csrf_token');
                if ($savedCsrf !== null && hash_equals($savedCsrf, $csrfToken)) {
                    $loginId = SaToken::getStpLogic('login')->getTokenManager()
                        ->getLoginIdByToken($tokenValue);
                    if ($loginId !== null) {
                        return $loginId;
                    }
                }
            }

            $newCsrf = bin2hex(random_bytes(16));
            SaTokenContext::setCookie('sso_csrf_token', $newCsrf, 300);
            throw new SaTokenException('同域 SSO 登录需要 CSRF 验证，请携带 X-CSRF-Token 请求头');
        }

        throw new SaTokenException('同域 SSO 登录失败：未检测到有效登录信息');
    }
}
