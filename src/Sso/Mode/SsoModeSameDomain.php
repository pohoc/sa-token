<?php

declare(strict_types=1);

namespace SaToken\Sso\Mode;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Sso\SaSsoConfig;
use SaToken\Sso\SaSsoHandle;
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
        $tokenName = SaToken::getConfig()->getTokenName();
        if (SaTokenContext::hasMultipleCookieValues($tokenName)) {
            throw new SaTokenException('同域 SSO Cookie 存在多个同名 Token，拒绝登录');
        }

        $tokenValue = SaTokenContext::getCookie($tokenName);
        if ($tokenValue !== null) {
            // 即使普通认证已识别出有效 Token，同域 SSO 入口也必须单独校验 CSRF。
            $csrfToken = SaTokenContext::getHeader('X-CSRF-Token');
            $expectedCsrf = self::buildCsrfValue($tokenValue);
            if ($csrfToken !== null && $csrfToken !== '' && hash_equals($expectedCsrf, $csrfToken)) {
                // 走 StpLogic 的完整校验路径，执行黑名单、loginType 归属、
                // Token 指纹与活动超时检查；直接查 TokenManager 会绕过这些约束。
                $loginId = SaToken::getStpLogic('login')->getLoginIdByToken($tokenValue);
                if ($loginId !== null) {
                    return $loginId;
                }
                // CSRF 正确但 Token 已失效：给客户端明确的重登录信号，
                // 而不是笼统的"需要 CSRF"（那会让前端陷入无意义的重试循环）
                throw new SaTokenException('同域 SSO 登录信息无效或已过期，请重新登录');
            }

            // 前端读取 host-only CSRF Cookie，并在请求头回传；跨站表单不能设置此头。
            SaTokenContext::setCookie('__Host-sso_csrf_token', $expectedCsrf, 300, '/', '', true, false, 'Lax');
            throw new SaTokenException('同域 SSO 登录需要 CSRF 验证，请携带 X-CSRF-Token 请求头');
        }

        throw new SaTokenException('同域 SSO 登录失败：未检测到有效登录信息');
    }

    /**
     * 计算与共享 Token 绑定的 CSRF 值（前端需回传该值作为 X-CSRF-Token）
     */
    public static function buildCsrfValue(string $tokenValue): string
    {
        $salt = SaToken::getConfig()->getSignKey();
        if ($salt === '') {
            $salt = SaToken::getConfig()->getTokenEncryptKey() ?: SaToken::getConfig()->getAesKey();
        }
        if ($salt === '') {
            throw new SaTokenException('同域 SSO CSRF 校验需要配置 signKey、tokenEncryptKey 或 aesKey');
        }
        return hash_hmac('sha256', 'sso-csrf:' . $tokenValue, $salt);
    }
}
