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
            // CSRF 值与共享 Token 确定性绑定（HMAC），不再使用随机双提交 Cookie：
            // 1) 共享 Token Cookie 为 HttpOnly，控制子域的攻击者读不到 Token 便无法
            //    伪造 CSRF 值，也无法通过子域 Cookie 注入固定已知值
            // 2) 只接受请求头（跨站表单无法携带自定义头）；GET 参数会把 CSRF 值
            //    泄入 Referer/日志，等于把票据递给攻击者
            // 3) 值可随时重算，验证失败不再"重置随机值"（消除重置竞态/DoS）
            $csrfToken = SaTokenContext::getHeader('X-CSRF-Token');
            $expectedCsrf = self::buildCsrfValue($tokenValue);
            if ($csrfToken !== null && $csrfToken !== '' && hash_equals($expectedCsrf, $csrfToken)) {
                $loginId = SaToken::getStpLogic('login')->getTokenManager()
                    ->getLoginIdByToken($tokenValue);
                if ($loginId !== null) {
                    return $loginId;
                }
                // CSRF 正确但 Token 已失效：给客户端明确的重登录信号，
                // 而不是笼统的"需要 CSRF"（那会让前端陷入无意义的重试循环）
                throw new SaTokenException('同域 SSO 登录信息无效或已过期，请重新登录');
            }

            // 前端契约：sso_csrf_token = sha256(共享Token)。未携带或不匹配时
            // 下发/刷新该 Cookie 供前端读取（登录请求必须用 X-CSRF-Token 头回传）
            SaTokenContext::setCookie('sso_csrf_token', $expectedCsrf, 300);
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
            // 无任何可用密钥时退化为纯哈希（仍优于可预测的双提交，但建议配置密钥）
            return hash('sha256', 'sso-csrf:' . $tokenValue);
        }
        return hash_hmac('sha256', 'sso-csrf:' . $tokenValue, $salt);
    }
}
