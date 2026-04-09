<?php

declare(strict_types=1);

namespace SaToken\Sso\Mode;

use SaToken\Exception\SaTokenException;
use SaToken\SaToken;
use SaToken\Sso\SaSsoConfig;
use SaToken\Sso\SaSsoHandle;
use SaToken\StpUtil;
use SaToken\Util\SaFoxUtil;

/**
 * SSO 模式三：前后端分离架构
 *
 * 适用于前后端分离项目，前端获取 ticket 后通过 AJAX 调用后端接口完成登录
 * 后端校验 ticket 后返回 Token 信息给前端
 *
 * 使用示例：
 *   $mode = new SsoModeFrontSeparate($ssoConfig);
 *   $result = $mode->doLoginByTicket($ticket);
 *   // 返回 ['tokenValue' => 'xxx', 'loginId' => 10001]
 */
class SsoModeFrontSeparate
{
    protected SaSsoHandle $handle;

    public function __construct(SaSsoConfig $config)
    {
        $this->handle = new SaSsoHandle($config);
    }

    /**
     * 通过 ticket 完成登录（前后端分离模式）
     *
     * 校验 ticket 后返回 Token 信息，前端自行保存
     *
     * @param  string                                                       $ticket SSO ticket
     * @return array{tokenValue: string, loginId: mixed, tokenName: string}
     * @throws SaTokenException
     */
    public function doLoginByTicket(string $ticket): array
    {
        if (SaFoxUtil::isEmpty($ticket)) {
            throw new SaTokenException('ticket 不能为空');
        }

        $loginId = $this->handle->doLoginCallback($ticket);

        $tokenValue = StpUtil::getTokenValue();
        $tokenName = SaToken::getConfig()->getTokenName();

        return [
            'tokenValue' => $tokenValue ?? '',
            'loginId'    => $loginId,
            'tokenName'  => $tokenName,
        ];
    }

    /**
     * 构建登录 URL（供前端跳转）
     *
     * @param  string|null $redirect 登录后回调地址
     * @return string
     */
    public function buildLoginUrl(?string $redirect = null): string
    {
        return $this->handle->buildLoginUrl($redirect);
    }

    /**
     * 处理单点注销
     *
     * @param  mixed $loginId 登录 ID
     * @return void
     */
    public function doSloCallback(mixed $loginId): void
    {
        $this->handle->doSloCallback($loginId);
    }
}
