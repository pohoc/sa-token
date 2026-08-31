<?php

declare(strict_types=1);

namespace SaToken\OAuth2;

use SaToken\Dao\SaTokenDaoInterface;
use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\Data\SaOAuth2IdToken;
use SaToken\OAuth2\Data\SaOAuth2RefreshToken;
use SaToken\SaToken;
use SaToken\Security\SaAntiBruteUtil;
use SaToken\Util\SaFoxUtil;
use SaToken\Util\SaTokenEncryptor;

/**
 * OAuth2 请求处理器
 *
 * 处理授权、令牌、资源端点请求
 */
class SaOAuth2Handle
{
    protected SaOAuth2Config $config;

    protected const CLIENT_PREFIX = 'oauth2:client:';

    /**
     * @var array<string, SaOAuth2Client>
     */
    protected array $clientRegistry = [];

    public function __construct(SaOAuth2Config $config)
    {
        $this->config = $config;
    }

    /**
     * 注册客户端
     *
     * 机密客户端（使用授权码/密码/客户端凭证等模式的）必须配置非空 clientSecret，
     * 否则任何提交空密钥的请求都能通过认证（hash_equals('', '') === true）
     *
     * @param  SaOAuth2Client   $client 客户端信息
     * @return void
     * @throws SaTokenException
     */
    public function registerClient(SaOAuth2Client $client): void
    {
        if ($client->getClientId() === '') {
            throw new SaTokenException('注册客户端必须提供 clientId');
        }
        if (trim($client->getClientSecret()) === '') {
            // 公开客户端（PKCE）允许无 secret，但只能使用授权码模式且强制 PKCE；
            // 其他授权模式没有 secret 就等于没有客户端认证
            $grantTypes = $client->getGrantTypes();
            $codeOnly = $grantTypes === [] || $grantTypes === ['authorization_code'];
            if (!$codeOnly) {
                throw new SaTokenException("注册客户端 {$client->getClientId()} 必须提供非空的 clientSecret");
            }
        }
        $this->clientRegistry[$client->getClientId()] = $client;
        $this->getDao()->set(
            self::CLIENT_PREFIX . $client->getClientId(),
            $this->encryptValue(SaFoxUtil::toJson($client->toArray())),
            null
        );
    }

    public function getClient(string $clientId): ?SaOAuth2Client
    {
        if (isset($this->clientRegistry[$clientId])) {
            return $this->clientRegistry[$clientId];
        }

        $json = $this->getDao()->get(self::CLIENT_PREFIX . $clientId);
        if ($json === null) {
            return null;
        }

        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($data)) {
            return null;
        }
        /** @var array<string, mixed> $data */

        $client = new SaOAuth2Client($data);
        $this->clientRegistry[$clientId] = $client;
        return $client;
    }

    /**
     * 生成授权码（授权码模式第一步）
     *
     * @param  string                    $clientId            客户端 ID
     * @param  mixed                     $loginId             资源所有者登录 ID
     * @param  string                    $redirectUri         回调地址
     * @param  string                    $scope               权限范围
     * @param  string                    $codeChallenge       PKCE code_challenge（可选）
     * @param  string                    $codeChallengeMethod PKCE 方法，仅支持 S256（可选）
     * @return SaOAuth2AuthorizationCode
     * @throws SaTokenException
     */
    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = '', string $codeChallenge = '', string $codeChallengeMethod = '', string $nonce = ''): SaOAuth2AuthorizationCode
    {
        $client = $this->validateClient($clientId);
        $this->validateRedirectUri($clientId, $redirectUri);
        $this->validateScopeForClient($client, $scope);

        // 公开客户端（无 secret）必须使用 PKCE，否则授权码可被任意持有 client_id 者兑换
        if ($client->getClientSecret() === '' && $codeChallenge === '') {
            throw new SaTokenException('公开客户端必须使用 PKCE（授权请求需携带 code_challenge）');
        }

        if ($codeChallenge !== '') {
            $method = $codeChallengeMethod !== '' ? $codeChallengeMethod : 'S256';
            if ($method !== 'S256') {
                throw new SaTokenException('PKCE 仅支持 S256 方法（plain 已废弃，不建议使用）');
            }
            if (strlen($codeChallenge) < 43 || strlen($codeChallenge) > 128) {
                throw new SaTokenException('code_challenge 长度必须在 43-128 字符之间');
            }
        }

        $code = new SaOAuth2AuthorizationCode([
            'code'         => SaFoxUtil::randomString(32),
            'clientId'     => $clientId,
            'loginId'      => $loginId,
            'redirectUri'  => $redirectUri,
            'scope'        => $scope,
            'expiresIn'    => $this->config->getCodeTimeout(),
            'codeChallenge' => $codeChallenge,
            'codeChallengeMethod' => $codeChallenge !== '' ? ($codeChallengeMethod !== '' ? $codeChallengeMethod : 'S256') : '',
            'nonce' => $nonce,
        ]);

        // 保存授权码到存储层
        $this->getDao()->set(
            $this->buildCodeKey($code->getCode()),
            $this->encryptValue(SaFoxUtil::toJson($code->toArray())),
            $this->config->getCodeTimeout()
        );

        return $code;
    }

    /**
     * 通过授权码换取访问令牌（授权码模式第二步）
     *
     * RFC 6749 §4.1.3：授权请求若携带 redirect_uri，则换token请求必须携带且完全一致；
     * 本实现强制要求换token请求始终携带 redirect_uri 并精确匹配
     *
     * @param  string              $code         授权码
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $redirectUri  回调地址（必填，与授权请求时完全一致）
     * @param  string              $codeVerifier PKCE 验证器（授权码绑定了 code_challenge 时必填）
     * @return SaOAuth2AccessToken
     * @throws SaTokenException
     */
    public function exchangeTokenByCode(string $code, string $clientId, string $clientSecret, string $redirectUri = '', string $codeVerifier = ''): SaOAuth2AccessToken
    {
        // 客户端认证先于授权码消费：避免攻击者用错误密钥"烧掉"合法客户端的授权码（DoS）。
        // 公开客户端（未配置 secret）改为强制 PKCE 验证作为客户端认证
        $client = $this->validateClient($clientId);
        $this->validateGrantTypeForClient($client, 'authorization_code');
        $isPublicClient = $client->getClientSecret() === '';
        if ($isPublicClient) {
            if ($clientSecret !== '') {
                throw new SaTokenException('客户端密钥错误');
            }
            $this->checkClientNotLocked($clientId);
        } else {
            $client = $this->validateClientWithSecret($clientId, $clientSecret);
        }

        if ($redirectUri === '') {
            throw new SaTokenException('换token请求必须携带 redirect_uri，且与授权请求时完全一致');
        }

        $codeData = $this->consumeAuthorizationCode($code);
        if ($codeData === null) {
            throw new SaTokenException('无效的授权码');
        }
        if ($codeData->isExpired()) {
            throw new SaTokenException('授权码已过期');
        }
        if ($codeData->getClientId() !== $clientId) {
            throw new SaTokenException('客户端 ID 不匹配');
        }

        // redirect_uri 必须与授权请求时提交的值逐一相同，防止授权码被劫持到其他回调
        if ($codeData->getRedirectUri() !== $redirectUri) {
            throw new SaTokenException('回调地址不匹配');
        }

        // PKCE：公开客户端强制要求；机密客户端在授权码绑定了 challenge 时同样必须验证
        if ($codeData->getCodeChallenge() !== '') {
            $this->validateCodeVerifier($codeData, $codeVerifier);
        } elseif ($isPublicClient) {
            throw new SaTokenException('公开客户端必须使用 PKCE（授权请求需携带 code_challenge）');
        }

        $accessToken = $this->generateAccessToken($clientId, $codeData->getLoginId(), $codeData->getScope());

        // OIDC：授权请求携带的 nonce 必须回显进 id_token（重放防护）
        if ($this->config->isOpenIdMode() && $this->scopeContainsOpenid($codeData->getScope()) && $codeData->getNonce() !== '') {
            $idTokenObj = $this->generateIdToken($clientId, $codeData->getLoginId(), $codeData->getScope(), $codeData->getNonce());
            $accessToken->setIdToken($idTokenObj->getIdToken());
        }

        return $accessToken;
    }

    /**
     * 校验 PKCE code_verifier 与授权码绑定的 code_challenge
     *
     * @throws SaTokenException
     */
    protected function validateCodeVerifier(SaOAuth2AuthorizationCode $codeData, string $codeVerifier): void
    {
        if ($codeVerifier === '') {
            throw new SaTokenException('该授权码绑定了 PKCE，必须提交 code_verifier');
        }
        if (strlen($codeVerifier) < 43 || strlen($codeVerifier) > 128) {
            throw new SaTokenException('code_verifier 长度必须在 43-128 字符之间');
        }
        $computed = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
        if (!hash_equals($codeData->getCodeChallenge(), $computed)) {
            throw new SaTokenException('code_verifier 验证失败');
        }
    }

    /**
     * 通过刷新令牌获取新的访问令牌
     *
     * RefreshToken 一次性消费（原子 get-and-delete）+ 重用检测：
     * 已消费的 RT 再次出现时立即撤销整个令牌家族（RFC 6749 BIS 最佳实践）
     *
     * @param  string              $refreshToken 刷新令牌
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @return SaOAuth2AccessToken
     * @throws SaTokenException
     */
    public function refreshToken(string $refreshToken, string $clientId, string $clientSecret): SaOAuth2AccessToken
    {
        $client = $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($client, 'refresh_token');

        $rtKey = $this->buildRefreshTokenKey($refreshToken);
        $markerTimeout = $this->config->getRefreshTokenTimeout() > 0 ? $this->config->getRefreshTokenTimeout() : 86400;

        // 消费前预读取：scope 收紧等配置变更时，让失败发生在 RT 被消费之前，
        // 避免客户端因运维操作被迫整体重新授权
        $preJson = $this->getDao()->get($rtKey);
        if ($preJson !== null) {
            $preData = SaFoxUtil::fromJson($this->decryptValue($preJson));
            if (is_array($preData)) {
                /** @var array<string, mixed> $preData */
                $preScope = is_string($preData['scope'] ?? null) ? $preData['scope'] : '';
                try {
                    $this->validateScopeForClient($client, $preScope);
                } catch (SaTokenException $e) {
                    throw new SaTokenException('刷新令牌的 scope 已不在客户端授权范围内：' . $e->getMessage());
                }
            }
        }

        // 重用检测：familyId 贯穿整条刷新链，重放链上任一 RT 即撤销整个家族
        $familyMarkerPrefix = 'oauth2:family:';
        $preFamilyId = null;
        if ($preJson !== null) {
            $preDecoded = SaFoxUtil::fromJson($this->decryptValue($preJson));
            if (is_array($preDecoded) && is_string($preDecoded['familyId'] ?? null) && $preDecoded['familyId'] !== '') {
                $preFamilyId = $preDecoded['familyId'];
            }
        }

        $rtData = null;
        $familyId = '';

        // 消费标记（RT 哈希 -> familyId）是重放判定的唯一权威：
        // RT 记录本身消费后即删除，标记独立存在使重放请求仍能定位家族并触发整体撤销
        $consumedKey = 'oauth2:rt:consumed:' . hash('sha256', $refreshToken);
        $consumedFamily = $this->getDao()->get($consumedKey);
        if (is_string($consumedFamily) && $consumedFamily !== '') {
            $familyMarkerKey = $familyMarkerPrefix . hash('sha256', $consumedFamily);
            if ($this->getDao()->get($familyMarkerKey) !== null) {
                $this->revokeTokenFamily($familyMarkerKey);
            }
            $this->getDao()->delete($consumedKey);
            throw new SaTokenException('刷新令牌已被使用，检测到可能的令牌泄露，相关令牌已全部撤销');
        }

        // 旧版数据（无 familyId）回退到按 RT 哈希标记
        $legacyMarkerKey = 'oauth2:rt:used:' . hash('sha256', $refreshToken);
        $legacyMarkerJson = $this->getDao()->get($legacyMarkerKey);
        if ($legacyMarkerJson !== null) {
            $this->revokeLegacyMarkerTokens($legacyMarkerKey);
            throw new SaTokenException('刷新令牌已被使用，检测到可能的令牌泄露，相关令牌已全部撤销');
        }

        // 原子消费
        $json = $this->getDao()->getAndDelete($rtKey);
        if ($json === null) {
            throw new SaTokenException('无效的刷新令牌');
        }
        $decoded = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($decoded)) {
            throw new SaTokenException('无效的刷新令牌');
        }
        /** @var array<string, mixed> $decoded */
        $rtData = new SaOAuth2RefreshToken($decoded);
        $familyId = $rtData->getFamilyId();

        if ($familyId !== '') {
            // 家族标记仅是注册表（已签发 AT + 派生 RT），存在与否不代表重放
            $familyMarkerKey = $familyMarkerPrefix . hash('sha256', $familyId);
            if ($this->getDao()->get($familyMarkerKey) === null) {
                $this->getDao()->set($familyMarkerKey, $this->encryptValue(SaFoxUtil::toJson([
                    'tokens'    => [],
                    'childRts'  => [],
                    'revokedAt' => time(),
                ])), $markerTimeout);
            }
            $this->getDao()->set($consumedKey, $familyId, $markerTimeout);

            // 本次消费对应的旧 AT 登记进家族
            if ($rtData->getAccessToken() !== '') {
                $this->appendToTokenFamily($familyMarkerKey, $rtData->getAccessToken(), '', $markerTimeout);
            }
        } else {
            $this->getDao()->set($legacyMarkerKey, $this->encryptValue(SaFoxUtil::toJson([
                'tokens'    => [$rtData->getAccessToken()],
                'revokedAt' => time(),
            ])), $markerTimeout);
        }

        if ($rtData->getClientId() !== $clientId) {
            throw new SaTokenException('客户端 ID 不匹配');
        }

        // 撤销旧访问令牌（若仍存在）
        if ($rtData->getAccessToken() !== '') {
            $this->getDao()->delete($this->buildAccessTokenKey($rtData->getAccessToken()));
        }

        // 生成新的访问令牌
        $accessToken = $this->generateAccessToken($clientId, $rtData->getLoginId(), $rtData->getScope());

        // 如果配置为每次生成新的刷新令牌，新 RT 归入同一家族
        $newRefreshTokenValue = '';
        if ($this->config->isNewRefreshToken()) {
            $newRefreshToken = $this->createRefreshToken($clientId, $rtData->getLoginId(), $accessToken->getAccessToken(), $rtData->getScope(), $familyId !== '' ? $familyId : '');
            $accessToken->setRefreshToken($newRefreshToken->getRefreshToken());
            $newRefreshTokenValue = $newRefreshToken->getRefreshToken();
        }

        // 将新签发的 AT/RT 登记进家族标记，重用检测时一并撤销
        if ($familyId !== '') {
            $this->appendToTokenFamily('oauth2:family:' . hash('sha256', $familyId), $accessToken->getAccessToken(), $newRefreshTokenValue, $markerTimeout);
        }

        return $accessToken;
    }

    /**
     * 撤销整个令牌家族：删除标记中记录的全部 AT 及其配对 RT、派生 RT
     */
    protected function revokeTokenFamily(string $familyMarkerKey): void
    {
        $markerJson = $this->getDao()->get($familyMarkerKey);
        if ($markerJson === null) {
            return;
        }
        $marker = SaFoxUtil::fromJson($this->decryptValue($markerJson));
        if (!is_array($marker)) {
            return;
        }
        $tokens = is_array($marker['tokens'] ?? null) ? $marker['tokens'] : [];
        foreach ($tokens as $familyToken) {
            if (is_string($familyToken) && $familyToken !== '') {
                $this->revokeAccessToken($familyToken);
            }
        }
        $childRts = is_array($marker['childRts'] ?? null) ? $marker['childRts'] : [];
        $rtKeys = [];
        foreach ($childRts as $childRt) {
            if (is_string($childRt) && $childRt !== '') {
                $rtKeys[] = $this->buildRefreshTokenKey($childRt);
            }
        }
        if ($rtKeys !== []) {
            $this->getDao()->deleteMultiple($rtKeys);
        }
        $this->getDao()->delete($familyMarkerKey);
    }

    protected function revokeLegacyMarkerTokens(string $markerKey): void
    {
        $markerJson = $this->getDao()->get($markerKey);
        if ($markerJson === null) {
            return;
        }
        $marker = SaFoxUtil::fromJson($this->decryptValue($markerJson));
        if (is_array($marker)) {
            $tokens = is_array($marker['tokens'] ?? null) ? $marker['tokens'] : [];
            foreach ($tokens as $familyToken) {
                if (is_string($familyToken) && $familyToken !== '') {
                    $this->revokeAccessToken($familyToken);
                }
            }
        }
    }

    protected function appendToTokenFamily(string $familyMarkerKey, string $accessToken, string $childRefreshToken, int $markerTimeout): void
    {
        $markerJson = $this->getDao()->get($familyMarkerKey);
        if ($markerJson === null) {
            return;
        }
        $marker = SaFoxUtil::fromJson($this->decryptValue($markerJson));
        if (!is_array($marker)) {
            return;
        }
        $tokens = is_array($marker['tokens'] ?? null) ? $marker['tokens'] : [];
        $tokens[] = $accessToken;
        $childRts = is_array($marker['childRts'] ?? null) ? $marker['childRts'] : [];
        if ($childRefreshToken !== '') {
            $childRts[] = $childRefreshToken;
        }
        $this->getDao()->set($familyMarkerKey, $this->encryptValue(SaFoxUtil::toJson([
            'tokens'    => $tokens,
            'childRts'  => $childRts,
            'revokedAt' => $marker['revokedAt'] ?? time(),
        ])), $markerTimeout);
    }

    /**
     * 密码模式获取令牌
     *
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $username     用户名
     * @param  string              $password     密码
     * @param  string              $scope        权限范围
     * @return SaOAuth2AccessToken
     * @throws SaTokenException
     */
    public function tokenByPassword(string $clientId, string $clientSecret, string $username, string $password, string $scope = ''): SaOAuth2AccessToken
    {
        if (!in_array('password', $this->config->getGrantTypes(), true)) {
            throw new SaTokenException('不支持密码模式');
        }

        $client = $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($client, 'password');

        // 密码模式是暴露在公网的用户凭据验证端点，必须接入防暴力锁定：
        // 连续失败达到 antiBruteMaxFailures 后该用户名临时锁定（原子计数）
        SaAntiBruteUtil::checkAndThrow($username);

        // 用户验证由外部回调处理
        $loginId = $this->validateUserCredentials($username, $password);
        if ($loginId === null) {
            SaAntiBruteUtil::recordFailure($username);
            throw new SaTokenException('用户名或密码错误');
        }

        SaAntiBruteUtil::clearFailures($username);

        return $this->generateAccessToken($clientId, $loginId, $scope);
    }

    /**
     * 客户端凭证模式获取令牌
     *
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $scope        权限范围
     * @return SaOAuth2AccessToken
     * @throws SaTokenException
     */
    public function tokenByClientCredentials(string $clientId, string $clientSecret, string $scope = ''): SaOAuth2AccessToken
    {
        if (!in_array('client_credentials', $this->config->getGrantTypes(), true)) {
            throw new SaTokenException('不支持客户端凭证模式');
        }

        $client = $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($client, 'client_credentials');

        return $this->generateAccessToken($clientId, 'client:' . $clientId, $scope);
    }

    /**
     * 验证访问令牌
     *
     * 除存储层 TTL 外，还会对数据对象做过期复查，
     * 防止自定义存储实现未正确处理 TTL 时已过期令牌仍可用
     *
     * @param  string                   $accessToken 访问令牌
     * @return SaOAuth2AccessToken|null
     */
    public function validateAccessToken(string $accessToken): ?SaOAuth2AccessToken
    {
        $json = $this->getDao()->get($this->buildAccessTokenKey($accessToken));
        if ($json === null) {
            return null;
        }

        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($data)) {
            return null;
        }
        /** @var array<string, mixed> $data */
        $tokenData = new SaOAuth2AccessToken($data);
        if ($tokenData->isExpired()) {
            $this->getDao()->delete($this->buildAccessTokenKey($accessToken));
            return null;
        }
        return $tokenData;
    }

    /**
     * 撤销访问令牌（同时撤销其配对的刷新令牌）
     *
     * @param  string $accessToken 访问令牌
     * @return void
     */
    public function revokeAccessToken(string $accessToken): void
    {
        $json = $this->getDao()->get($this->buildAccessTokenKey($accessToken));
        if ($json !== null) {
            $data = SaFoxUtil::fromJson($this->decryptValue($json));
            if (is_array($data)) {
                $refreshToken = is_string($data['refreshToken'] ?? null) ? $data['refreshToken'] : '';
                if ($refreshToken !== '') {
                    $this->getDao()->delete($this->buildRefreshTokenKey($refreshToken));
                }
            }
        }
        $this->getDao()->delete($this->buildAccessTokenKey($accessToken));
    }

    /**
     * 获取客户端，不存在时抛出异常（供策略层等外部调用做前置校验）
     *
     * @throws SaTokenException
     */
    public function getClientOrFail(string $clientId): SaOAuth2Client
    {
        return $this->validateClient($clientId);
    }

    /**
     * 回调地址校验的公开入口（供策略层等外部调用）
     *
     * @throws SaTokenException
     */
    public function validateRedirectUriPublic(string $clientId, string $redirectUri): void
    {
        $this->validateRedirectUri($clientId, $redirectUri);
    }

    public function checkScope(string $accessToken, string $requiredScope): bool
    {
        $tokenData = $this->validateAccessToken($accessToken);
        if ($tokenData === null) {
            return false;
        }

        $scope = $tokenData->getScope();
        if ($scope === '') {
            return false;
        }

        $scopes = explode(' ', $scope);
        return in_array($requiredScope, $scopes, true);
    }

    public function checkScopeAndThrow(string $accessToken, string $requiredScope): void
    {
        if (!$this->checkScope($accessToken, $requiredScope)) {
            throw new SaTokenException("权限不足，缺少 scope: {$requiredScope}");
        }
    }

    public function hasScope(string $accessToken, string $scope): bool
    {
        return $this->checkScope($accessToken, $scope);
    }

    // ---- 内部方法 ----

    /**
     * 生成访问令牌
     *
     * scope 在此做最终兜底校验：请求 scope 必须是客户端注册 scopes 的子集，
     * 防止任何入口（策略类/直接调用）自授权未授予的权限
     */
    public function generateAccessToken(string $clientId, mixed $loginId, string $scope = ''): SaOAuth2AccessToken
    {
        $client = $this->getClient($clientId);
        if ($client !== null) {
            $this->validateScopeForClient($client, $scope);
        }

        $tokenStr = SaFoxUtil::randomString(64);
        $expiresIn = $this->config->getAccessTokenTimeout();

        $accessToken = new SaOAuth2AccessToken([
            'accessToken' => $tokenStr,
            'expiresIn'   => $expiresIn,
            'tokenType'   => 'Bearer',
            'scope'       => $scope,
            'loginId'     => $loginId,
            'clientId'    => $clientId,
        ]);

        // 生成刷新令牌
        if ($this->config->getRefreshTokenTimeout() > 0) {
            $refreshToken = $this->createRefreshToken($clientId, $loginId, $tokenStr, $scope);
            $accessToken->setRefreshToken($refreshToken->getRefreshToken());
        }

        // 保存到存储层（含 refreshToken 关联，便于撤销时联动）
        $this->getDao()->set(
            $this->buildAccessTokenKey($tokenStr),
            $this->encryptValue(SaFoxUtil::toJson($accessToken->toArray())),
            $expiresIn
        );

        // OIDC 规范：id_token 仅在请求包含 openid scope 时签发，
        // 防止未请求身份信息的流程被附带下发 sub 等身份声明
        if ($this->config->isOpenIdMode() && $this->scopeContainsOpenid($scope)) {
            $idTokenObj = $this->generateIdToken($clientId, $loginId, $scope);
            $accessToken->setIdToken($idTokenObj->getIdToken());
            $this->getDao()->set(
                $this->buildAccessTokenKey($tokenStr),
                $this->encryptValue(SaFoxUtil::toJson($accessToken->toArray())),
                $expiresIn
            );
        }

        return $accessToken;
    }

    /**
     * 创建刷新令牌
     */
    protected function createRefreshToken(string $clientId, mixed $loginId, string $accessToken, string $scope = '', string $familyId = ''): SaOAuth2RefreshToken
    {
        $rtStr = SaFoxUtil::randomString(64);
        $expiresIn = $this->config->getRefreshTokenTimeout();

        $refreshToken = new SaOAuth2RefreshToken([
            'refreshToken' => $rtStr,
            'accessToken'  => $accessToken,
            'clientId'     => $clientId,
            'loginId'      => $loginId,
            'scope'        => $scope,
            'expiresIn'    => $expiresIn,
            'familyId'     => $familyId !== '' ? $familyId : SaFoxUtil::randomString(32),
        ]);

        $this->getDao()->set(
            $this->buildRefreshTokenKey($rtStr),
            $this->encryptValue(SaFoxUtil::toJson($refreshToken->toArray())),
            $expiresIn
        );

        return $refreshToken;
    }

    /**
     * 获取授权码数据
     */
    protected function getAuthorizationCode(string $code): ?SaOAuth2AuthorizationCode
    {
        $json = $this->getDao()->get($this->buildCodeKey($code));
        if ($json === null) {
            return null;
        }

        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return new SaOAuth2AuthorizationCode($data);
    }

    protected function consumeAuthorizationCode(string $code): ?SaOAuth2AuthorizationCode
    {
        $json = $this->getDao()->getAndDelete($this->buildCodeKey($code));
        if ($json === null) {
            return null;
        }

        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return new SaOAuth2AuthorizationCode($data);
    }

    /**
     * 获取刷新令牌数据
     */
    protected function getRefreshTokenData(string $refreshToken): ?SaOAuth2RefreshToken
    {
        $json = $this->getDao()->get($this->buildRefreshTokenKey($refreshToken));
        if ($json === null) {
            return null;
        }

        $data = SaFoxUtil::fromJson($this->decryptValue($json));
        if (!is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return new SaOAuth2RefreshToken($data);
    }

    /**
     * 验证客户端
     */
    protected function validateClient(string $clientId): SaOAuth2Client
    {
        $client = $this->getClient($clientId);
        if ($client === null) {
            throw new SaTokenException('未注册的客户端');
        }
        return $client;
    }

    /**
     * 验证客户端（含密钥）
     *
     * 空密钥一律拒绝（hash_equals('', '') === true 的空密码绕过）；
     * 连续失败达到配置阈值后临时锁定，防止 client_secret 在线爆破
     */
    protected function validateClientWithSecret(string $clientId, string $clientSecret): SaOAuth2Client
    {
        $this->checkClientNotLocked($clientId);
        $client = $this->validateClient($clientId);
        if ($client->getClientSecret() === '' || $clientSecret === '' || !hash_equals($client->getClientSecret(), $clientSecret)) {
            $this->recordClientFailure($clientId);
            throw new SaTokenException('客户端密钥错误');
        }
        $this->clearClientFailures($clientId);
        return $client;
    }

    /**
     * 校验请求 scope 是客户端注册 scopes 的子集。
     * 客户端未注册 scopes 时视为不限制（等价 *），注册了 scopes 则严格执行白名单
     */
    protected function validateScopeForClient(SaOAuth2Client $client, string $scope): void
    {
        if ($scope === '') {
            return;
        }
        $registered = $client->getScopes();
        if ($registered === []) {
            return;
        }
        $requested = preg_split('/\s+/', trim($scope)) ?: [];
        foreach ($requested as $item) {
            if ($item !== '' && !in_array($item, $registered, true)) {
                throw new SaTokenException('请求了未授予的 scope');
            }
        }
    }

    /**
     * 校验客户端被授权使用该 grant_type。
     * 客户端未注册 grantTypes 时回退到全局配置检查
     */
    protected function validateGrantTypeForClient(SaOAuth2Client $client, string $grantType): void
    {
        $allowed = $client->getGrantTypes();
        if ($allowed === []) {
            $allowed = $this->config->getGrantTypes();
        }
        if (!in_array($grantType, $allowed, true)) {
            throw new SaTokenException('该客户端未被授权使用此授权模式');
        }
    }

    protected function clientFailureKey(string $clientId): string
    {
        return 'oauth2:client:fail:' . hash('sha256', $clientId);
    }

    protected function checkClientNotLocked(string $clientId): void
    {
        $max = $this->config->getClientSecretMaxFailures();
        if ($max <= 0) {
            return;
        }
        $count = $this->getDao()->get($this->clientFailureKey($clientId));
        if ($count !== null && (int) $count >= $max) {
            throw new SaTokenException('客户端认证失败次数过多，已临时锁定，请稍后重试');
        }
    }

    protected function recordClientFailure(string $clientId): void
    {
        $max = $this->config->getClientSecretMaxFailures();
        if ($max <= 0) {
            return;
        }
        $window = $this->config->getClientFailureWindow();
        $this->getDao()->increment($this->clientFailureKey($clientId), 1, $window > 0 ? $window : 300);
    }

    protected function clearClientFailures(string $clientId): void
    {
        $this->getDao()->delete($this->clientFailureKey($clientId));
    }

    /**
     * 验证回调地址（fail-closed：客户端不存在、地址为空、未注册列表为空均拒绝）
     */
    protected function validateRedirectUri(string $clientId, string $redirectUri): void
    {
        $client = $this->validateClient($clientId);

        if ($redirectUri === '') {
            throw new SaTokenException('回调地址不能为空');
        }

        $parsed = parse_url($redirectUri);
        if ($parsed === false || !isset($parsed['scheme']) || !isset($parsed['host']) || $parsed['host'] === '') {
            throw new SaTokenException('回调地址必须是绝对 URL');
        }
        $scheme = strtolower((string) $parsed['scheme']);
        $host = strtolower((string) $parsed['host']);
        $isLocal = $host === 'localhost' || $host === '127.0.0.1' || $host === '::1';
        if ($scheme !== 'https' && !$isLocal) {
            throw new SaTokenException('回调地址必须使用 HTTPS 协议');
        }

        $uris = $client->getRedirectUris();
        if (in_array($redirectUri, $uris, true)) {
            return;
        }

        // scheme/host 按大小写不敏感语义做归一化精确匹配（path/query 仍精确比较），
        // 未注册列表为空时直接拒绝，不放行任意 URI
        $targetPort = isset($parsed['port']) ? ':' . $parsed['port'] : '';
        $target = $scheme . '://' . $host . $targetPort . ($parsed['path'] ?? '');
        foreach ($uris as $uri) {
            if (!is_string($uri)) {
                continue;
            }
            $p = parse_url($uri);
            if ($p === false || !isset($p['scheme']) || !isset($p['host'])) {
                continue;
            }
            $normalized = strtolower((string) $p['scheme']) . '://' . strtolower((string) $p['host'])
                . (isset($p['port']) ? ':' . $p['port'] : '') . ($p['path'] ?? '');
            if ($normalized === $target && ($p['query'] ?? '') === ($parsed['query'] ?? '')) {
                return;
            }
        }

        throw new SaTokenException('未注册的回调地址');
    }

    /**
     * 用户凭据验证回调
     * @var callable|null
     */
    protected $userCredentialsValidator = null;

    /**
     * 设置用户凭据验证回调
     *
     * @param  callable $validator (string $username, string $password): mixed 返回 loginId 或 null
     * @return static
     */
    public function setUserCredentialsValidator(callable $validator): static
    {
        $this->userCredentialsValidator = $validator;
        return $this;
    }

    /**
     * 验证用户凭据
     *
     * @param  string $username 用户名
     * @param  string $password 密码
     * @return mixed  登录 ID，验证失败返回 null
     */
    protected function validateUserCredentials(string $username, string $password): mixed
    {
        if ($this->userCredentialsValidator !== null) {
            return ($this->userCredentialsValidator)($username, $password);
        }
        return null;
    }

    /**
     * 生成 ID Token（OpenID Connect）
     *
     * @param  string          $clientId 客户端 ID
     * @param  mixed           $loginId  资源所有者登录 ID
     * @param  string          $scope    权限范围
     * @return SaOAuth2IdToken
     */
    public function generateIdToken(string $clientId, mixed $loginId, string $scope = '', string $nonce = ''): SaOAuth2IdToken
    {
        $now = time();
        $expiresAt = $now + $this->config->getAccessTokenTimeout();

        $loginIdStr = is_string($loginId) ? $loginId : (is_scalar($loginId) ? (string) $loginId : '');

        $payload = [
            'iss' => $this->config->getIssuer(),
            'sub' => $loginIdStr,
            'aud' => $clientId,
            'iat' => $now,
            'exp' => $expiresAt,
            // jti 唯一标识 + nonce 回显：nonce 是 OIDC 的 id_token 重放防护——
            // 客户端在授权请求中携带随机 nonce，必须在签发的 id_token 中原样返回
            'jti' => SaFoxUtil::randomString(24),
        ];
        if ($nonce !== '') {
            $payload['nonce'] = $nonce;
        }

        $jwtStr = $this->signJwt($payload);

        return new SaOAuth2IdToken([
            'idToken'  => $jwtStr,
            'subject'  => $loginIdStr,
            'audience' => $clientId,
            'issuedAt' => $now,
            'expiresAt' => $expiresAt,
            'issuer'   => $this->config->getIssuer(),
            'claims'   => $payload,
        ]);
    }

    protected function scopeContainsOpenid(string $scope): bool
    {
        $scopes = preg_split('/\s+/', $scope);
        if ($scopes === false) {
            return false;
        }
        return in_array('openid', $scopes, true);
    }

    /**
     * @param array<string, mixed> $payload
     */
    protected function signJwt(array $payload): string
    {
        $header = [
            'typ' => 'JWT',
            'alg' => 'HS256',
        ];

        $headerB64 = $this->base64UrlEncode(json_encode($header, JSON_UNESCAPED_UNICODE) ?: '');
        $payloadB64 = $this->base64UrlEncode(json_encode($payload, JSON_UNESCAPED_UNICODE) ?: '');
        $signingInput = $headerB64 . '.' . $payloadB64;

        $secretKey = $this->getClientSecretForSigning();
        $signature = hash_hmac('sha256', $signingInput, $secretKey);

        $signatureBin = hex2bin($signature);
        if ($signatureBin === false) {
            throw new SaTokenException('JWT 签名失败');
        }

        return $signingInput . '.' . $this->base64UrlEncode($signatureBin);
    }

    protected function getClientSecretForSigning(): string
    {
        $jwtSecretKey = SaToken::getConfig()->getJwtSecretKey();
        if ($jwtSecretKey !== '') {
            return $jwtSecretKey;
        }
        throw new SaTokenException('OAuth2 ID Token 签名需要配置 jwtSecretKey');
    }

    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * 获取存储层
     */
    protected ?SaTokenEncryptor $encryptor = null;

    protected function getEncryptor(): SaTokenEncryptor
    {
        if ($this->encryptor === null) {
            $config = SaToken::getConfig();
            $key = $config->getTokenEncryptKey() ?: $config->getAesKey();
            if ($config->getCryptoType() === 'sm') {
                $key = $config->getTokenEncryptKey() ?: $config->getSm4Key();
            }
            $this->encryptor = new SaTokenEncryptor($config->isTokenEncrypt(), $key, $config->getCryptoType());
        }
        return $this->encryptor;
    }

    protected function encryptValue(string $value): string
    {
        return $this->getEncryptor()->encrypt($value);
    }

    protected function decryptValue(string $value): string
    {
        return $this->getEncryptor()->decrypt($value);
    }

    protected function getDao(): SaTokenDaoInterface
    {
        return SaToken::getDao();
    }

    /**
     * 构建授权码存储键
     */
    protected function buildCodeKey(string $code): string
    {
        return 'oauth2:code:' . $code;
    }

    /**
     * 构建访问令牌存储键
     */
    protected function buildAccessTokenKey(string $token): string
    {
        return 'oauth2:at:' . $token;
    }

    /**
     * 构建刷新令牌存储键
     */
    protected function buildRefreshTokenKey(string $token): string
    {
        return 'oauth2:rt:' . $token;
    }
}
