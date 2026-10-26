<?php

declare(strict_types=1);

namespace SaToken\OAuth2;

use SaToken\Dao\SaTokenDaoCompareAndExpireInterface;
use SaToken\Dao\SaTokenDaoCompareAndSetInterface;
use SaToken\Dao\SaTokenDaoCompareAndUpdateInterface;
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
use SaToken\Util\SaTokenContext;
use SaToken\Util\SaTokenEncryptor;

/**
 * OAuth2 请求处理器
 *
 * 处理授权、令牌、资源端点请求
 */
class SaOAuth2Handle
{
    protected const MAX_SCOPE_LENGTH = 4096;

    protected const MAX_OIDC_NONCE_LENGTH = 1024;

    protected SaOAuth2Config $config;

    protected const CLIENT_PREFIX = 'oauth2:client:';

    public function __construct(SaOAuth2Config $config)
    {
        $this->config = $config;
    }

    /**
     * 注册客户端
     *
     * 机密客户端必须配置至少 32 字节的 clientSecret；公开客户端仅能用空 secret 并使用授权码 + PKCE
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
        $clientSecret = $client->getClientSecret();
        if ($clientSecret === '') {
            // 公开客户端（PKCE）允许无 secret，但只能使用授权码模式且强制 PKCE；
            // 其他授权模式没有 secret 就等于没有客户端认证
            $grantTypes = $client->getGrantTypes();
            $codeOnly = $grantTypes === [] || $grantTypes === ['authorization_code'];
            if (!$codeOnly) {
                throw new SaTokenException("注册客户端 {$client->getClientId()} 必须提供非空的 clientSecret");
            }
        } elseif (trim($clientSecret) === '') {
            throw new SaTokenException("注册客户端 {$client->getClientId()} 的 clientSecret 不能只包含空白字符");
        } elseif (strlen($clientSecret) < 32) {
            throw new SaTokenException("注册客户端 {$client->getClientId()} 的 clientSecret 至少需要 32 字节");
        }
        $this->getDao()->set(
            self::CLIENT_PREFIX . $client->getClientId(),
            $this->encryptValue(SaFoxUtil::toJson($client->toArray())),
            null
        );
    }

    public function getClient(string $clientId): ?SaOAuth2Client
    {
        // Client secrets and redirect/grant allowlists can be rotated from a
        // different process. Always read the shared DAO so cached credentials
        // cannot remain valid after revocation or rotation.
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
        return $client->getClientId() === $clientId ? $client : null;
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
        $this->validateGrantTypeForClient($client, 'authorization_code');
        $this->validateRedirectUri($clientId, $redirectUri);
        $scope = $this->validateScopeForClient($client, $scope);
        $this->validateOidcNonce($nonce);

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
        $codeKey = $this->buildCodeKey($code->getCode());
        $this->getDao()->set(
            $codeKey,
            $this->encryptValueForContext(SaFoxUtil::toJson($code->toArray()), $codeKey),
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

        // A redirect URI may have been removed from the client's live
        // allowlist after this code was issued. Revalidate current policy
        // before reading or consuming the code so administrative revocation
        // takes effect immediately without burning codes on rejected requests.
        $this->validateRedirectUri($clientId, $redirectUri);

        // 绑定校验完成前只读取，不消费授权码；否则错误客户端、redirect_uri 或
        // PKCE verifier 可烧毁合法授权码，造成拒绝服务。
        $codeData = $this->getAuthorizationCode($code);
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

        $scope = $this->validateScopeForClient($client, $codeData->getScope());
        $nonce = $codeData->getNonce();
        $this->validateOidcNonce($nonce);
        if ($this->config->isOpenIdMode() && $this->scopeContainsOpenid($scope)) {
            $this->validateIdTokenIssuer();
        }

        // Client policy and credentials are stored in the shared DAO and may
        // be revoked while this request validates the code. Re-read one current
        // client snapshot at the consumption boundary so an old redirect URI,
        // secret, grant, or scope cannot authorize a code after revocation.
        $currentClient = $isPublicClient
            ? $this->validateClient($clientId)
            : $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($currentClient, 'authorization_code');
        if (($currentClient->getClientSecret() === '') !== $isPublicClient) {
            throw new SaTokenException('客户端认证配置已变更，请重新发起授权');
        }
        $this->validateRedirectUriForClient($currentClient, $redirectUri);
        $scope = $this->validateScopeForClient($currentClient, $codeData->getScope());

        // 绑定校验成功后再原子消费；并发兑换时只有一个请求能继续签发令牌。
        $consumedCode = $this->consumeAuthorizationCode($code);
        if ($consumedCode === null || $consumedCode->getCode() !== $code
            || $consumedCode->getClientId() !== $clientId
            || $consumedCode->getRedirectUri() !== $redirectUri) {
            throw new SaTokenException('无效的授权码');
        }

        return $this->generateAccessToken(
            $clientId,
            $codeData->getLoginId(),
            $scope,
            '',
            true,
            $nonce,
            false,
            'authorization_code'
        );
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
        // 同一家族的不同 RT 也必须串行处理：否则旧 RT 重放撤销家族时，
        // 并发子 RT 可能在撤销完成后继续签发并登记新访问令牌。
        $client = $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($client, 'refresh_token');

        $lockValue = bin2hex(random_bytes(16));
        $tokenLockKey = 'oauth2:refresh:token:' . hash('sha256', $refreshToken);
        $this->acquireRefreshLock($tokenLockKey, $lockValue);

        try {
            // 必须在拿到单 RT 锁后重新解析家族：若请求在前一请求消费 RT 的
            // 窗口中启动，它此时才能读到已写入的 consumed 标记并加入同一家族锁。
            $familyLockKey = 'oauth2:refresh:' . $this->getRefreshTokenFamilyLockIdentity($refreshToken);
            $this->acquireRefreshLock($familyLockKey, $lockValue);
            try {
                return $this->refreshTokenUnlocked($refreshToken, $clientId, $clientSecret);
            } finally {
                $this->releaseRefreshLock($familyLockKey, $lockValue);
            }
        } finally {
            $this->releaseRefreshLock($tokenLockKey, $lockValue);
        }
    }

    protected function acquireRefreshLock(string $lockKey, string $lockValue): void
    {
        $dao = $this->getDao();
        for ($attempt = 0; $attempt <= 100; $attempt++) {
            if (\SaToken\Dao\SaTokenDaoLock::acquire($dao, $lockKey, $lockValue, 120)) {
                return;
            }
            if ($attempt < 100) {
                usleep(10000);
            }
        }

        throw new SaTokenException('刷新令牌正在处理中，请重试');
    }

    protected function releaseRefreshLock(string $lockKey, string $lockValue): void
    {
        $dao = $this->getDao();
        \SaToken\Dao\SaTokenDaoLock::release($dao, $lockKey, $lockValue);
    }

    /**
     * 获取刷新锁身份；家族 RT 共用同一把锁，旧版无家族数据时退回单 RT 锁。
     */
    protected function getRefreshTokenFamilyLockIdentity(string $refreshToken): string
    {
        $tokenHash = hash('sha256', $refreshToken);
        $consumedFamily = $this->getConsumedRefreshFamily($refreshToken);
        if (is_string($consumedFamily) && $consumedFamily !== '') {
            return 'family:' . hash('sha256', $consumedFamily);
        }

        $json = $this->getDao()->get($this->buildRefreshTokenKey($refreshToken));
        if ($json !== null) {
            $data = SaFoxUtil::fromJson($this->decryptValue($json));
            if (is_array($data)
                && is_string($data['familyId'] ?? null)
                && $data['familyId'] !== '') {
                return 'family:' . hash('sha256', $data['familyId']);
            }
        }

        return 'legacy:' . $tokenHash;
    }

    protected function refreshTokenUnlocked(string $refreshToken, string $clientId, string $clientSecret): SaOAuth2AccessToken
    {
        $client = $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($client, 'refresh_token');

        $rtKey = $this->buildRefreshTokenKey($refreshToken);
        // Keep replay evidence for at least as long as either the descendant
        // access token or its refresh token can remain valid.
        $markerTimeout = max(
            1,
            $this->config->getAccessTokenTimeout(),
            $this->config->getRefreshTokenTimeout()
        );

        // 消费前预读取：scope 收紧等配置变更时，让失败发生在 RT 被消费之前，
        // 避免客户端因运维操作被迫整体重新授权
        $preJson = $this->getDao()->get($rtKey);
        $preRtData = null;
        if ($preJson !== null) {
            $preData = SaFoxUtil::fromJson($this->decryptValue($preJson));
            if (is_array($preData)) {
                /** @var array<string, mixed> $preData */
                if (($preData['_state'] ?? null) === 'consumed') {
                    $refreshTokenHash = is_string($preData['refreshTokenHash'] ?? null)
                        ? $preData['refreshTokenHash']
                        : '';
                    if ($refreshTokenHash === '' || !hash_equals(hash('sha256', $refreshToken), $refreshTokenHash)) {
                        throw new SaTokenException('刷新令牌消费记录与凭据不匹配');
                    }
                    $familyId = is_string($preData['familyId'] ?? null) ? $preData['familyId'] : '';
                    $consumedClientId = is_string($preData['clientId'] ?? null) ? $preData['clientId'] : '';
                    if ($familyId === '' || $consumedClientId === '') {
                        throw new SaTokenException('刷新令牌客户端绑定无效');
                    }
                    if ($consumedClientId !== $clientId) {
                        throw new SaTokenException('客户端 ID 不匹配');
                    }
                    $this->rejectConsumedRefreshTokenReplay(
                        $clientId,
                        $familyId,
                        'oauth2:rt:consumed:' . hash('sha256', $refreshToken)
                    );
                }
                if (!is_string($preData['refreshToken'] ?? null)
                    || !hash_equals($refreshToken, $preData['refreshToken'])) {
                    throw new SaTokenException('刷新令牌存储记录与凭据不匹配');
                }
                if (!$this->isRefreshTokenRecordValid($preData)) {
                    throw new SaTokenException('刷新令牌数据无效或已过期');
                }
                $preRtData = new SaOAuth2RefreshToken($preData);
                $markerTimeout = $this->extendTokenFamilyMarkerTimeout($markerTimeout, $preData);
                $preClientId = is_string($preData['clientId'] ?? null) ? $preData['clientId'] : '';
                if ($preClientId !== '' && $preClientId !== $clientId) {
                    throw new SaTokenException('客户端 ID 不匹配');
                }
                $preScope = is_string($preData['scope'] ?? null) ? $preData['scope'] : '';
                try {
                    $preScope = $this->validateScopeForClient($client, $preScope);
                    $preRtData->setScope($preScope);
                } catch (SaTokenException $e) {
                    throw new SaTokenException('刷新令牌的 scope 已不在客户端授权范围内：' . $e->getMessage());
                }
            }
        }

        // 重用检测：familyId 贯穿整条刷新链，重放链上任一 RT 即撤销整个家族
        $familyMarkerPrefix = 'oauth2:family:';
        $preFamilyId = null;
        if ($preRtData !== null && $preRtData->getFamilyId() !== '') {
            $preFamilyId = $preRtData->getFamilyId();
            if ($this->isTokenFamilyRevoked($preFamilyId)) {
                throw new SaTokenException('刷新令牌家族已撤销');
            }
        }

        $rtData = $preRtData;
        $familyId = $preRtData?->getFamilyId() ?? '';

        // 消费标记（RT 哈希 -> familyId）是重放判定的唯一权威：
        // RT 记录本身消费后即删除，标记独立存在使重放请求仍能定位家族并触发整体撤销
        $consumedKey = 'oauth2:rt:consumed:' . hash('sha256', $refreshToken);
        $consumedFamily = $this->getConsumedRefreshFamily($refreshToken);
        if (is_string($consumedFamily) && $consumedFamily !== '') {
            $this->rejectConsumedRefreshTokenReplay($clientId, $consumedFamily, $consumedKey);
        }

        // 旧版数据（无 familyId）回退到按 RT 哈希标记
        $legacyMarkerKey = 'oauth2:rt:used:' . hash('sha256', $refreshToken);
        $legacyMarkerJson = $this->getDao()->get($legacyMarkerKey);
        if ($legacyMarkerJson !== null) {
            $this->revokeLegacyMarkerTokens($legacyMarkerKey);
            throw new SaTokenException('刷新令牌已被使用，检测到可能的令牌泄露，相关令牌已全部撤销');
        }

        if ($preJson === null || $rtData === null) {
            throw new SaTokenException('无效的刷新令牌');
        }

        // 将旧版无 familyId 的 RT 在首次轮换时迁移进家族模型。
        // 后续重放依靠与 RT 同键的 tombstone 找到此家族，避免消费与标记
        // 分成两次写入时出现可绕过的暂停窗口。
        if ($familyId === '') {
            $familyId = SaFoxUtil::randomString(32);
        }

        $familyMarkerKey = $familyMarkerPrefix . hash('sha256', $familyId);
        $familyMarkerSeed = $this->encryptValueForContext(SaFoxUtil::toJson([
            'tokens'    => [],
            'childRts'  => [],
            'clientId'  => $rtData->getClientId(),
            'familyId'  => $familyId,
            'revokedAt' => time(),
        ]), $familyMarkerKey);
        $this->getDao()->setIfNotExists($familyMarkerKey, $familyMarkerSeed, $markerTimeout);
        $familyMarkerJson = $this->getDao()->get($familyMarkerKey);
        $familyMarker = $familyMarkerJson !== null
            ? SaFoxUtil::fromJson($this->decryptValueForContext($familyMarkerJson, $familyMarkerKey) ?? '')
            : null;
        if (!is_array($familyMarker)
            || !is_string($familyMarker['clientId'] ?? null)
            || $familyMarker['clientId'] !== $rtData->getClientId()
            || !is_string($familyMarker['familyId'] ?? null)
            || $familyMarker['familyId'] !== $familyId) {
            throw new SaTokenException('刷新令牌客户端绑定无效');
        }
        if (($familyMarker['revoked'] ?? false) === true) {
            throw new SaTokenException('刷新令牌家族已撤销');
        }

        // Record the currently valid access token before consumption so a
        // replay that observes the tombstone can revoke it immediately.
        if ($rtData->getAccessToken() !== '') {
            $this->updateTokenFamilyCurrentDescendants($familyMarkerKey, $rtData->getAccessToken(), '', $markerTimeout);
        }

        $dao = $this->getDao();
        if (!$dao instanceof SaTokenDaoCompareAndUpdateInterface) {
            throw new SaTokenException('DAO 不支持刷新令牌的原子消费');
        }
        $consumedRecord = $this->encryptValue(SaFoxUtil::toJson([
            '_state'          => 'consumed',
            'refreshTokenHash' => hash('sha256', $refreshToken),
            'familyId'        => $familyId,
            'clientId'        => $rtData->getClientId(),
        ]));
        if (!$dao->compareAndUpdate($rtKey, $preJson, $consumedRecord)) {
            // Another lock owner may have consumed this token after its lease
            // expired. The same-key tombstone is authoritative even before
            // the compatibility consumed-key index is written.
            $latestJson = $dao->get($rtKey);
            $latest = $latestJson !== null ? SaFoxUtil::fromJson($this->decryptValue($latestJson)) : null;
            if (is_array($latest) && ($latest['_state'] ?? null) === 'consumed'
                && is_string($latest['refreshTokenHash'] ?? null)
                && hash_equals(hash('sha256', $refreshToken), $latest['refreshTokenHash'])
                && is_string($latest['familyId'] ?? null) && $latest['familyId'] !== '') {
                if (($latest['clientId'] ?? null) !== $clientId) {
                    throw new SaTokenException('客户端 ID 不匹配');
                }
                $this->rejectConsumedRefreshTokenReplay($clientId, $latest['familyId'], $consumedKey);
            }
            $latestConsumedFamily = $this->getConsumedRefreshFamily($refreshToken);
            if (is_string($latestConsumedFamily) && $latestConsumedFamily !== '') {
                $this->rejectConsumedRefreshTokenReplay($clientId, $latestConsumedFamily, $consumedKey);
            }
            throw new SaTokenException('刷新令牌状态已变更，拒绝刷新');
        }
        $dao->set($consumedKey, $this->encryptValueForContext($familyId, $consumedKey), $markerTimeout);
        if ($this->isTokenFamilyRevoked($familyId)) {
            throw new SaTokenException('刷新令牌家族已撤销');
        }

        if ($rtData->getClientId() !== $clientId) {
            throw new SaTokenException('客户端 ID 不匹配');
        }

        // 撤销旧访问令牌（若仍存在）
        if ($rtData->getAccessToken() !== '') {
            $this->getDao()->delete($this->buildAccessTokenKey($rtData->getAccessToken()));
        }

        // 刷新时先签发不带 RT 的访问令牌，随后按轮换配置创建唯一 RT 并与 AT 一起持久化。
        $accessToken = $this->generateAccessToken(
            $clientId,
            $rtData->getLoginId(),
            $rtData->getScope(),
            $familyId,
            false,
            '',
            false,
            'refresh_token'
        );
        $newRefreshTokenValue = '';
        if ($this->config->isNewRefreshToken() && $this->config->getRefreshTokenTimeout() > 0) {
            $newRefreshToken = $this->createRefreshToken(
                $clientId,
                $rtData->getLoginId(),
                $accessToken->getAccessToken(),
                $rtData->getScope(),
                $familyId
            );
            $newRefreshTokenValue = $newRefreshToken->getRefreshToken();
            $accessToken->setRefreshToken($newRefreshTokenValue);
            $this->getDao()->set(
                $this->buildAccessTokenKey($accessToken->getAccessToken()),
                $this->encryptValue(SaFoxUtil::toJson($accessToken->toArray())),
                $accessToken->getExpiresIn()
            );
        }

        // 将新签发的 AT/RT 登记进家族标记，重用检测时一并撤销
        if ($familyId !== '') {
            $this->updateTokenFamilyCurrentDescendants(
                'oauth2:family:' . hash('sha256', $familyId),
                $accessToken->getAccessToken(),
                $newRefreshTokenValue,
                $markerTimeout
            );
        }

        return $accessToken;
    }

    /**
     * Validate persisted expiry metadata instead of trusting the DAO TTL alone.
     * @param array<string, mixed> $data
     */
    protected function isRefreshTokenRecordValid(array $data): bool
    {
        if (!is_int($data['createTime'] ?? null) || !is_int($data['expiresIn'] ?? null)) {
            return false;
        }

        return !(new SaOAuth2RefreshToken($data))->isExpired();
    }

    /**
     * Revoke the token family after a refresh-token replay and always fail the request.
     */
    protected function rejectConsumedRefreshTokenReplay(string $clientId, string $familyId, string $consumedKey): never
    {
        $familyMarkerKey = 'oauth2:family:' . hash('sha256', $familyId);
        $familyMarkerJson = $this->getDao()->get($familyMarkerKey);
        $familyMarker = $familyMarkerJson !== null
            ? SaFoxUtil::fromJson($this->decryptValueForContext($familyMarkerJson, $familyMarkerKey) ?? '')
            : null;
        if (!is_array($familyMarker)
            || !is_string($familyMarker['clientId'] ?? null)
            || $familyMarker['clientId'] === '') {
            throw new SaTokenException('刷新令牌客户端绑定无效');
        }
        if ($familyMarker['clientId'] !== $clientId) {
            throw new SaTokenException('客户端 ID 不匹配');
        }
        $this->revokeTokenFamily($familyMarkerKey);
        $this->getDao()->delete($consumedKey);
        throw new SaTokenException('刷新令牌已被使用，检测到可能的令牌泄露，相关令牌已全部撤销');
    }

    /**
     * 撤销整个令牌家族：删除标记中记录的全部 AT 及其配对 RT、派生 RT
     */
    protected function revokeTokenFamily(string $familyMarkerKey): void
    {
        $dao = $this->getDao();
        if (!$dao instanceof SaTokenDaoCompareAndSetInterface) {
            throw new SaTokenException('DAO 不支持 OAuth2 令牌家族的原子撤销');
        }

        // A family lock is a lease, so a paused refresh may resume after the
        // lock expires and replace the marker with a newly registered child.
        // Never write a revoked state from an old snapshot: retry against the
        // latest marker so every descendant is included in cleanup.
        $marker = null;
        $tokens = [];
        $childRts = [];
        $revokedMarkerJson = '';
        $updated = false;
        for ($attempt = 0; $attempt < 8; $attempt++) {
            $markerJson = $dao->get($familyMarkerKey);
            if ($markerJson === null) {
                return;
            }
            $marker = SaFoxUtil::fromJson($this->decryptValueForContext($markerJson, $familyMarkerKey) ?? '');
            if (!is_array($marker)) {
                return;
            }
            if (($marker['revoked'] ?? false) === true) {
                return;
            }

            $tokens = is_array($marker['tokens'] ?? null) ? $marker['tokens'] : [];
            $childRts = is_array($marker['childRts'] ?? null) ? $marker['childRts'] : [];

            // Refresh locks are leases. Keep a tombstone for the maximum
            // lifetime of family credentials so a paused lock owner cannot
            // resurrect them. compareAndSet changes the state and TTL in one
            // atomic operation, preventing stale snapshots from winning.
            $marker['revoked'] = true;
            $marker['revokedAt'] = time();
            $revokedMarkerJson = $this->encryptValueForContext(SaFoxUtil::toJson($marker), $familyMarkerKey);
            if ($dao->compareAndSet(
                $familyMarkerKey,
                $markerJson,
                $revokedMarkerJson,
                $this->getTokenFamilyMarkerTimeout($tokens, $childRts)
            )) {
                $updated = true;
                break;
            }
        }

        if (!$updated) {
            throw new SaTokenException('OAuth2 令牌家族状态持续变化，撤销失败，请重试');
        }

        foreach ($tokens as $familyToken) {
            if (is_string($familyToken) && $familyToken !== '') {
                $this->revokeAccessTokenUnlocked($familyToken);
            }
        }
        $rtKeys = [];
        foreach ($childRts as $childRt) {
            if (is_string($childRt) && $childRt !== '') {
                $rtKeys[] = $this->buildRefreshTokenKey($childRt);
            }
        }
        if ($rtKeys !== []) {
            $this->getDao()->deleteMultiple($rtKeys);
        }
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
                    $this->revokeAccessTokenUnlocked($familyToken);
                }
            }
        }
    }

    protected function updateTokenFamilyCurrentDescendants(string $familyMarkerKey, string $accessToken, string $childRefreshToken, ?int $markerTimeout): void
    {
        $markerJson = $this->getDao()->get($familyMarkerKey);
        if ($markerJson === null) {
            return;
        }
        $marker = SaFoxUtil::fromJson($this->decryptValueForContext($markerJson, $familyMarkerKey) ?? '');
        if (!is_array($marker)) {
            return;
        }
        if (($marker['revoked'] ?? false) === true) {
            // The refresh lock lease may have expired while this request was
            // paused. Do not attach its newly written credentials to a revoked
            // family, and remove them before returning.
            $this->revokeAccessTokenUnlocked($accessToken);
            $this->getDao()->delete($this->buildAccessTokenFamilyKey($accessToken));
            if ($childRefreshToken !== '') {
                $this->getDao()->delete($this->buildRefreshTokenKey($childRefreshToken));
            }
            throw new SaTokenException('刷新令牌家族已撤销');
        }
        // Refresh rotation has a single active descendant: the previous AT is
        // deleted before its replacement is registered, and the consumed RT is
        // already unavailable. Keeping history here makes an active family grow
        // without bound; consumed-RT markers retain replay detection separately.
        $tokens = [$accessToken];
        $childRts = $childRefreshToken !== '' ? [$childRefreshToken] : [];
        $newMarkerJson = $this->encryptValueForContext(SaFoxUtil::toJson([
            'tokens'    => $tokens,
            'childRts'  => $childRts,
            'clientId'  => is_string($marker['clientId'] ?? null) ? $marker['clientId'] : '',
            'familyId'  => is_string($marker['familyId'] ?? null) ? $marker['familyId'] : '',
            'revokedAt' => $marker['revokedAt'] ?? time(),
            'revoked'   => false,
        ]), $familyMarkerKey);
        $dao = $this->getDao();
        if (!$dao instanceof SaTokenDaoCompareAndUpdateInterface
            || !$dao instanceof SaTokenDaoCompareAndExpireInterface
            || !$dao->compareAndUpdate($familyMarkerKey, $markerJson, $newMarkerJson)
            || !$dao->compareAndExpire($familyMarkerKey, $newMarkerJson, $markerTimeout ?? -1)) {
            // Never overwrite a marker changed by a newer owner after our lock
            // lease expired. The issued credentials are not safe to keep.
            $this->revokeAccessTokenUnlocked($accessToken);
            $this->getDao()->delete($this->buildAccessTokenFamilyKey($accessToken));
            if ($childRefreshToken !== '') {
                $this->getDao()->delete($this->buildRefreshTokenKey($childRefreshToken));
            }
            throw new SaTokenException('刷新令牌家族状态已变更，拒绝签发令牌');
        }
    }

    protected function isTokenFamilyRevoked(string $familyId): bool
    {
        $markerJson = $this->getDao()->get('oauth2:family:' . hash('sha256', $familyId));
        if ($markerJson === null) {
            return false;
        }
        $key = 'oauth2:family:' . hash('sha256', $familyId);
        $marker = SaFoxUtil::fromJson($this->decryptValueForContext($markerJson, $key) ?? '');
        return is_array($marker) && ($marker['revoked'] ?? false) === true;
    }

    /** @param array<mixed> $tokens
     * @param array<mixed> $childRefreshTokens
     */
    protected function getTokenFamilyMarkerTimeout(array $tokens, array $childRefreshTokens): ?int
    {
        $timeout = max(1, $this->config->getAccessTokenTimeout(), $this->config->getRefreshTokenTimeout());
        $now = time();
        foreach ($tokens as $token) {
            if (!is_string($token) || $token === '') {
                continue;
            }
            $json = $this->getDao()->get($this->buildAccessTokenKey($token));
            $data = $json !== null ? SaFoxUtil::fromJson($this->decryptValue($json)) : null;
            if (is_array($data)) {
                $expiresIn = $data['expiresIn'] ?? null;
                $createTime = $data['createTime'] ?? null;
                if (!is_int($expiresIn) || !is_int($createTime)) {
                    continue;
                }
                if ($expiresIn === -1) {
                    return null;
                }
                if ($expiresIn > 0 && $createTime > 0 && $createTime <= PHP_INT_MAX - $expiresIn - 60) {
                    $timeout = max($timeout, $createTime + $expiresIn - $now);
                }
            }
        }
        foreach ($childRefreshTokens as $token) {
            if (!is_string($token) || $token === '') {
                continue;
            }
            $json = $this->getDao()->get($this->buildRefreshTokenKey($token));
            $data = $json !== null ? SaFoxUtil::fromJson($this->decryptValue($json)) : null;
            if (is_array($data)) {
                $expiresIn = $data['expiresIn'] ?? null;
                $createTime = $data['createTime'] ?? null;
                if (!is_int($expiresIn) || !is_int($createTime)) {
                    continue;
                }
                if ($expiresIn === -1) {
                    return null;
                }
                if ($expiresIn > 0 && $createTime > 0 && $createTime <= PHP_INT_MAX - $expiresIn - 60) {
                    $timeout = max($timeout, $createTime + $expiresIn - $now);
                }
            }
        }

        return max(1, $timeout);
    }

    /** @param array<string, mixed> $record */
    protected function extendTokenFamilyMarkerTimeout(?int $timeout, array $record): ?int
    {
        $expiresIn = $record['expiresIn'] ?? null;
        $createTime = $record['createTime'] ?? null;
        if ($expiresIn === -1) {
            return null;
        }
        if (!is_int($expiresIn) || !is_int($createTime)
            || $expiresIn <= 0
            || $createTime <= 0
            || $createTime > PHP_INT_MAX - $expiresIn - 60) {
            return $timeout;
        }

        $remaining = max(1, $createTime + $expiresIn - time());
        return $timeout === null ? null : max($timeout, $remaining);
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

        // Resource Owner Password Credentials is not an OpenID Connect flow.
        // Do not let a direct password exchange mint an ID Token that clients
        // could mistake for an OIDC authentication response.
        if ($this->config->isOpenIdMode() && $this->scopeContainsOpenid($scope)) {
            throw new SaTokenException('OpenID Connect 不支持密码授权请求 openid scope');
        }

        $client = $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($client, 'password');

        // 密码模式是暴露在公网的用户凭据验证端点，必须接入防暴力锁定：
        // 同一来源 IP 连续失败达到 antiBruteMaxFailures 后临时锁定（原子计数）
        SaAntiBruteUtil::checkAndThrow($username);

        // 用户验证由外部回调处理
        try {
            $loginId = $this->validateUserCredentials($username, $password);
        } catch (\Throwable $exception) {
            // Validator callbacks may signal rejected credentials by throwing.
            // Count those failures too, otherwise callers can bypass brute-force
            // protection simply by using an exception-based validator.
            SaAntiBruteUtil::recordFailure($username);
            throw $exception;
        }
        if ($loginId === null || is_bool($loginId) || !is_scalar($loginId) || $loginId === '') {
            SaAntiBruteUtil::recordFailure($username);
            throw new SaTokenException('用户名或密码错误');
        }

        // 凭据验证回调可能耗时或触发客户端配置更新；签发前重新确认
        // 当前密钥和授权策略，避免已轮换的密钥继续完成在途认证。
        $client = $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($client, 'password');
        $scope = $this->validateScopeForClient($client, $scope);

        $accessToken = $this->generateAccessToken($clientId, $loginId, $scope, '', true, '', false, 'password');
        SaAntiBruteUtil::clearCurrentSourceFailures($username);

        return $accessToken;
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
        $scope = $this->validateScopeForClient($client, $scope);
        if ($this->scopeContainsOpenid($scope)) {
            throw new SaTokenException('client_credentials 不允许请求 openid scope');
        }

        // Client configuration lives in the shared DAO and may be rotated
        // while this request validates scope. Recheck credentials and policy
        // immediately before issuing a token, as the password grant does.
        $currentClient = $this->validateClientWithSecret($clientId, $clientSecret);
        $this->validateGrantTypeForClient($currentClient, 'client_credentials');
        $scope = $this->validateScopeForClient($currentClient, $scope);
        if ($this->scopeContainsOpenid($scope)) {
            throw new SaTokenException('client_credentials 不允许请求 openid scope');
        }

        // Client credentials authenticate the client, not a resource owner;
        // they therefore cannot issue refresh credentials for later delegation.
        return $this->generateAccessToken($clientId, 'client:' . $clientId, $scope, '', false, '', false, 'client_credentials');
    }

    public function isOpenIdMode(): bool
    {
        return $this->config->isOpenIdMode();
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
        if (!hash_equals($accessToken, $tokenData->getAccessToken())) {
            return null;
        }
        if ($tokenData->isExpired()) {
            $this->getDao()->delete($this->buildAccessTokenKey($accessToken));
            return null;
        }
        $familyId = $this->getAccessTokenFamilyId($accessToken);
        if (is_string($familyId) && $familyId !== '' && $this->isTokenFamilyRevoked($familyId)) {
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
        $accessTokenKey = $this->buildAccessTokenKey($accessToken);
        $json = $this->getDao()->get($accessTokenKey);
        $data = $json !== null ? SaFoxUtil::fromJson($this->decryptValue($json)) : null;
        $refreshToken = is_array($data) && is_string($data['refreshToken'] ?? null) ? $data['refreshToken'] : '';

        if ($refreshToken === '') {
            $familyId = $this->getAccessTokenFamilyId($accessToken);
            if (!is_string($familyId) || $familyId === '') {
                $this->getDao()->delete($accessTokenKey);
                return;
            }

            // The old AT is removed during rotation. Its short-lived family
            // index preserves the revocation link after that point.
            $lockValue = bin2hex(random_bytes(16));
            $familyLockKey = 'oauth2:refresh:family:' . hash('sha256', $familyId);
            $this->acquireRefreshLock($familyLockKey, $lockValue);
            try {
                $this->revokeTokenFamily('oauth2:family:' . hash('sha256', $familyId));
                $this->getDao()->delete($accessTokenKey);
            } finally {
                $this->releaseRefreshLock($familyLockKey, $lockValue);
            }
            return;
        }

        // Serialize revocation with rotation. If rotation already consumed this
        // RT, its marker identifies the family whose new descendants must also
        // be revoked; if revocation wins first, refresh can no longer consume it.
        $lockValue = bin2hex(random_bytes(16));
        $tokenLockKey = 'oauth2:refresh:token:' . hash('sha256', $refreshToken);
        $this->acquireRefreshLock($tokenLockKey, $lockValue);

        try {
            $familyId = $this->getAccessTokenFamilyId($accessToken);
            if (!is_string($familyId) || $familyId === '') {
                $familyLockKey = 'oauth2:refresh:' . $this->getRefreshTokenFamilyLockIdentity($refreshToken);
            } else {
                $familyLockKey = 'oauth2:refresh:family:' . hash('sha256', $familyId);
            }
            $this->acquireRefreshLock($familyLockKey, $lockValue);
            try {
                $consumedFamily = $this->getConsumedRefreshFamily($refreshToken);
                if ((!is_string($consumedFamily) || $consumedFamily === '') && is_string($familyId) && $familyId !== '') {
                    $consumedFamily = $familyId;
                }
                if (is_string($consumedFamily) && $consumedFamily !== '') {
                    $familyMarkerKey = 'oauth2:family:' . hash('sha256', $consumedFamily);
                    $this->revokeTokenFamily($familyMarkerKey);
                }

                $this->revokeAccessTokenUnlocked($accessToken);
            } finally {
                $this->releaseRefreshLock($familyLockKey, $lockValue);
            }
        } finally {
            $this->releaseRefreshLock($tokenLockKey, $lockValue);
        }
    }

    /** Remove an access token and its paired refresh token without acquiring locks. */
    protected function revokeAccessTokenUnlocked(string $accessToken): void
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

    /**
     * 校验公开策略使用的授权模式，遵循客户端白名单或全局默认白名单。
     *
     * @throws SaTokenException
     */
    public function validateGrantTypePublic(string $clientId, string $grantType): void
    {
        $this->validateGrantTypeForClient($this->validateClient($clientId), $grantType);
    }

    public function validateScopePublic(string $clientId, string $scope): string
    {
        return $this->validateScopeForClient($this->validateClient($clientId), $scope);
    }

    public function checkScope(string $accessToken, string $requiredScope): bool
    {
        if ($requiredScope === '' || trim($requiredScope) !== $requiredScope || preg_match('/\s/', $requiredScope) === 1) {
            return false;
        }

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
    public function generateAccessToken(
        string $clientId,
        mixed $loginId,
        string $scope = '',
        string $refreshFamilyId = '',
        bool $includeRefreshToken = true,
        string $idTokenNonce = '',
        bool $includeAtHash = false,
        ?string $grantType = null
    ): SaOAuth2AccessToken {
        $client = $this->validateClient($clientId);
        if ($grantType === null || $grantType === '') {
            throw new SaTokenException('访问令牌签发必须明确指定授权类型');
        }
        $this->validateGrantTypeForClient($client, $grantType);
        $scope = $this->validateScopeForClient($client, $scope);
        $this->validateOidcNonce($idTokenNonce);
        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }
        if ($this->config->isOpenIdMode() && $this->scopeContainsOpenid($scope)) {
            $this->validateIdTokenIssuer();
        }
        if ($includeAtHash && (!$this->config->isOpenIdMode() || !$this->scopeContainsOpenid($scope) || $idTokenNonce === '')) {
            throw new SaTokenException('OpenID Connect 隐式授权必须包含 openid scope 和 nonce');
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
        if ($includeRefreshToken && $this->config->getRefreshTokenTimeout() > 0) {
            $refreshToken = $this->createRefreshToken($clientId, $loginId, $tokenStr, $scope, $refreshFamilyId);
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
            $idTokenObj = $this->generateIdToken(
                $clientId,
                $loginId,
                $scope,
                $idTokenNonce,
                $includeAtHash ? $tokenStr : ''
            );
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
        $accessTokenTimeout = $this->config->getAccessTokenTimeout();
        $familyKey = $this->buildAccessTokenFamilyKey($accessToken);
        $this->getDao()->set(
            $familyKey,
            $this->encryptValueForContext($refreshToken->getFamilyId(), $familyKey),
            $accessTokenTimeout > 0 ? $accessTokenTimeout : null
        );

        return $refreshToken;
    }

    /**
     * 获取授权码数据
     */
    protected function getAuthorizationCode(string $code): ?SaOAuth2AuthorizationCode
    {
        $key = $this->buildCodeKey($code);
        $json = $this->getDao()->get($key);
        if ($json === null) {
            return null;
        }

        $data = SaFoxUtil::fromJson($this->decryptValueForContext($json, $key) ?? '');
        if (!is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        if (!is_string($data['code'] ?? null) || !hash_equals($code, $data['code'])) {
            return null;
        }
        return new SaOAuth2AuthorizationCode($data);
    }

    protected function consumeAuthorizationCode(string $code): ?SaOAuth2AuthorizationCode
    {
        $dao = $this->getDao();
        if (!$dao instanceof \SaToken\Dao\SaTokenDaoCompareAndDeleteInterface) {
            throw new SaTokenException('DAO 不支持授权码的原子消费');
        }
        $key = $this->buildCodeKey($code);
        $json = $dao->get($key);
        if ($json === null) {
            return null;
        }

        $data = SaFoxUtil::fromJson($this->decryptValueForContext($json, $key) ?? '');
        if (!is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        if (!is_string($data['code'] ?? null) || !hash_equals($code, $data['code'])
            || !$dao->compareAndDelete($key, $json)) {
            return null;
        }
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
        if (!is_string($data['refreshToken'] ?? null)
            || !hash_equals($refreshToken, $data['refreshToken'])) {
            return null;
        }
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
        $storedSecret = $client->getClientSecret();
        if (trim($storedSecret) === '' || strlen($storedSecret) < 32) {
            throw new SaTokenException('客户端密钥长度不足，至少需要 32 字节');
        }
        if ($clientSecret === '' || !hash_equals($storedSecret, $clientSecret)) {
            $this->recordClientFailure($clientId);
            throw new SaTokenException('客户端密钥错误');
        }
        $this->clearClientFailures($clientId);
        return $client;
    }

    /**
     * 校验请求 scope 是客户端注册 scopes 的子集。
     * 未配置 scope 白名单的客户端只能请求空 scope，防止客户端自行声明权限。
     */
    protected function validateScopeForClient(SaOAuth2Client $client, string $scope): string
    {
        if ($scope === '') {
            return '';
        }
        if (strlen($scope) > self::MAX_SCOPE_LENGTH) {
            throw new SaTokenException('scope 长度不能超过 ' . self::MAX_SCOPE_LENGTH . ' 字节');
        }
        if (trim($scope) === '') {
            throw new SaTokenException('scope 不能只包含空白字符');
        }
        $registered = $client->getScopes();
        if ($registered === []) {
            throw new SaTokenException('客户端未配置 scope 白名单，不能请求非空 scope');
        }
        $requested = preg_split('/\s+/', trim($scope)) ?: [];
        $normalized = [];
        $seen = [];
        foreach ($requested as $item) {
            if ($item !== '' && !in_array($item, $registered, true)) {
                throw new SaTokenException('请求了未授予的 scope');
            }
            if ($item !== '' && !isset($seen[$item])) {
                $seen[$item] = true;
                $normalized[] = $item;
            }
        }

        return implode(' ', $normalized);
    }

    protected function validateOidcNonce(string $nonce): void
    {
        if (strlen($nonce) > self::MAX_OIDC_NONCE_LENGTH) {
            throw new SaTokenException('OIDC nonce 长度不能超过 ' . self::MAX_OIDC_NONCE_LENGTH . ' 字节');
        }
    }

    /**
     * 校验全局和客户端都允许使用该 grant_type。
     * 客户端未注册 grantTypes 时继承全局配置；全局配置仍是管理员的
     * 最终开关，便于紧急关闭某种授权模式。
     */
    protected function validateGrantTypeForClient(SaOAuth2Client $client, string $grantType): void
    {
        if (!in_array($grantType, $this->config->getGrantTypes(), true)) {
            $message = $grantType === 'implicit'
                ? '该授权模式未被授权使用此授权模式（全局配置未启用）'
                : '该授权模式未被授权（全局配置未启用）';
            throw new SaTokenException($message);
        }

        if ($client->getClientSecret() === '' && $grantType !== 'authorization_code') {
            throw new SaTokenException('公开客户端只允许使用授权码模式并强制 PKCE');
        }

        $allowed = $client->getGrantTypes();
        $allowed = $allowed === [] ? $this->config->getGrantTypes() : $allowed;
        if (!in_array($grantType, $allowed, true)) {
            throw new SaTokenException('该客户端未被授权使用此授权模式');
        }
    }

    protected function clientFailureKey(string $clientId): ?string
    {
        // client_id 是公开信息；仅按客户端全局锁定会让任意未认证请求者
        // 通过提交错误密钥阻断该客户端的合法流量。来源 IP 遵循可信代理配置；
        // 未能解析来源时跳过本地锁定，避免所有请求共用 unknown 桶而形成全局 DoS。
        $clientIp = SaTokenContext::getClientIp();
        if ($clientIp === null || $clientIp === '') {
            return null;
        }

        return 'oauth2:client:fail:' . hash('sha256', $clientId . "\0" . $clientIp);
    }

    protected function checkClientNotLocked(string $clientId): void
    {
        $max = $this->config->getClientSecretMaxFailures();
        if ($max <= 0) {
            return;
        }
        $key = $this->clientFailureKey($clientId);
        if ($key === null) {
            return;
        }
        $count = $this->getDao()->get($key);
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
        $key = $this->clientFailureKey($clientId);
        if ($key !== null) {
            $this->getDao()->increment($key, 1, $window > 0 ? $window : 300);
        }
    }

    protected function clearClientFailures(string $clientId): void
    {
        $key = $this->clientFailureKey($clientId);
        if ($key !== null) {
            $this->getDao()->delete($key);
        }
    }

    /**
     * 验证回调地址（fail-closed：客户端不存在、地址为空、未注册列表为空均拒绝）
     */
    protected function validateRedirectUri(string $clientId, string $redirectUri): void
    {
        $this->validateRedirectUriForClient($this->validateClient($clientId), $redirectUri);
    }

    protected function validateRedirectUriForClient(SaOAuth2Client $client, string $redirectUri): void
    {
        if ($redirectUri === '') {
            throw new SaTokenException('回调地址不能为空');
        }

        // parse_url() accepts characters that browsers and HTTP clients may
        // reinterpret while resolving an authority. Keep redirect validation
        // aligned with the URL actually consumed by those clients.
        if (preg_match('/[\\\\\x00-\x20\x7f]/', $redirectUri) === 1) {
            throw new SaTokenException('回调地址包含歧义字符');
        }

        $parsed = parse_url($redirectUri);
        if ($parsed === false || !isset($parsed['scheme']) || !isset($parsed['host']) || $parsed['host'] === '') {
            throw new SaTokenException('回调地址必须是绝对 URL');
        }
        if (array_key_exists('user', $parsed) || array_key_exists('pass', $parsed) || array_key_exists('fragment', $parsed)) {
            throw new SaTokenException('回调地址不能包含用户信息或片段');
        }
        $scheme = strtolower((string) $parsed['scheme']);
        $host = strtolower((string) $parsed['host']);
        $isLocal = $host === 'localhost' || $host === '127.0.0.1' || $host === '::1';
        if (!in_array($scheme, ['https', 'http'], true) || ($scheme === 'http' && !$isLocal)) {
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
            if (array_key_exists('user', $p) || array_key_exists('pass', $p) || array_key_exists('fragment', $p)) {
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
     * @return mixed  登录 ID，验证失败返回 null 或 false
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
    public function generateIdToken(string $clientId, mixed $loginId, string $scope = '', string $nonce = '', string $accessToken = ''): SaOAuth2IdToken
    {
        $this->validateIdTokenIssuer();
        if (!$this->config->isOpenIdMode()) {
            throw new SaTokenException('生成 ID Token 必须启用 OpenID Connect 并请求 openid scope');
        }
        $client = $this->validateClient($clientId);
        $scope = $this->validateScopeForClient($client, $scope);
        if (!$this->scopeContainsOpenid($scope)) {
            throw new SaTokenException('生成 ID Token 必须启用 OpenID Connect 并请求 openid scope');
        }
        $this->validateOidcNonce($nonce);
        if ($loginId === null || $loginId === '' || is_bool($loginId) || !is_scalar($loginId)) {
            throw new SaTokenException('loginId 不能为空且必须是非布尔标量');
        }

        $now = time();
        $expiresAt = $now + $this->config->getAccessTokenTimeout();

        $loginIdStr = (string) $loginId;

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
        if ($accessToken !== '') {
            $payload['at_hash'] = $this->base64UrlEncode(substr(hash('sha256', $accessToken, true), 0, 16));
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

    /** Ensure an ID Token never carries an empty or non-HTTPS issuer identifier. */
    protected function validateIdTokenIssuer(): void
    {
        $issuer = $this->config->getIssuer();
        $parsed = parse_url($issuer);
        if ($issuer === '' || preg_match('/[\\\\\x00-\x20\x7f]/', $issuer) === 1
            || !is_array($parsed)
            || strtolower((string) ($parsed['scheme'] ?? '')) !== 'https'
            || !isset($parsed['host']) || $parsed['host'] === ''
            || array_key_exists('user', $parsed) || array_key_exists('pass', $parsed)
            || array_key_exists('query', $parsed) || array_key_exists('fragment', $parsed)) {
            throw new SaTokenException('OpenID Connect 必须配置无凭据、无查询或片段的 HTTPS issuer URL');
        }
    }

    protected function scopeContainsOpenid(string $scope): bool
    {
        if (strlen($scope) > self::MAX_SCOPE_LENGTH) {
            throw new SaTokenException('scope 长度不能超过 ' . self::MAX_SCOPE_LENGTH . ' 字节');
        }

        return preg_match('/(?:^|\s)openid(?:\s|$)/', $scope) === 1;
    }

    /**
     * @param array<string, mixed> $payload
     */
    protected function signJwt(array $payload): string
    {
        $header = [
            'typ' => 'JWT',
            'alg' => 'RS256',
        ];

        try {
            $headerJson = json_encode($header, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            $payloadJson = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new SaTokenException('OAuth2 ID Token Payload 无法编码为 JSON', 0, $exception);
        }

        $headerB64 = $this->base64UrlEncode($headerJson);
        $payloadB64 = $this->base64UrlEncode($payloadJson);
        $signingInput = $headerB64 . '.' . $payloadB64;

        $signature = (new \SaToken\Plugin\SaTokenCrypto([
            'rsaPrivateKey' => SaToken::getConfig()->getRsaPrivateKey(),
        ]))->rsaSign($signingInput);
        $signatureBin = base64_decode($signature, true);
        if ($signatureBin === false || $signatureBin === '') {
            throw new SaTokenException('JWT 签名失败');
        }

        return $signingInput . '.' . $this->base64UrlEncode($signatureBin);
    }

    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * 获取存储层
     */
    protected function getEncryptor(): SaTokenEncryptor
    {
        $config = SaToken::getConfig();
        $key = $config->getTokenEncryptKey() ?: $config->getAesKey();
        if ($config->getCryptoType() === 'sm') {
            $key = $config->getTokenEncryptKey() ?: $config->getSm4Key();
        }
        return new SaTokenEncryptor($config->isTokenEncrypt(), $key, $config->getCryptoType());
    }

    protected function encryptValue(string $value): string
    {
        return $this->getEncryptor()->encrypt($value);
    }

    protected function encryptValueForContext(string $value, string $context): string
    {
        return $this->getEncryptor()->encryptForContext($value, $context);
    }

    protected function decryptValueForContext(string $value, string $context): ?string
    {
        return $this->getEncryptor()->decryptCheckedForContext($value, $context);
    }

    protected function getAccessTokenFamilyId(string $accessToken): ?string
    {
        $key = $this->buildAccessTokenFamilyKey($accessToken);
        $value = $this->getDao()->get($key);
        if ($value === null) {
            return null;
        }
        return $this->decryptValueForContext($value, $key);
    }

    protected function getConsumedRefreshFamily(string $refreshToken): ?string
    {
        $key = 'oauth2:rt:consumed:' . hash('sha256', $refreshToken);
        $value = $this->getDao()->get($key);
        if ($value === null) {
            return null;
        }
        return $this->decryptValueForContext($value, $key);
    }

    protected function decryptValue(string $value): string
    {
        $decrypted = $this->getEncryptor()->decryptChecked($value);
        if ($decrypted === null) {
            throw new SaTokenException('OAuth2 存储数据完整性校验失败');
        }
        return $decrypted;
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

    protected function buildAccessTokenFamilyKey(string $token): string
    {
        return 'oauth2:at:family:' . hash('sha256', $token);
    }

    /**
     * 构建刷新令牌存储键
     */
    protected function buildRefreshTokenKey(string $token): string
    {
        return 'oauth2:rt:' . $token;
    }
}
