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
     * @param  SaOAuth2Client $client 客户端信息
     * @return void
     */
    public function registerClient(SaOAuth2Client $client): void
    {
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
     * @param  string                    $clientId    客户端 ID
     * @param  mixed                     $loginId     资源所有者登录 ID
     * @param  string                    $redirectUri 回调地址
     * @param  string                    $scope       权限范围
     * @return SaOAuth2AuthorizationCode
     * @throws SaTokenException
     */
    public function generateAuthorizationCode(string $clientId, mixed $loginId, string $redirectUri, string $scope = ''): SaOAuth2AuthorizationCode
    {
        $this->validateClient($clientId);
        $this->validateRedirectUri($clientId, $redirectUri);

        $code = new SaOAuth2AuthorizationCode([
            'code'         => SaFoxUtil::randomString(32),
            'clientId'     => $clientId,
            'loginId'      => $loginId,
            'redirectUri'  => $redirectUri,
            'scope'        => $scope,
            'expiresIn'    => $this->config->getCodeTimeout(),
        ]);

        // 保存授权码到存储层
        $this->getDao()->set(
            $this->buildCodeKey($code->getCode()),
            $this->encryptValue(SaFoxUtil::toJson($code->toArray() + ['used' => false])),
            $this->config->getCodeTimeout()
        );

        return $code;
    }

    /**
     * 通过授权码换取访问令牌（授权码模式第二步）
     *
     * @param  string              $code         授权码
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @param  string              $redirectUri  回调地址
     * @return SaOAuth2AccessToken
     * @throws SaTokenException
     */
    public function exchangeTokenByCode(string $code, string $clientId, string $clientSecret, string $redirectUri = ''): SaOAuth2AccessToken
    {
        $codeData = $this->consumeAuthorizationCode($code);
        if ($codeData === null) {
            throw new SaTokenException('无效的授权码');
        }

        if ($codeData->isUsed()) {
            throw new SaTokenException('授权码已使用');
        }
        if ($codeData->isExpired()) {
            throw new SaTokenException('授权码已过期');
        }
        if ($codeData->getClientId() !== $clientId) {
            throw new SaTokenException('客户端 ID 不匹配');
        }

        $client = $this->validateClientWithSecret($clientId, $clientSecret);

        if ($redirectUri !== '' && $codeData->getRedirectUri() !== $redirectUri) {
            throw new SaTokenException('回调地址不匹配');
        }

        $accessToken = $this->generateAccessToken($clientId, $codeData->getLoginId(), $codeData->getScope());

        if ($this->config->isOpenIdMode() && $this->scopeContainsOpenid($codeData->getScope())) {
            $idTokenObj = $this->generateIdToken($clientId, $codeData->getLoginId(), $codeData->getScope());
            $accessToken->setIdToken($idTokenObj->getIdToken());
        }

        return $accessToken;
    }

    /**
     * 通过刷新令牌获取新的访问令牌
     *
     * @param  string              $refreshToken 刷新令牌
     * @param  string              $clientId     客户端 ID
     * @param  string              $clientSecret 客户端密钥
     * @return SaOAuth2AccessToken
     * @throws SaTokenException
     */
    public function refreshToken(string $refreshToken, string $clientId, string $clientSecret): SaOAuth2AccessToken
    {
        $this->validateClientWithSecret($clientId, $clientSecret);

        $rtData = $this->getRefreshTokenData($refreshToken);
        if ($rtData === null) {
            throw new SaTokenException('无效的刷新令牌');
        }
        if ($rtData->getClientId() !== $clientId) {
            throw new SaTokenException('客户端 ID 不匹配');
        }

        // 废弃旧的刷新令牌
        $this->getDao()->delete($this->buildRefreshTokenKey($refreshToken));

        // 生成新的访问令牌
        $accessToken = $this->generateAccessToken($clientId, $rtData->getLoginId(), $rtData->getScope());

        // 如果配置为每次生成新的刷新令牌
        if ($this->config->isNewRefreshToken()) {
            $newRefreshToken = $this->createRefreshToken($clientId, $rtData->getLoginId(), $accessToken->getAccessToken(), $rtData->getScope());
            $accessToken->setRefreshToken($newRefreshToken->getRefreshToken());
        }

        return $accessToken;
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

        $this->validateClientWithSecret($clientId, $clientSecret);

        // 用户验证由外部回调处理，此处简化
        $loginId = $this->validateUserCredentials($username, $password);
        if ($loginId === null) {
            throw new SaTokenException('用户名或密码错误');
        }

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

        $this->validateClientWithSecret($clientId, $clientSecret);

        return $this->generateAccessToken($clientId, 'client:' . $clientId, $scope);
    }

    /**
     * 验证访问令牌
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
        return new SaOAuth2AccessToken($data);
    }

    /**
     * 撤销访问令牌
     *
     * @param  string $accessToken 访问令牌
     * @return void
     */
    public function revokeAccessToken(string $accessToken): void
    {
        $this->getDao()->delete($this->buildAccessTokenKey($accessToken));
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
     */
    public function generateAccessToken(string $clientId, mixed $loginId, string $scope = ''): SaOAuth2AccessToken
    {
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

        // 保存到存储层
        $this->getDao()->set(
            $this->buildAccessTokenKey($tokenStr),
            $this->encryptValue(SaFoxUtil::toJson($accessToken->toArray())),
            $expiresIn
        );

        // 生成刷新令牌
        if ($this->config->getRefreshTokenTimeout() > 0) {
            $refreshToken = $this->createRefreshToken($clientId, $loginId, $tokenStr, $scope);
            $accessToken->setRefreshToken($refreshToken->getRefreshToken());
        }

        if ($this->config->isOpenIdMode()) {
            $idTokenObj = $this->generateIdToken($clientId, $loginId, $scope);
            $accessToken->setIdToken($idTokenObj->getIdToken());
        }

        return $accessToken;
    }

    /**
     * 创建刷新令牌
     */
    protected function createRefreshToken(string $clientId, mixed $loginId, string $accessToken, string $scope = ''): SaOAuth2RefreshToken
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
            throw new SaTokenException("未注册的客户端：{$clientId}");
        }
        return $client;
    }

    /**
     * 验证客户端（含密钥）
     */
    protected function validateClientWithSecret(string $clientId, string $clientSecret): SaOAuth2Client
    {
        $client = $this->validateClient($clientId);
        if (!hash_equals($client->getClientSecret(), $clientSecret)) {
            throw new SaTokenException('客户端密钥错误');
        }
        return $client;
    }

    /**
     * 验证回调地址
     */
    protected function validateRedirectUri(string $clientId, string $redirectUri): void
    {
        $client = $this->getClient($clientId);
        if ($client === null) {
            return;
        }

        if ($redirectUri === '') {
            return;
        }

        $parsed = parse_url($redirectUri);
        if ($parsed === false || !isset($parsed['scheme']) || !isset($parsed['host'])) {
            throw new SaTokenException('回调地址必须是绝对 URL');
        }
        if (($parsed['scheme'] ?? '') !== 'https') {
            $isLocalhost = ($parsed['host'] ?? '') === 'localhost' || ($parsed['host'] ?? '') === '127.0.0.1';
            if (!$isLocalhost) {
                throw new SaTokenException('回调地址必须使用 HTTPS 协议');
            }
        }

        $uris = $client->getRedirectUris();
        if (!empty($uris) && !in_array($redirectUri, $uris, true)) {
            throw new SaTokenException('未注册的回调地址');
        }
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
    public function generateIdToken(string $clientId, mixed $loginId, string $scope = ''): SaOAuth2IdToken
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
        ];

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
