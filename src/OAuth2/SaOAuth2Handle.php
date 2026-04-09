<?php

declare(strict_types=1);

namespace SaToken\OAuth2;

use SaToken\Dao\SaTokenDaoInterface;
use SaToken\Exception\SaTokenException;
use SaToken\OAuth2\Data\SaOAuth2AccessToken;
use SaToken\OAuth2\Data\SaOAuth2AuthorizationCode;
use SaToken\OAuth2\Data\SaOAuth2Client;
use SaToken\OAuth2\Data\SaOAuth2RefreshToken;
use SaToken\SaToken;
use SaToken\Util\SaFoxUtil;

/**
 * OAuth2 请求处理器
 *
 * 处理授权、令牌、资源端点请求
 */
class SaOAuth2Handle
{
    protected SaOAuth2Config $config;

    /**
     * 客户端注册表
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
    }

    /**
     * 获取客户端信息
     *
     * @param  string              $clientId 客户端 ID
     * @return SaOAuth2Client|null
     */
    public function getClient(string $clientId): ?SaOAuth2Client
    {
        return $this->clientRegistry[$clientId] ?? null;
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
            SaFoxUtil::toJson($code->toArray() + ['used' => false]),
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
        // 获取授权码
        $codeData = $this->getAuthorizationCode($code);
        if ($codeData === null) {
            throw new SaTokenException('无效的授权码');
        }

        // 验证授权码
        if ($codeData->isUsed()) {
            throw new SaTokenException('授权码已使用');
        }
        if ($codeData->isExpired()) {
            throw new SaTokenException('授权码已过期');
        }
        if ($codeData->getClientId() !== $clientId) {
            throw new SaTokenException('客户端 ID 不匹配');
        }

        // 验证客户端
        $client = $this->validateClientWithSecret($clientId, $clientSecret);

        // 验证回调地址
        if ($redirectUri !== '' && $codeData->getRedirectUri() !== $redirectUri) {
            throw new SaTokenException('回调地址不匹配');
        }

        // 标记授权码已使用
        $codeData->markUsed();
        $this->getDao()->delete($this->buildCodeKey($code));

        // 生成访问令牌
        return $this->generateAccessToken($clientId, $codeData->getLoginId(), $codeData->getScope());
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

        $data = SaFoxUtil::fromJson($json);
        if (!is_array($data)) {
            return null;
        }

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
            SaFoxUtil::toJson($accessToken->toArray()),
            $expiresIn
        );

        // 生成刷新令牌
        if ($this->config->getRefreshTokenTimeout() > 0) {
            $refreshToken = $this->createRefreshToken($clientId, $loginId, $tokenStr, $scope);
            $accessToken->setRefreshToken($refreshToken->getRefreshToken());
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
            SaFoxUtil::toJson($refreshToken->toArray()),
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

        $data = SaFoxUtil::fromJson($json);
        if (!is_array($data)) {
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

        $data = SaFoxUtil::fromJson($json);
        if (!is_array($data)) {
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
     * 获取存储层
     */
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
