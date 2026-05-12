<?php

declare(strict_types=1);

namespace SaToken\Sso;

use CryptoSm\SM3\HmacSm3;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;

class SaSsoTemplate
{
    protected ?string $lastError = null;

    protected string $cryptoType = 'intl';

    public function __construct(?string $cryptoType = null)
    {
        $this->cryptoType = $cryptoType ?? SaToken::getConfig()->getCryptoType();
    }

    /**
     * @param array<string, string> $params
     */
    public function get(string $url, array $params = []): string
    {
        if (!empty($params)) {
            $url .= (str_contains($url, '?') ? '&' : '?') . http_build_query($params);
        }

        $response = $this->doRequest('GET', $url);
        if ($response === false || $response === '') {
            $errorMsg = $this->lastError ?? 'SSO HTTP 请求失败';
            throw new SaTokenException("SSO HTTP 请求失败：{$url} - {$errorMsg}");
        }

        return $response;
    }

    /**
     * @param array<string, string> $data
     */
    public function post(string $url, array $data = []): string
    {
        $response = $this->doRequest('POST', $url, $data);
        if ($response === false) {
            throw new SaTokenException("SSO HTTP 请求失败：{$url}" . ($this->lastError ? ' - ' . $this->lastError : ''));
        }

        return $response;
    }

    /**
     * @param  array<string, string> $params
     * @return array<string, string>
     */
    public function signParams(array $params, string $clientSecret): array
    {
        unset($params['sign']);
        ksort($params);
        $signStr = http_build_query($params) . '&key=' . $clientSecret;

        if ($this->cryptoType === 'sm') {
            $params['sign'] = HmacSm3::hmac($clientSecret, $signStr);
        } else {
            $params['sign'] = hash_hmac('sha256', $signStr, $clientSecret);
        }

        return $params;
    }

    /**
     * @param array<string, string> $params
     */
    public function verifySign(array $params, string $clientSecret): bool
    {
        $sign = $params['sign'] ?? '';
        unset($params['sign']);
        ksort($params);
        $signStr = http_build_query($params) . '&key=' . $clientSecret;

        if ($this->cryptoType === 'sm') {
            $expected = HmacSm3::hmac($clientSecret, $signStr);
        } else {
            $expected = hash_hmac('sha256', $signStr, $clientSecret);
        }

        return hash_equals($expected, $sign);
    }

    /**
     * @param array<string, string> $data
     */
    protected function doRequest(string $method, string $url, array $data = []): string|false
    {
        $this->lastError = null;
        if (function_exists('curl_init')) {
            return $this->curlRequest($method, $url, $data);
        }

        return $this->fileGetContentsRequest($method, $url, $data);
    }

    /**
     * @param array<string, string> $data
     */
    protected function curlRequest(string $method, string $url, array $data = []): string|false
    {
        $ch = curl_init();
        $nonEmptyUrl = $url !== '' ? $url : 'http://localhost';
        curl_setopt($ch, CURLOPT_URL, $nonEmptyUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            $postFields = http_build_query($data);
            if ($postFields !== '') {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
            }
        }

        /** @var string|false $response */
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false) {
            $this->lastError = 'Curl request failed';
            return false;
        }

        if ($httpCode >= 400) {
            $this->lastError = "HTTP {$httpCode}";
            return false;
        }

        return $response;
    }

    /**
     * @param array<string, string> $data
     */
    protected function fileGetContentsRequest(string $method, string $url, array $data = []): string|false
    {
        $context = [
            'http' => [
                'method'  => $method,
                'timeout' => 10,
                'header'  => 'Content-Type: application/x-www-form-urlencoded',
            ],
        ];

        if ($method === 'POST' && !empty($data)) {
            $context['http']['content'] = http_build_query($data);
        }

        $result = @file_get_contents($url, false, stream_context_create($context));
        if ($result === false) {
            $this->lastError = error_get_last()['message'] ?? 'file_get_contents failed';
        }
        return $result !== false ? $result : false;
    }
}
