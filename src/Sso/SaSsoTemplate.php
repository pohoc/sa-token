<?php

declare(strict_types=1);

namespace SaToken\Sso;

use CryptoSm\SM3\HmacSm3;
use SaToken\Exception\SaTokenException;
use SaToken\SaToken;

class SaSsoTemplate
{
    protected const MAX_RESPONSE_BYTES = 1_048_576;

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
            throw new SaTokenException('SSO HTTP 请求失败：' . $this->sanitizeUrlForError($url) . " - {$errorMsg}");
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
            throw new SaTokenException('SSO HTTP 请求失败：' . $this->sanitizeUrlForError($url) . ($this->lastError ? ' - ' . $this->lastError : ''));
        }

        return $response;
    }

    /**
     * @param  array<string, string> $params
     * @return array<string, string>
     */
    public function signParams(array $params, string $clientSecret): array
    {
        if (strlen($clientSecret) < 32) {
            throw new SaTokenException('SSO 客户端密钥长度不足，至少需要 32 字节');
        }
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
     * 接受外部输入的参数集（值可能为 mixed），仅标量值参与规范化。
     *
     * $maxAge 非 null 时要求 timestamp 存在且为数字，并校验时效（秒），
     * 防止合法签名在窗口外被无限重放（check-ticket/SLO 回调建议传入）
     *
     * @param array<string, mixed> $params
     */
    public function verifySign(array $params, string $clientSecret, ?int $maxAge = null): bool
    {
        if (strlen($clientSecret) < 32) {
            return false;
        }
        $ts = $params['timestamp'] ?? null;
        if ($maxAge !== null) {
            if (!is_scalar($ts) || !is_numeric($ts) || abs(time() - (int) (string) $ts) > $maxAge) {
                return false;
            }
        }
        $sign = $params['sign'] ?? '';
        unset($params['sign']);
        $normalized = [];
        foreach ($params as $k => $v) {
            // Reject values that cannot be represented by the flat signing
            // format. Silently dropping them would authenticate only a subset
            // of the request while callers may still consume the full array.
            if (!is_scalar($v)) {
                return false;
            }
            $normalized[(string) $k] = (string) $v;
        }
        ksort($normalized);
        $signStr = http_build_query($normalized) . '&key=' . $clientSecret;

        if ($this->cryptoType === 'sm') {
            $expected = HmacSm3::hmac($clientSecret, $signStr);
        } else {
            $expected = hash_hmac('sha256', $signStr, $clientSecret);
        }

        return is_string($sign) && hash_equals($expected, $sign);
    }

    /**
     * @param array<string, string> $data
     */
    protected function doRequest(string $method, string $url, array $data = []): string|false
    {
        $this->lastError = null;
        $urlParts = parse_url($url);
        $scheme = is_array($urlParts) ? strtolower((string) ($urlParts['scheme'] ?? '')) : '';
        if (!is_array($urlParts) || !isset($urlParts['host']) || $urlParts['host'] === ''
            || !in_array($scheme, ['http', 'https'], true)) {
            $this->lastError = 'Only HTTP and HTTPS URLs are allowed';
            return false;
        }

        if (function_exists('curl_init')) {
            return $this->curlRequest($method, $url, $data);
        }

        return $this->fileGetContentsRequest($method, $url, $data);
    }

    /**
     * Remove URL components that commonly carry tickets, credentials, or
     * signed parameters before including an endpoint in an exception.
     */
    protected function sanitizeUrlForError(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return '[invalid URL]';
        }

        $scheme = isset($parts['scheme']) ? $parts['scheme'] . '://' : '';
        $host = (string) ($parts['host'] ?? '');
        if (str_contains($host, ':') && !str_starts_with($host, '[')) {
            $host = '[' . $host . ']';
        }
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        $path = (string) ($parts['path'] ?? '');

        return $scheme . $host . $port . $path;
    }

    /**
     * @param array<string, string> $data
     */
    protected function curlRequest(string $method, string $url, array $data = []): string|false
    {
        $ch = curl_init();
        if ($ch === false) {
            $this->lastError = 'Unable to initialize Curl';
            return false;
        }
        $nonEmptyUrl = $url !== '' ? $url : 'http://localhost';
        curl_setopt($ch, CURLOPT_URL, $nonEmptyUrl);
        // Stream the body through a bounded callback instead of letting cURL
        // buffer an untrusted endpoint response without a memory limit.
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        // 协议白名单：即使配置被注入 file:// 等伪协议，也不会触发本地文件读取
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_HTTP);
        curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_HTTP);

        $responseBody = '';
        $responseTooLarge = false;
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($handle, string $chunk) use (&$responseBody, &$responseTooLarge): int {
            if (!$this->appendResponseChunk($responseBody, $chunk)) {
                $responseTooLarge = true;
                return 0;
            }
            return strlen($chunk);
        });

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            $postFields = http_build_query($data);
            if ($postFields !== '') {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
            }
        }

        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($responseTooLarge) {
            $this->lastError = 'SSO response exceeds the 1 MiB limit';
            return false;
        }
        if ($result === false) {
            $this->lastError = 'Curl request failed';
            return false;
        }

        if ($httpCode >= 400) {
            $this->lastError = "HTTP {$httpCode}";
            return false;
        }

        return $responseBody;
    }

    /**
     * @param array<string, string> $data
     */
    protected function fileGetContentsRequest(string $method, string $url, array $data = []): string|false
    {
        $context = [
            'http' => [
                'method'          => $method,
                'timeout'         => 10,
                'header'          => 'Content-Type: application/x-www-form-urlencoded',
                // 不跟随 Location：否则 HTTPS ticket 端点可把敏感 POST
                // 重定向到未验证的 HTTP/第三方主机。
                'follow_location' => 0,
                'max_redirects'   => 0,
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ],
        ];

        if ($method === 'POST' && !empty($data)) {
            $context['http']['content'] = http_build_query($data);
        }

        // Read one byte beyond the accepted maximum so oversized responses can
        // be rejected without loading their full body into memory.
        $result = @file_get_contents($url, false, stream_context_create($context), 0, self::MAX_RESPONSE_BYTES + 1);
        if ($result === false) {
            // PHP's warning may embed the full URL, including query credentials
            // or tickets. Keep transport details out of exceptions and logs.
            $this->lastError = 'SSO stream request failed';
        } elseif (strlen($result) > self::MAX_RESPONSE_BYTES) {
            $this->lastError = 'SSO response exceeds the 1 MiB limit';
            return false;
        }
        return $result !== false ? $result : false;
    }

    protected function appendResponseChunk(string &$response, string $chunk): bool
    {
        if (strlen($chunk) > self::MAX_RESPONSE_BYTES - strlen($response)) {
            return false;
        }

        $response .= $chunk;
        return true;
    }
}
