<?php

declare(strict_types=1);

namespace SaToken\Sso;

use SaToken\Exception\SaTokenException;

/**
 * SSO HTTP 请求模板
 *
 * 封装与 SSO 认证中心的 HTTP 通信
 */
class SaSsoTemplate
{
    /**
     * 发起 HTTP GET 请求
     *
     * @param  string           $url    请求 URL
     * @param  array            $params 查询参数
     * @return string           响应体
     * @throws SaTokenException
     */
    public function get(string $url, array $params = []): string
    {
        if (!empty($params)) {
            $url .= (str_contains($url, '?') ? '&' : '?') . http_build_query($params);
        }

        $response = $this->doRequest('GET', $url);
        if ($response === false) {
            throw new SaTokenException("SSO HTTP 请求失败：{$url}");
        }

        return $response;
    }

    /**
     * 发起 HTTP POST 请求
     *
     * @param  string           $url  请求 URL
     * @param  array            $data POST 数据
     * @return string           响应体
     * @throws SaTokenException
     */
    public function post(string $url, array $data = []): string
    {
        $response = $this->doRequest('POST', $url, $data);
        if ($response === false) {
            throw new SaTokenException("SSO HTTP 请求失败：{$url}");
        }

        return $response;
    }

    /**
     * 执行 HTTP 请求
     *
     * @param  string       $method 请求方法
     * @param  string       $url    请求 URL
     * @param  array        $data   请求数据
     * @return string|false
     */
    protected function doRequest(string $method, string $url, array $data = []): string|false
    {
        // 优先使用 cURL
        if (function_exists('curl_init')) {
            return $this->curlRequest($method, $url, $data);
        }

        // 回退到 file_get_contents
        return $this->fileGetContentsRequest($method, $url, $data);
    }

    /**
     * 使用 cURL 发送请求
     *
     * @param  string       $method 请求方法
     * @param  string       $url    请求 URL
     * @param  array        $data   请求数据
     * @return string|false
     */
    protected function curlRequest(string $method, string $url, array $data = []): string|false
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode >= 400) {
            return false;
        }

        return $response !== false ? $response : false;
    }

    /**
     * 使用 file_get_contents 发送请求
     *
     * @param  string       $method 请求方法
     * @param  string       $url    请求 URL
     * @param  array        $data   请求数据
     * @return string|false
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
        return $result !== false ? $result : false;
    }
}
