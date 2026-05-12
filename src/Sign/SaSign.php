<?php

declare(strict_types=1);

namespace SaToken\Sign;

class SaSign
{
    protected string $key = '';

    protected int $timestampGap = 600;

    protected string $signAlg = 'sha256';

    /** @var callable(string): bool|null */
    protected $nonceValidator = null;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [])
    {
        $key = $config['key'] ?? '';
        $this->key = is_string($key) ? $key : '';
        $timestampGap = $config['timestampGap'] ?? 600;
        $this->timestampGap = is_int($timestampGap) ? $timestampGap : 600;
        $signAlg = $config['signAlg'] ?? 'sha256';
        $this->signAlg = is_string($signAlg) ? $signAlg : 'sha256';
    }

    /**
     * @param  array<string, string|int> $params
     * @return array<string, string|int>
     */
    public function signParams(array $params): array
    {
        if (!isset($params['timestamp'])) {
            $params['timestamp'] = (string) time();
        }
        if (!isset($params['nonce'])) {
            $params['nonce'] = bin2hex(random_bytes(16));
        }
        $params['sign'] = $this->createSign($params);
        return $params;
    }

    /**
     * @param array<string, string|int> $params
     */
    public function verifySign(array $params): bool
    {
        $sign = $params['sign'] ?? null;
        if ($sign === null) {
            return false;
        }

        if (isset($params['timestamp'])) {
            if (abs(time() - (int) $params['timestamp']) > $this->timestampGap) {
                return false;
            }
        }

        if ($this->nonceValidator !== null && array_key_exists('nonce', $params)) {
            $nonce = $params['nonce'];
            if ($nonce !== null && !($this->nonceValidator)((string) $nonce)) {
                return false;
            }
        }

        $expectedSign = $this->createSign($params);
        return hash_equals($expectedSign, (string) $sign);
    }

    public function setNonceValidator(callable $validator): static
    {
        $this->nonceValidator = $validator;
        return $this;
    }

    public function setSignAlg(string $alg): static
    {
        $this->signAlg = $alg;
        return $this;
    }

    /**
     * @param array<string, string|int> $params
     */
    protected function createSign(array $params): string
    {
        unset($params['sign']);
        ksort($params);
        $parts = [];
        foreach ($params as $k => $v) {
            if ($v === '') {
                continue;
            }
            $parts[] = $k . '=' . $v;
        }
        $queryString = implode('&', $parts);
        $queryString .= '&key=' . $this->key;
        return hash($this->signAlg, $queryString);
    }
}
