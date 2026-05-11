<?php

declare(strict_types=1);

namespace SaToken\Sign;

class SaSign
{
    protected string $key = '';

    protected int $timestampGap = 600;

    protected string $signAlg = 'md5';

    protected $nonceValidator = null;

    public function __construct(array $config = [])
    {
        $this->key = $config['key'] ?? '';
        $this->timestampGap = $config['timestampGap'] ?? 600;
        $this->signAlg = $config['signAlg'] ?? 'md5';
    }

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

        if ($this->nonceValidator !== null && isset($params['nonce'])) {
            if (!($this->nonceValidator)($params['nonce'])) {
                return false;
            }
        }

        $expectedSign = $this->createSign($params);
        return hash_equals($expectedSign, $sign);
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

    protected function createSign(array $params): string
    {
        unset($params['sign']);
        ksort($params);
        $parts = [];
        foreach ($params as $k => $v) {
            if ($v === '' || $v === null) {
                continue;
            }
            $parts[] = $k . '=' . $v;
        }
        $queryString = implode('&', $parts);
        $queryString .= '&key=' . $this->key;
        return hash($this->signAlg, $queryString);
    }
}
