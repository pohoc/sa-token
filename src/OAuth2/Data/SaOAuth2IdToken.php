<?php

declare(strict_types=1);

namespace SaToken\OAuth2\Data;

class SaOAuth2IdToken
{
    protected string $idToken = '';
    protected string $subject = '';
    protected string $audience = '';
    protected int $issuedAt = 0;
    protected int $expiresAt = 0;
    protected string $issuer = '';
    /** @var array<string, mixed> */
    protected array $claims = [];

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                $this->$method($value);
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'idToken'  => $this->idToken,
            'subject'  => $this->subject,
            'audience' => $this->audience,
            'issuedAt' => $this->issuedAt,
            'expiresAt' => $this->expiresAt,
            'issuer'   => $this->issuer,
            'claims'   => $this->claims,
        ];
    }

    public function getIdToken(): string
    {
        return $this->idToken;
    }

    public function setIdToken(string $idToken): static
    {
        $this->idToken = $idToken;
        return $this;
    }

    public function getSubject(): string
    {
        return $this->subject;
    }

    public function setSubject(string $subject): static
    {
        $this->subject = $subject;
        return $this;
    }

    public function getAudience(): string
    {
        return $this->audience;
    }

    public function setAudience(string $audience): static
    {
        $this->audience = $audience;
        return $this;
    }

    public function getIssuedAt(): int
    {
        return $this->issuedAt;
    }

    public function setIssuedAt(int $issuedAt): static
    {
        $this->issuedAt = $issuedAt;
        return $this;
    }

    public function getExpiresAt(): int
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(int $expiresAt): static
    {
        $this->expiresAt = $expiresAt;
        return $this;
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function setIssuer(string $issuer): static
    {
        $this->issuer = $issuer;
        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function setClaims(array $claims): static
    {
        $this->claims = $claims;
        return $this;
    }
}
