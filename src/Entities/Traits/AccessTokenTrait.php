<?php

namespace Idaas\OpenID\Entities\Traits;

use Idaas\OpenID\Entities\ClaimEntityInterface;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait as LeagueAccessTokenTrait;

trait AccessTokenTrait
{
    use LeagueAccessTokenTrait {
        LeagueAccessTokenTrait::setPrivateKey as parentSetPrivateKey;
        LeagueAccessTokenTrait::toString as parentToString;
    }

    private CryptKeyInterface $openidPrivateKey;

    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        $this->openidPrivateKey = $privateKey;

        $this->parentSetPrivateKey($privateKey);
    }

    public function toString(): string
    {
        $privateKeyContents = $this->openidPrivateKey->getKeyContents();

        $config = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($privateKeyContents, $this->openidPrivateKey->getPassPhrase() ?? ''),
            InMemory::plainText('empty', 'empty')
        );

        return $config->builder()
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new \DateTimeImmutable())
            ->canOnlyBeUsedAfter(new \DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) ($this->getUserIdentifier() ?? $this->getClient()->getIdentifier()))
            ->withClaim('scopes', $this->getScopes())
            ->withClaim('claims', $this->getClaims())
            ->getToken($config->signer(), $config->signingKey())
            ->toString();
    }

    /**
     * @return ClaimEntityInterface[]
     */
    abstract public function getClaims();
}
