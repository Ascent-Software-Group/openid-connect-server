<?php

namespace Idaas\OpenID;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;

class AdvancedResourceServer extends ResourceServer
{
    /**
     * New server instance.
     *
     * @param AccessTokenRepositoryInterface       $accessTokenRepository
     * @param CryptKeyInterface|string             $publicKey
     * @param null|AuthorizationValidatorInterface $authorizationValidator
     */
    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        CryptKeyInterface|string $publicKey,
        ?AuthorizationValidatorInterface $authorizationValidator = null
    ) {
        parent::__construct($accessTokenRepository, $publicKey, $authorizationValidator);
    }
}
