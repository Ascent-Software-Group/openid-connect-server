<?php

namespace IdaasTests;

use DateInterval;
use Idaas\OpenID\Grant\AuthCodeGrant;
use Idaas\OpenID\Grant\ImplicitGrant;
use Idaas\OpenID\Repositories\ClaimRepositoryInterface;
use Idaas\OpenID\Repositories\UserRepositoryInterface;
use Idaas\OpenID\Session;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use PHPUnit\Framework\TestCase;

class GrantInstantiationTest extends TestCase
{
    public function testImplicitGrantIsCompatibleWithTheParentGrant()
    {
        $grant = new ImplicitGrant(
            $this->getMockBuilder(UserRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock(),
            new Session(),
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $this->assertSame('implicit_oidc', $grant->getIdentifier());
    }

    public function testAuthCodeGrantIsCompatibleWithTheParentGrant()
    {
        $grant = new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock(),
            new Session(),
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );

        $this->assertSame('authorization_code_oidc', $grant->getIdentifier());
    }
}
