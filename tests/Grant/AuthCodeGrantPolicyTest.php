<?php

namespace LeagueTests\Grant;

use DateInterval;
use DateTime;
use Idaas\OpenID\Grant\AuthCodeGrant;
use Idaas\OpenID\Repositories\ClaimRepositoryInterface;
use Idaas\OpenID\ResponseTypes\BearerTokenResponse;
use Idaas\OpenID\Session;
use Idaas\OpenID\SessionInformation;
use IdaasTests\Stubs\ClaimEntity;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\AuthCodeEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

class AuthCodeGrantPolicyTest extends TestCase
{
    public function testPublicClientCanAuthorizeWithoutPkceByDefault()
    {
        $grant = $this->grant();
        $grant->setClientRepository($this->clientRepository(false));
        $grant->setScopeRepository($this->scopeRepository());

        $request = $this->authorizationRequest();

        $authorizationRequest = $grant->validateAuthorizationRequest($request);

        $this->assertNull($authorizationRequest->getCodeChallenge());
    }

    public function testConfidentialClientIsRejectedWithoutASecret()
    {
        $grant = $this->grant();
        $grant->setClientRepository($this->clientRepository(true));

        $request = (new ServerRequest('POST', '/'))->withParsedBody([
            'grant_type' => 'authorization_code',
            'client_id' => 'foo',
            'code' => 'not-used',
        ]);

        try {
            $grant->respondToAccessTokenRequest($request, new BearerTokenResponse(), new DateInterval('PT10M'));
            $this->fail('A confidential client without a secret was accepted.');
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertStringContainsString('client_secret', (string) $exception->getHint());
        }
    }

    public function testConfidentialClientIsRejectedWhenTheSecretIsInvalid()
    {
        $clients = $this->clientRepository(true);
        $clients->method('validateClient')->willReturn(false);

        $grant = $this->grant();
        $grant->setClientRepository($clients);

        $request = (new ServerRequest('POST', '/'))->withParsedBody([
            'grant_type' => 'authorization_code',
            'client_id' => 'foo',
            'client_secret' => 'wrong',
            'code' => 'not-used',
        ]);

        try {
            $grant->respondToAccessTokenRequest($request, new BearerTokenResponse(), new DateInterval('PT10M'));
            $this->fail('An invalid client secret was accepted.');
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_client', $exception->getErrorType());
        }
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testAuthorizationCodeIdTokenIncludesTheEmailClaim()
    {
        eval('function config($key) {
            if ($key === "auth.guards.api.provider") {
                return "users";
            }

            if ($key === "auth.providers.users.model") {
                return "LeagueTests\\\\Grant\\\\EmailClaimUser";
            }

            return null;
        }');

        $crypt = new CryptTraitStub();
        $clients = $this->clientRepository(false);
        $clients->method('validateClient')->willReturn(true);

        $grant = $this->grant();
        $grant->setIssuer('https://issuer.example.com');
        $grant->setClientRepository($clients);
        $grant->setScopeRepository($this->scopeRepository());
        $grant->setAccessTokenRepository($this->accessTokenRepository());
        $grant->setRefreshTokenRepository($this->refreshTokenRepository());
        $grant->setEncryptionKey($crypt->getKey());
        $privateKey = new CryptKey('file://' . __DIR__ . '/../../vendor/league/oauth2-server/tests/Stubs/private.key');
        $grant->setPrivateKey($privateKey);

        $authCodes = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodes->method('isAuthCodeRevoked')->willReturn(false);
        $grant->setAuthCodeRepository($authCodes);

        $code = $crypt->doEncrypt(json_encode([
            'auth_code_id' => uniqid(),
            'expire_time' => time() + 3600,
            'client_id' => 'foo',
            'user_id' => 'user-1',
            'scopes' => ['openid'],
            'claims' => null,
            'redirect_uri' => 'http://foo/bar',
            'nonce' => 'nonce-1',
            'auth_time' => (new DateTime())->getTimestamp(),
            'sessionInformation' => (new SessionInformation())->setAcr('acr')->setAmr('amr')->setAzp('azp')->toJSON(),
        ]));

        $request = (new ServerRequest('POST', '/'))->withParsedBody([
            'grant_type' => 'authorization_code',
            'client_id' => 'foo',
            'redirect_uri' => 'http://foo/bar',
            'code' => $code,
        ]);

        $responseType = new BearerTokenResponse();
        $responseType->setPrivateKey($privateKey);
        $responseType->setEncryptionKey($crypt->getKey());
        $result = $grant->respondToAccessTokenRequest($request, $responseType, new DateInterval('PT10M'));

        $payload = json_decode((string) $result->generateHttpResponse(new Response())->getBody(), true);
        $claims = json_decode(base64_decode(explode('.', $payload['id_token'])[1]), true);

        $this->assertSame('user@example.com', $claims['email']);
    }

    protected function grant(): AuthCodeGrant
    {
        $claims = $this->getMockBuilder(ClaimRepositoryInterface::class)->getMock();
        $claims->method('claimsRequestToEntities')->willReturn([new ClaimEntity('sub')]);

        return new AuthCodeGrant(
            $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock(),
            $claims,
            new Session(),
            new DateInterval('PT10M'),
            new DateInterval('PT10M')
        );
    }

    protected function clientRepository(bool $confidential)
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        if ($confidential) {
            $client->setConfidential();
        }

        $repository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $repository->method('getClientEntity')->willReturn($client);

        return $repository;
    }

    protected function scopeRepository()
    {
        $repository = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $repository->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());
        $repository->method('finalizeScopes')->willReturnArgument(0);

        return $repository;
    }

    protected function accessTokenRepository()
    {
        $repository = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $repository->method('getNewToken')->willReturnCallback(function ($client) {
            $accessToken = new AccessTokenEntity();
            $accessToken->setClient($client);

            return $accessToken;
        });

        return $repository;
    }

    protected function refreshTokenRepository()
    {
        $repository = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $repository->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        return $repository;
    }

    protected function authorizationRequest(): ServerRequest
    {
        return (new ServerRequest('GET', '/'))->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => 'http://foo/bar',
            'scope' => 'openid',
        ]);
    }
}

class EmailClaimUser
{
    public string $email = 'user@example.com';

    public function findForPassport($identifier): self
    {
        return $this;
    }
}
