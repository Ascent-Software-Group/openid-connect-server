<?php

namespace IdaasTests;

use Idaas\OpenID\AdvancedResourceServer;
use Idaas\OpenID\Entities\IdToken;
use Idaas\OpenID\IdTokenEvent;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\EventEmitting\EventEmitter;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

class IdTokenEventTest extends TestCase
{
    public function testNamedListenersReceiveTheIdTokenEvent()
    {
        $received = null;
        $emitter = new EventEmitter();
        $emitter->addListener(IdTokenEvent::TOKEN_POPULATED, function ($event) use (&$received) {
            $received = $event;
        });

        $idToken = new IdToken();
        $event = new IdTokenEvent(
            IdTokenEvent::TOKEN_POPULATED,
            $idToken,
            $this->getMockBuilder(GrantTypeInterface::class)->getMock()
        );

        $emitter->emit($event);

        $this->assertSame($event, $received);
        $this->assertSame($idToken, $received->getIdToken());
    }

    public function testAdvancedResourceServerValidatesRequestsThroughTheParentServer()
    {
        $server = new AdvancedResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            new CryptKey(__DIR__.'/../vendor/league/oauth2-server/tests/Stubs/public.key', null, false)
        );

        $this->expectException(OAuthServerException::class);

        $server->validateAuthenticatedRequest(new ServerRequest('GET', '/'));
    }
}
