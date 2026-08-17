<?php

declare(strict_types=1);

namespace AccessControl\Tests\Requester;

use PHPUnit\Framework\TestCase;
use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\Requester\TokenStorageRequesterProvider;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeTokenStorage;
use AccessControl\Tests\Fixtures\FakeUser;

final class RequesterProviderTest extends TestCase
{
    public function testStaticProviderHandsOverAnythingIncludingNull(): void
    {
        $this->assertNull((new StaticRequesterProvider())->getRequester());
        $this->assertSame('a-service-account', (new StaticRequesterProvider('a-service-account'))->getRequester());
    }

    public function testTokenStorageProviderReadsTheCurrentToken(): void
    {
        $tokenStorage = new FakeTokenStorage();
        $provider = new TokenStorageRequesterProvider($tokenStorage);

        $this->assertNull($provider->getRequester());

        $tokenStorage->setToken($token = new FakeToken(new FakeUser()));

        $this->assertSame($token, $provider->getRequester());
    }
}
