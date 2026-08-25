<?php

declare(strict_types=1);

namespace AccessControl\Tests\Requester;

use AccessControl\Requester\StaticRequesterProvider;
use AccessControl\Requester\TokenStorageRequesterProvider;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeTokenStorage;
use AccessControl\Tests\Fixtures\FakeUser;
use PHPUnit\Framework\TestCase;

final class RequesterProviderTest extends TestCase
{
    public function testStaticProviderHandsOverAnythingIncludingNull(): void
    {
        static::assertNull(new StaticRequesterProvider()->getRequester());
        static::assertSame('a-service-account', new StaticRequesterProvider('a-service-account')->getRequester());
    }

    public function testTokenStorageProviderReadsTheCurrentToken(): void
    {
        $tokenStorage = new FakeTokenStorage();
        $provider = new TokenStorageRequesterProvider($tokenStorage);

        static::assertNull($provider->getRequester());

        $tokenStorage->setToken($token = new FakeToken(new FakeUser()));

        static::assertSame($token, $provider->getRequester());
    }
}
