<?php

declare(strict_types=1);

namespace AccessControl\Tests\Requester;

use AccessControl\Requester\Actor;
use AccessControl\Tests\Fixtures\DelegatedRequester;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The single place that knows both ways of saying "somebody else is really asking". Written twice,
 * the rule would be free to drift, which is the mistake this component already made once with
 * is_granted_for_user.
 */
final class ActorTest extends TestCase
{
    public function testNobodyIsActingByDefault(): void
    {
        static::assertNull(Actor::of(new StandaloneRequester(['ROLE_ADMIN'])));
        static::assertFalse(Actor::isActedFor(new StandaloneRequester(['ROLE_ADMIN'])));
    }

    public function testARequesterWithoutAnyShapeAtAll(): void
    {
        static::assertNull(Actor::of(null));
        static::assertNull(Actor::of('an-api-key'));
    }

    public function testTheComponentContract(): void
    {
        $administrator = new StandaloneRequester(['ROLE_ADMIN']);

        static::assertSame($administrator, Actor::of(new DelegatedRequester($administrator)));
        static::assertTrue(Actor::isActedFor(new DelegatedRequester($administrator)));
    }

    /**
     * Security says it with a token it built long before this component existed, and which is not
     * this component's to change. Read where it stands rather than made to implement anything.
     */
    public function testSecuritysImpersonation(): void
    {
        $original = new UsernamePasswordToken(new InMemoryUser('root', null), 'main', ['ROLE_ADMIN']);
        $token = new SwitchUserToken(new InMemoryUser('alice', null), 'main', ['ROLE_USER'], $original);

        static::assertSame($original, Actor::of($token));
        static::assertTrue(Actor::isActedFor($token));
    }

    public function testAnOrdinaryTokenIsNobodysActor(): void
    {
        static::assertNull(Actor::of(new UsernamePasswordToken(new InMemoryUser('alice', null), 'main', ['ROLE_USER'])));
    }
}
