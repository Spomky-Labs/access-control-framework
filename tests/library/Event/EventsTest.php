<?php

declare(strict_types=1);

namespace AccessControl\Tests\Event;

use AccessControl\AccessRequest;
use AccessControl\Event\AccessDecisionEvent;
use AccessControl\Event\VoteEvent;
use AccessControl\Tests\StrategyTestCase;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;

final class EventsTest extends StrategyTestCase
{
    public function testDecide(): void
    {
        $accessRequest = new AccessRequest(new NullToken(), 'PUBLIC_ACCESS');

        $this->getAccessControlManager()->decide($accessRequest);

        $events = $this->getEventDispatcher()->events;
        $this->assertCount(2, $events);
        $this->assertInstanceOf(VoteEvent::class, $events[0]);
        $this->assertInstanceOf(AccessDecisionEvent::class, $events[1]);
    }
}
