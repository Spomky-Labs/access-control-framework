<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures;

use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

final class FakeEventDispatcher implements EventDispatcherInterface
{
    public array $events = [];

    public function dispatch(object $event, ?string $eventName = null): object
    {
        $this->events[] = $event;

        return $event;
    }
}
