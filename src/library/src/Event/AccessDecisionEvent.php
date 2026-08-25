<?php

declare(strict_types=1);

namespace AccessControl\Event;

use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use Symfony\Contracts\EventDispatcher\Event;

final class AccessDecisionEvent extends Event
{
    /**
     * @param string|null        $strategy The combining algorithm that reached the decision, which a
     *                                     policy may pick per call and which the decision itself does
     *                                     not carry
     * @param AccessRequest|null $parent   The request being decided when this one was asked, a voter
     *                                     calling is_granted() being the usual case
     */
    public function __construct(
        public readonly AccessRequest $accessRequest,
        public readonly AccessDecision $accessDecision,
        public readonly ?string $strategy = null,
        public readonly ?AccessRequest $parent = null,
    ) {
    }
}
