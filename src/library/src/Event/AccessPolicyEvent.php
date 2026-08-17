<?php

declare(strict_types=1);

namespace AccessControl\Event;

use AccessControl\AccessOutcome;
use AccessControl\Attribute\AccessPolicyInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * One policy of a tree, and what it answered.
 *
 * A composite is what makes a verdict, not the decisions under it: the very same two policies read
 * "both of them" under All and "either of them" under AtLeastOneOf, for opposite verdicts. Recorded
 * as decisions alone, the two are indistinguishable, and a composite that short circuits leaves
 * fewer decisions than it has branches, so a satisfied AtLeastOneOf looks exactly like a lone
 * policy. A When whose condition does not hold leaves nothing at all, while knowing perfectly well
 * why it stepped aside.
 *
 * The parent is the same idea as the one AccessDecisionEvent carries for a nested question, applied
 * to the shape of the policy rather than to the shape of the questions it asks.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final class AccessPolicyEvent extends Event
{
    /**
     * @param AccessPolicyInterface|null $parent The composite this policy is a branch of, null for
     *                                           the one the entry point declared
     */
    public function __construct(
        public readonly AccessPolicyInterface $accessPolicy,
        public readonly AccessOutcome $outcome,
        public readonly ?AccessPolicyInterface $parent = null,
    ) {
    }
}
