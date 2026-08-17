<?php

declare(strict_types=1);

namespace AccessControl\Http;

use AccessControl\Attribute\AccessPolicyInterface;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

/**
 * What a part of the site requires, matched by the request it applies to.
 *
 * The matcher says which requests the rule covers, the access policy says what they require. Those
 * are two different questions and keeping them apart is what lets a matcher stay a matcher: the
 * voters run on the requests a rule already selected, not on every request that goes by.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
final readonly class AccessRule
{
    /**
     * @param AccessPolicyInterface|null $accessPolicy What the request must satisfy, null for a rule that only enforces a channel
     * @param string|null                $channel      The channel to enforce, http, https or null
     */
    public function __construct(
        public RequestMatcherInterface $requestMatcher,
        public ?AccessPolicyInterface $accessPolicy = null,
        public ?string $channel = null,
    ) {
    }
}
