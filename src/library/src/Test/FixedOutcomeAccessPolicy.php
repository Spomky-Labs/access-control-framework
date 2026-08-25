<?php

declare(strict_types=1);

namespace AccessControl\Test;

use AccessControl\AccessOutcome;
use AccessControl\Attribute\AccessPolicyInterface;

/**
 * A nested policy whose outcome the test decides, so a composite can be exercised without a voter,
 * a manager or a requester anywhere in sight.
 *
 * Testing a composite handler otherwise means assembling the whole stack underneath it just to make
 * a child grant or refuse, and the assembly is then what the test is really about.
 *
 * @experimental
 */
final readonly class FixedOutcomeAccessPolicy implements AccessPolicyInterface
{
    public function __construct(
        public AccessOutcome $outcome,
        public ?string $message = null,
    ) {
    }
}
