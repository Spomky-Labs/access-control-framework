<?php

declare(strict_types=1);

namespace AccessControl;

/**
 * Who asks what, on what, and under which circumstances.
 *
 * The four fields line up with the attribute categories of ABAC and XACML, but two of the names
 * deliberately differ, so the correspondence is spelled out here:
 *
 *     requester    XACML calls it the subject
 *     attribute    XACML calls it the action
 *     subject      XACML calls it the resource
 *     environment  same word on both sides
 *
 * The word subject therefore means the thing being acted upon, as everywhere in Symfony, and not
 * the actor, as in the security literature. Keeping it is deliberate: it is the word every
 * application voter has used for a decade, the word of #[IsGranted] and of the Twig function, and
 * the word of AuthorizationCheckerInterface::isGranted(), which the Security bridge implements. A
 * rename would move the translation to that very seam instead of removing it. And requester says
 * more plainly than subject ever could who is doing the asking.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
readonly class AccessRequest
{
    public function __construct(
        public mixed $requester,
        public mixed $attribute,
        public mixed $subject = null,
        public AccessEnvironment $environment = new AccessEnvironment(),
        /**
         * What to answer when no voter had anything to say. Null defers to the manager, which is
         * where an application settles it once for the whole of itself; a boolean here overrides it
         * for this one question.
         */
        public ?bool $allowIfAllAbstain = null,
    ) {
    }
}
