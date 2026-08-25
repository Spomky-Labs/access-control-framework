<?php

declare(strict_types=1);

namespace AccessControl\Requester;

use Symfony\Component\Security\Core\Authentication\Token\SwitchUserToken;

/**
 * Tells who is really asking, behind the requester an access request names.
 *
 * Two sources, and one place that knows both. An application states it through the component's own
 * contract; Security states it through a token it built long before this component existed, and
 * which is not this component's to change. Asking each voter to know both would be the same rule
 * written twice, free to drift.
 *
 * The reference to Security is soft, as everywhere else here: the instanceof answers false rather
 * than raising when security-core is absent, so the component stands alone without a guard.
 *
 * @experimental
 */
final class Actor
{
    /**
     * Null when nobody else is acting, which is the ordinary case.
     */
    public static function of(mixed $requester): mixed
    {
        if ($requester instanceof DelegatedRequesterInterface) {
            return $requester->getActor();
        }

        if ($requester instanceof SwitchUserToken) {
            return $requester->getOriginalToken();
        }

        return null;
    }

    public static function isActedFor(mixed $requester): bool
    {
        return self::of($requester) !== null;
    }
}
