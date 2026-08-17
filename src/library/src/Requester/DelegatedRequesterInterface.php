<?php

declare(strict_types=1);

namespace AccessControl\Requester;

/**
 * A requester somebody else is really acting as.
 *
 * Two situations share this shape under opposite names: an administrator impersonating a user, who
 * was granted nothing by them, and an agent a user has authorised to act for them. The word that
 * covers both is the actor, as RFC 8693 names it: the requester is who the access is asked for, the
 * actor is who is really asking.
 *
 * A contract on the requester rather than a wrapper around it, deliberately. Wrapping would hide
 * the requester from every voter that reads its type, which is the very reason an offline token
 * cannot be reproduced here.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface DelegatedRequesterInterface
{
    /**
     * Who is really asking, behind the requester this stands for.
     */
    public function getActor(): mixed;
}
