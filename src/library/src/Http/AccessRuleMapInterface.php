<?php

declare(strict_types=1);

namespace AccessControl\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * Tells which access rule covers a request, if any.
 *
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @experimental
 */
interface AccessRuleMapInterface
{
    /**
     * Returns the first rule matching the request, null when none does.
     */
    public function getRule(Request $request): ?AccessRule;
}
