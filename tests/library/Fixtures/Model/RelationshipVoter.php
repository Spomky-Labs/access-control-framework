<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;

/**
 * ReBAC: access follows the edges of a graph of relations.
 *
 * A tuple binds an object and a relation to either an identity or another "object#relation" pair,
 * so that membership is reached indirectly, as in the Zanzibar model.
 */
final class RelationshipVoter implements VoterInterface
{
    /**
     * @param array<string, list<string>> $tuples Members, indexed by "object#relation"
     */
    public function __construct(
        private readonly array $tuples,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return \is_string($attribute);
    }

    public function supportsSubject(mixed $subject): bool
    {
        return \is_string($subject);
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (!\is_string($accessRequest->requester) || !\is_string($accessRequest->subject)) {
            return AccessOutcome::abstain('The request carries no identity or no object.');
        }

        return $this->isRelated($accessRequest->subject, $accessRequest->attribute, $accessRequest->requester)
            ? AccessOutcome::grant(\sprintf('"%s" is a "%s" of "%s".', $accessRequest->requester, $accessRequest->attribute, $accessRequest->subject))
            : AccessOutcome::deny(\sprintf('No "%s" relation ties "%s" to "%s".', $accessRequest->attribute, $accessRequest->requester, $accessRequest->subject));
    }

    /**
     * @param array<string, true> $visited
     */
    private function isRelated(string $object, string $relation, string $identity, array &$visited = []): bool
    {
        $key = $object.'#'.$relation;

        if (isset($visited[$key])) {
            return false;
        }

        $visited[$key] = true;

        foreach ($this->tuples[$key] ?? [] as $member) {
            if ($member === $identity) {
                return true;
            }

            if (str_contains($member, '#')) {
                [$nestedObject, $nestedRelation] = explode('#', $member, 2);

                if ($this->isRelated($nestedObject, $nestedRelation, $identity, $visited)) {
                    return true;
                }
            }
        }

        return false;
    }
}
