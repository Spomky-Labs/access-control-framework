<?php

declare(strict_types=1);

namespace AccessControl\Tests\Fixtures\Model;

use AccessControl\AccessOutcome;
use AccessControl\AccessRequest;
use AccessControl\VoterInterface;
use function sprintf;

/**
 * CBAC: the decision reads the circumstances of the request only, never the requester nor the resource.
 */
final readonly class ContextVoter implements VoterInterface
{
    public function __construct(
        private float $maximumRisk = 0.5,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return true;
    }

    public function supportsSubject(mixed $subject): bool
    {
        return true;
    }

    public function vote(AccessRequest $accessRequest): AccessOutcome
    {
        if (! $accessRequest->environment->has('risk')) {
            return AccessOutcome::abstain('The request carries no context.');
        }

        if ($accessRequest->environment->get('trusted_device') !== true) {
            return AccessOutcome::deny('The device is not trusted.');
        }

        if ($accessRequest->environment->get('risk') > $this->maximumRisk) {
            return AccessOutcome::deny(sprintf('The risk score %s is above %s.', $accessRequest->environment->get('risk'), $this->maximumRisk));
        }

        return AccessOutcome::grant('The request comes from a trusted device with a low risk score.');
    }
}
