<?php

declare(strict_types=1);

namespace AccessControl;

use AccessControl\Attribute\Argument;
use AccessControl\Exception\UnknownArgumentException;
use function array_key_exists;
use function is_array;
use function sprintf;

/**
 * @experimental
 */
final readonly class AccessPolicyContext
{
    /**
     * @param array<string, mixed> $arguments   Values an Argument reference can point to
     * @param array<string, mixed> $environment The circumstances of the call, handed over to the voters
     * @param string|null          $origin      What is asking, for diagnostics only: it never reaches
     *                                          a voter, a decision being the same wherever it is asked from
     */
    public function __construct(
        public mixed $requester = null,
        public array $arguments = [],
        public array $environment = [],
        public ?string $origin = null,
    ) {
    }

    /**
     * An array is walked so that a map of named subjects resolves each of its references, which is
     * what #[IsGranted] does when its subject is an array.
     */
    public function resolve(mixed $value): mixed
    {
        if (is_array($value)) {
            return array_map($this->resolve(...), $value);
        }

        if (! $value instanceof Argument) {
            return $value;
        }

        if (! array_key_exists($value->name, $this->arguments)) {
            throw new UnknownArgumentException(sprintf('Could not resolve the "%s" argument. Available arguments are: "%s".', $value->name, implode('", "', array_keys($this->arguments))));
        }

        return $this->arguments[$value->name];
    }
}
