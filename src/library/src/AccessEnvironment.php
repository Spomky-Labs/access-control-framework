<?php

declare(strict_types=1);

namespace AccessControl;

use ArrayIterator;
use Countable;
use IteratorAggregate;
use function array_key_exists;
use function count;

/**
 * The circumstances of a request, that is what belongs neither to the requester, nor to the
 * subject, nor to the attribute.
 *
 * Entry points fill it in with what they know: the HTTP request on the web, the command and its
 * input on the console. It is what lets a voter decide on the surroundings of a call, and it is
 * the fourth attribute category of the ABAC and XACML vocabularies.
 *
 * It carries what an entry point knows and a voter could not reach on its own. Anything ambient
 * that a voter can obtain by itself belongs to that voter instead, the clock being the obvious
 * case: a rule that abstains on a missing key fails open, and no entry point should be able to
 * disable a rule by omission.
 *
 * @experimental
 */
final readonly class AccessEnvironment implements IteratorAggregate, Countable
{
    /**
     * @param array<string, mixed> $parameters
     */
    public function __construct(
        private array $parameters = [],
    ) {
    }

    /**
     * Returns the parameter keys.
     */
    public function keys(): array
    {
        return array_keys($this->parameters);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->parameters) ? $this->parameters[$key] : $default;
    }

    /**
     * Returns true if the parameter is defined.
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->parameters);
    }

    /**
     * Returns an iterator for parameters.
     *
     * @return ArrayIterator<string, mixed>
     */
    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->parameters);
    }

    /**
     * Returns the number of parameters.
     */
    public function count(): int
    {
        return count($this->parameters);
    }
}
