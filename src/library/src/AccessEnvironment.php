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
 */
final readonly class AccessEnvironment implements IteratorAggregate, Countable
{
    /**
     * The HTTP request, seeded by every web entry point: the access policy listener, the URL rule
     * listener and the #[IsGranted] bridge.
     */
    public const string REQUEST = 'request';

    /**
     * The command about to run, seeded by the console entry point.
     */
    public const string COMMAND = 'command';

    /**
     * The console input, seeded by the console entry point. This is where a policy reads an option.
     */
    public const string INPUT = 'input';

    /**
     * The console output, seeded by the console entry point.
     */
    public const string OUTPUT = 'output';

    /**
     * Every key this component seeds on its own, so that an application can tell them from its own.
     *
     * They are the only ones named here. The bag stays open on purpose: its consumers are string
     * keyed, an expression naming request or input and a closure reading whatever the application
     * put there, so a closed type would buy them nothing and would cost this library its
     * independence from HttpFoundation and Console.
     */
    public const array SEEDED_KEYS = [self::REQUEST, self::COMMAND, self::INPUT, self::OUTPUT];

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
