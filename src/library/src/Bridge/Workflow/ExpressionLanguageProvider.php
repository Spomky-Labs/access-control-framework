<?php

declare(strict_types=1);

namespace AccessControl\Bridge\Workflow;

use Symfony\Component\ExpressionLanguage\ExpressionFunction;
use Symfony\Component\ExpressionLanguage\ExpressionFunctionProviderInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Component\Workflow\Exception\RuntimeException;
use function count;
use function sprintf;

/**
 * The one guard function that is not about access at all.
 *
 * Workflow adds is_valid() to the expression language it borrows from Security, so a guard already
 * written with it must keep working here. It is kept out of this component's own expression language
 * on purpose: an access rule asking whether an object passes validation is not an access question,
 * and the language a rule speaks should not grow a Validator function by accident.
 *
 * The validator is held rather than read from the evaluation variables, which is what lets the
 * expression voter be reused untouched: its variables are the ones an access rule sees, and this
 * function needs none of them.
 *
 * @experimental
 */
final readonly class ExpressionLanguageProvider implements ExpressionFunctionProviderInterface
{
    public function __construct(
        private ?ValidatorInterface $validator = null,
    ) {
    }

    public function getFunctions(): array
    {
        return [
            new ExpressionFunction(
                'is_valid',
                static fn ($subject = 'null', $groups = 'null') => sprintf('0 === count($validator->validate(%s, null, %s))', $subject, $groups),
                fn (array $variables, $subject = null, $groups = null) => count($this->validator()->validate($subject, null, $groups)) === 0,
            ),
        ];
    }

    private function validator(): ValidatorInterface
    {
        return $this->validator ?? throw new RuntimeException('"is_valid" cannot be used as the Validator component is not installed. Try running "composer require symfony/validator".');
    }
}
