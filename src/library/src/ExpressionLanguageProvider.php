<?php

declare(strict_types=1);

namespace AccessControl;

use Symfony\Component\ExpressionLanguage\ExpressionFunction;
use Symfony\Component\ExpressionLanguage\ExpressionFunctionProviderInterface;
use function sprintf;

/**
 * Every function goes through the access checker, so that an expression and a voter answer the same
 * question the same way, even when the shipped voters have been replaced.
 */
class ExpressionLanguageProvider implements ExpressionFunctionProviderInterface
{
    public function getFunctions(): array
    {
        return [
            new ExpressionFunction(
                'is_authenticated',
                static fn () => '$auth_checker->isGranted("IS_AUTHENTICATED")',
                static fn (array $variables) => $variables['auth_checker']->isGranted('IS_AUTHENTICATED'),
            ),
            new ExpressionFunction(
                'is_fully_authenticated',
                static fn () => '$auth_checker->isGranted("IS_AUTHENTICATED_FULLY")',
                static fn (array $variables) => $variables['auth_checker']->isGranted('IS_AUTHENTICATED_FULLY'),
            ),
            new ExpressionFunction(
                'is_remember_me',
                static fn () => '$auth_checker->isGranted("IS_REMEMBERED")',
                static fn (array $variables) => $variables['auth_checker']->isGranted('IS_REMEMBERED'),
            ),
            new ExpressionFunction(
                'is_granted',
                static fn ($attribute, $subject = 'null') => sprintf('$auth_checker->isGranted(%s, %s)', $attribute, $subject),
                static fn (array $variables, $attribute, $subject = null) => $variables['auth_checker']->isGranted($attribute, $subject),
            ),
        ];
    }
}
