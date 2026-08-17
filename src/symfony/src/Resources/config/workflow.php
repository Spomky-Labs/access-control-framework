<?php

declare(strict_types=1);

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use AccessControl\Bridge\Workflow\ExpressionLanguageProvider;
use AccessControl\ExpressionLanguage;
use AccessControl\Voter\Expression\ExpressionVoter;

return static function (ContainerConfigurator $container) {
    $container->services()
        // A language of its own rather than access_control.expression_language, so that is_valid()
        // is reachable from a workflow guard and from nowhere else. No cache pool: the parsed
        // expressions are memoised in the object anyway, and sharing a pool between two languages
        // that know different functions would let one of them borrow a parse it could not have made.
        ->set('access_control.workflow.expression_language', ExpressionLanguage::class)
            ->args([
                null,
                [inline_service(ExpressionLanguageProvider::class)->args([service('validator')->nullOnInvalid()])],
            ])

        // Not tagged access_control.voter on purpose: this instance answers guards only, and a
        // voter of the general decision path has no business knowing is_valid().
        ->set('access_control.workflow.voter.expression', ExpressionVoter::class)
            ->args([
                service('access_control.workflow.expression_language'),
                service('access_control.manager'),
                // No trust resolver: this is only ever wired in an application that has no Security.
                null,
                service('access_control.role_hierarchy'),
            ])
    ;
};
