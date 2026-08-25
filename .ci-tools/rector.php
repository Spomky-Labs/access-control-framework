<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Php80\Rector\Ternary\GetDebugTypeRector;
use Rector\PHPUnit\CodeQuality\Rector\Class_\PreferPHPUnitThisCallRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Renaming\Rector\String_\RenameStringRector;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Symfony73\Rector\Class_\GetFiltersAndFunctionsToAsTwigAttributeRector;
use Rector\ValueObject\PhpVersion;

$builder = RectorConfig::configure();
if (file_exists('/tools/.composer/vendor-bin/phpunit/vendor/autoload.php')) {
    $builder->withAutoloadPaths(['/tools/.composer/vendor-bin/phpunit/vendor/autoload.php']);
}
$builder->withSets([SetList::DEAD_CODE, LevelSetList::UP_TO_PHP_84, PHPUnitSetList::PHPUNIT_CODE_QUALITY]);
$builder->withComposerBased(twig: true, phpunit: true, symfony: true);
$builder->withPhpVersion(PhpVersion::PHP_84);
$builder->withPaths([
    __DIR__ . '/../src',
    __DIR__ . '/../tests',
    __DIR__ . '/../castor.php',
    __DIR__ . '/ecs.php',
    __DIR__ . '/rector.php',
]);
$builder->withSkip([
    PreferPHPUnitThisCallRector::class,
    // Rewrites bare strings off Symfony's rename map, and 'ROLE_PREVIOUS_ADMIN' => 'IS_IMPERSONATOR'
    // conflates the two vocabularies this component keeps apart: a role name, read by RoleVoter off
    // its ROLE_ prefix, and an authentication state, read by AuthenticatedVoter. Measured on the
    // parity tests, which name the old value on purpose: one broke, and the other silently collapsed
    // two distinct assertions into the same one twice, staying green.
    RenameStringRector::class,
    // Collapses the subject key to get_debug_type(), where AccessDecisionManager::getVoters() keys on
    // is_object($object) ? $object::class : get_debug_type($object). VoterAdapter mirrors that line so
    // an application's CacheableVoterInterface::supportsType() is asked the same string by both
    // stacks; the two answers part company on anonymous classes.
    GetDebugTypeRector::class,
    // Drops AbstractExtension for #[AsTwigFunction], which needs Twig 3.21 and would narrow the
    // supported range from ^3.12|^4.0 for no functional gain, on the one integration a silent
    // divergence already bit: Twig resolves a function's owner off the registered extension.
    GetFiltersAndFunctionsToAsTwigAttributeRector::class,
]);
$builder->withParallel();
$builder->withImportNames();

return $builder;
