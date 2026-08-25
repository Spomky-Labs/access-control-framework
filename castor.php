<?php

declare(strict_types=1);

namespace qa;

use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use Throwable;
use function Castor\context;
use function Castor\fs;
use function Castor\guard_min_version;
use function Castor\io;
use function Castor\run;
use function count;
use function sprintf;
use const STDIN;

guard_min_version('v1.0.0');

const DEFAULT_PHP_VERSION = '8.4';

const ALLOWED_LICENSES = ['Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MIT', 'MPL-2.0', 'OSL-3.0'];

const SOURCE_DIRS = ['src', 'tests'];

/**
 * Runs a command in the QA image, or straight through when there is no Docker or when we already are
 * in a container, which is how the CI runs: its jobs already have the image around them.
 *
 * @param array<string> $command
 * @param array<string> $dockerOptions
 */
function phpqa(array $command, array $dockerOptions = [], bool $allowFailure = false): void
{
    $context = context()
        ->withAllowFailure($allowFailure);
    $inContainer = file_exists('/.dockerenv');
    $hasDocker = trim((string) shell_exec('command -v docker')) !== '';

    if (! $hasDocker || $inContainer) {
        run($command, context: $context);

        return;
    }

    ensureTmpPhpqa();

    $defaultDockerOptions = [
        '--rm',
        '--init',
        '--user', sprintf('%s:%s', getmyuid(), getmygid()),
        '--pull', 'always',
        '-v', getcwd() . ':/project',
        '-v', getcwd() . '/tmp-phpqa:/project/tmp-phpqa',
        '-w', '/project',
        '-e', 'XDEBUG_MODE=off',
        '-e', 'PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d',
        '-e', 'PHP_INI_ENTRY=sys_temp_dir=/project/tmp-phpqa',
        // Without it a terminal width of zero reaches the tools, and ECS dies in str_repeat() while
        // reporting the error it died on. Asked for only when there is a terminal to ask about.
        '-e', 'COLUMNS=' . (getenv('COLUMNS') ?: '160'),
    ];

    if (stream_isatty(STDIN)) {
        $defaultDockerOptions[] = '-it';
    }

    run([
        'docker', 'run',
        ...$defaultDockerOptions,
        ...$dockerOptions,
        'ghcr.io/spomky-labs/phpqa:' . phpVersion(),
        ...$command,
    ], context: $context);
}

/**
 * The version the CI calls default, so that running a task by hand asks the same image the CI asks.
 * The matrix jobs set PHP_VERSION and get their own.
 */
function phpVersion(): string
{
    return getenv('PHP_VERSION') ?: DEFAULT_PHP_VERSION;
}

function ensureTmpPhpqa(): void
{
    $path = getcwd() . '/tmp-phpqa';

    try {
        if (! fs()->exists($path)) {
            fs()->mkdir($path, 0777);
        }

        if (! is_writable($path)) {
            fs()->chmod($path, 0777);
        }
    } catch (Throwable $e) {
        io()->error(sprintf('Could not create or fix %s: %s', $path, $e->getMessage()));
        exit(1);
    }
}

#[AsTask(description: 'Update the PHPQA Docker image', namespace: 'qa')]
function update_image(): void
{
    run(['docker', 'pull', 'ghcr.io/spomky-labs/phpqa:' . phpVersion()]);
}

#[AsTask(description: 'Install composer dependencies', namespace: 'qa')]
function install(bool $lowest = false): void
{
    $command = ['composer', 'install'];

    if ($lowest) {
        $command[] = '--prefer-lowest';
    }

    phpqa($command);
}

/**
 * Deliberately "phpunit" and not a pinned "phpunit-NN" from the image: a project is tested with the
 * PHPUnit it requires. Measured, the image's 11 reports 27 failures that are none, the suite calling
 * expectExceptionMessageIsOrContains(), which PHPUnit only grew in 12.
 */
#[AsTask(description: 'Run PHPUnit tests with coverage', namespace: 'qa', ignoreValidationErrors: true)]
function phpunit(#[AsRawTokens] array $args = []): void
{
    phpqa(
        [
            'composer', 'exec', '--', 'phpunit',
            '--coverage-xml', '.ci-tools/coverage',
            '--log-junit=.ci-tools/coverage/junit.xml',
            '--configuration', '.ci-tools/phpunit.xml.dist',
            '--display-warnings',
            '--display-deprecations',
            ...$args,
        ],
        ['-e', 'XDEBUG_MODE=coverage']
    );
}

#[AsTask(description: 'Run Easy Coding Standard', namespace: 'qa')]
function ecs(): void
{
    phpqa(['composer', 'exec', '--', 'ecs', 'check', '--config', '.ci-tools/ecs.php']);
}

#[AsTask(description: 'Fix coding style with Easy Coding Standard', namespace: 'qa')]
function ecs_fix(): void
{
    phpqa(['composer', 'exec', '--', 'ecs', 'check', '--config', '.ci-tools/ecs.php', '--fix']);
}

#[AsTask(description: 'Run Rector dry-run', namespace: 'qa')]
function rector(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--dry-run', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run Rector with fix', namespace: 'qa')]
function rector_fix(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run PHPStan', namespace: 'qa')]
function phpstan(): void
{
    phpqa([
        'composer', 'exec', '--', 'phpstan', 'analyse',
        '--error-format=github',
        '--configuration=.ci-tools/phpstan.neon',
    ]);
}

#[AsTask(description: 'Generate PHPStan baseline', namespace: 'qa')]
function phpstan_baseline(): void
{
    phpqa([
        'composer', 'exec', '--', 'phpstan', 'analyse',
        '--configuration=.ci-tools/phpstan.neon',
        '--generate-baseline=.ci-tools/phpstan-baseline.neon',
    ]);
}

#[AsTask(description: 'Run Deptrac', namespace: 'qa')]
function deptrac(): void
{
    phpqa([
        'composer', 'exec', '--', 'deptrac',
        '--config-file', '.ci-tools/deptrac.yaml',
        '--report-uncovered',
        '--report-skipped',
        '--fail-on-uncovered',
    ]);
}

#[AsTask(description: 'Run PHP parallel linter', namespace: 'qa')]
function lint(): void
{
    phpqa(['composer', 'exec', '--', 'parallel-lint', ...SOURCE_DIRS]);
}

/**
 * Left in place but not wired to the CI: Infection cannot run against PHPUnit 13, which writes no
 * test at all under the execution order it forces, and the time budget a suite of functional kernels
 * needs is still to be decided. Both are written down in TODO.md.
 *
 * Paths are resolved from the directory of the configuration file, hence "coverage" and not
 * ".ci-tools/coverage".
 */
#[AsTask(description: 'Run Infection for mutation testing', namespace: 'qa')]
function infect(int $minMsi = 0, int $minCoveredMsi = 0): void
{
    phpqa([
        'composer', 'exec', '--', 'infection',
        '--coverage=coverage',
        sprintf('--min-msi=%d', $minMsi),
        sprintf('--min-covered-msi=%d', $minCoveredMsi),
        '--threads=max',
        '--logger-github',
        '-s',
        '--filter=src/',
        '--test-framework-options=--order-by=default',
        '--configuration=.ci-tools/infection.json.dist',
    ], ['-e', 'XDEBUG_MODE=coverage']);
}

#[AsTask(description: 'Run JS tests', namespace: 'qa')]
function js(): void
{
    io()->info('This project has no JavaScript.');
}

#[AsTask(description: 'Check licenses', namespace: 'qa')]
function check_licenses(): void
{
    io()->title('Checking licenses');

    $result = run(['composer', 'licenses', '-f', 'json'], context: context()
        ->withEnvironment([
            'XDEBUG_MODE' => 'off',
        ])
        ->withQuiet());

    if (! $result->isSuccessful()) {
        io()->error('Cannot determine licenses');
        exit(1);
    }

    $licenses = json_decode((string) $result->getOutput(), true);
    $disallowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info): bool => count(array_diff($info['license'], ALLOWED_LICENSES)) > 0,
    );

    if (count($disallowed) > 0) {
        io()->table(
            ['Package', 'License'],
            array_map(
                static fn ($name, $info): array => [$name, implode(', ', $info['license'])],
                array_keys($disallowed),
                $disallowed
            )
        );
        io()
            ->error('Disallowed licenses found');
        exit(1);
    }

    io()
        ->success(sprintf('All %d dependencies carry an allowed license.', count($licenses['dependencies'])));
}

#[AsTask(description: 'Validate composer.json', namespace: 'qa')]
function validate(): void
{
    phpqa(['composer', 'dump-autoload', '--optimize', '--strict-psr']);
    phpqa(['composer', 'validate', '--strict']);
    phpqa(['composer', 'normalize', '--dry-run', '--diff'], allowFailure: true);
}

#[AsTask(description: 'Fix code style and apply Rector rules, then run static analysis', namespace: 'qa')]
function prepare_pr(): void
{
    io()->title('Preparing code for pull request…');

    ecs_fix();
    rector_fix();

    io()
        ->section('Running static analysis…');
    phpstan_baseline();
    deptrac();
    lint();

    io()
        ->success('Code is ready. You may now commit and push your changes.');
}

#[AsTask(description: 'Run all QA checks', namespace: 'qa')]
function all(): void
{
    io()->title('Running all QA checks…');

    lint();
    validate();
    ecs();
    rector();
    phpstan();
    deptrac();
    phpunit();

    io()
        ->success('All QA checks passed!');
}

#[AsTask(description: 'Run QA command', namespace: 'qa', ignoreValidationErrors: true)]
function exec(#[AsRawTokens] array $args = []): void
{
    phpqa(['composer', 'exec', '--', ...$args]);
}
