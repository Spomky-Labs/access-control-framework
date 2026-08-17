<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

/**
 * The combining algorithm an application chose must give the same answer under the three shapes it
 * can have: SecurityBundle alone, both bundles, and this bundle alone.
 *
 * The first two compare a migration: same security.yaml, one bundle more. Measured before the
 * algorithm was carried over, three of the four silently fell back to this component's default and
 * started granting what the application refused. No unit test would have seen it, both stacks
 * answering correctly on their own; only the configuration failed to travel.
 *
 * The third compares a vocabulary: the same voters and the same algorithm written on this
 * component's own key, which is where an application arrives at the end of the migration.
 *
 * The voters never agree with one another on purpose. Voters that agree say nothing about the
 * algorithm combining them, which is exactly how the divergence went unnoticed.
 */
class StrategyParityTest extends WebTestCase
{
    /**
     * Two refusing against one granting: the shape that separates the four algorithms.
     */
    private const MAJORITY_DENIES = [false, false, true];

    /**
     * One each, so that the equality rule of consensus is the only thing left to decide.
     */
    private const A_TIE = [false, true];

    private static string $shape = self::class;
    private static array $voters = [];
    private static array $decisionManager = [];
    private static array $accessControl = [];

    private static string $attribute = 'THING';

    protected static function createKernel(array $options = []): KernelInterface
    {
        return new StrategyParityKernel(self::$shape, self::$voters, self::$decisionManager, self::$accessControl, self::$attribute);
    }

    /**
     * @return iterable<string, array{0: array<mixed>, 1: array<mixed>, 2: string}>
     */
    public static function provideAllAbstainRules(): iterable
    {
        yield 'the default of either stack' => [[], [], 'denied'];
        yield 'granting when nobody answered' => [['allow_if_all_abstain' => true], ['allow_if_all_abstain' => true], 'granted'];
        yield 'refusing when nobody answered' => [['allow_if_all_abstain' => false], ['allow_if_all_abstain' => false], 'denied'];
    }

    /**
     * What to answer when no voter had anything to say. Security carries it on each of its
     * strategies, this component on its manager, so the setting has to travel from the one to the
     * other or an application that granted would start refusing.
     *
     * The attribute is one no voter of the fixture supports, so the rule is the only thing left
     * deciding.
     *
     * @param array<mixed> $decisionManager
     * @param array<mixed> $accessControl
     */
    #[DataProvider('provideAllAbstainRules')]
    public function testTheAllAbstainRuleSurvivesTheInstallation(array $decisionManager, array $accessControl, string $expected)
    {
        self::$attribute = 'NOBODY_ANSWERS_THIS';

        try {
            $security = $this->answerOf(StrategyParityKernel::SECURITY, self::MAJORITY_DENIES, $decisionManager);
            $both = $this->answerOf(StrategyParityKernel::BOTH, self::MAJORITY_DENIES, $decisionManager);
            $alone = $this->answerOf(StrategyParityKernel::ACCESS_CONTROL, self::MAJORITY_DENIES, [], $accessControl);
        } finally {
            self::$attribute = 'THING';
        }

        $this->assertSame($expected, $security, 'Security did not answer what this test assumes.');
        $this->assertSame($security, $both, 'Installing the bundle changed the answer.');
        $this->assertSame($security, $alone, 'The component alone does not answer like Security.');
    }

    /**
     * The last three cases each isolate one thing. The two ties leave the equality flag as the only
     * thing still deciding. And an algorithm of the application's own is wrapped by the bridge
     * rather than replaced, with nothing to compare it to without Security, that service being one
     * of its contracts.
     *
     * @return iterable<string, array{0: list<bool>, 1: array<mixed>, 2: ?array<mixed>, 3: string}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield 'the default of either stack' => [self::MAJORITY_DENIES, [], [], 'granted'];

        yield 'affirmative and permit_overrides' => [
            self::MAJORITY_DENIES,
            ['strategy' => 'affirmative'],
            ['default_strategy' => 'permit_overrides'],
            'granted',
        ];

        yield 'unanimous and deny_overrides' => [
            self::MAJORITY_DENIES,
            ['strategy' => 'unanimous'],
            ['default_strategy' => 'deny_overrides'],
            'denied',
        ];

        yield 'consensus and majority' => [
            self::MAJORITY_DENIES,
            ['strategy' => 'consensus'],
            ['default_strategy' => 'majority'],
            'denied',
        ];

        yield 'priority and first_applicable' => [
            self::MAJORITY_DENIES,
            ['strategy' => 'priority'],
            ['default_strategy' => 'first_applicable'],
            'denied',
        ];

        yield 'a tie granted' => [
            self::A_TIE,
            ['strategy' => 'consensus'],
            ['default_strategy' => 'majority'],
            'granted',
        ];

        yield 'a tie refused' => [
            self::A_TIE,
            ['strategy' => 'consensus', 'allow_if_equal_granted_denied' => false],
            ['default_strategy' => 'majority', 'allow_if_equal_granted_denied' => false],
            'denied',
        ];

        yield 'an algorithm of the application' => [
            self::MAJORITY_DENIES,
            ['strategy_service' => AlwaysDenyingStrategy::class],
            null,
            'denied',
        ];
    }

    /**
     * @param list<bool>        $voters
     * @param array<mixed>      $decisionManager
     * @param array<mixed>|null $accessControl   null when the case has no counterpart without Security
     */
    #[DataProvider('provideAlgorithms')]
    public function testTheThreeShapesAnswerAlike(array $voters, array $decisionManager, ?array $accessControl, string $expected)
    {
        $security = $this->answerOf(StrategyParityKernel::SECURITY, $voters, $decisionManager);
        $both = $this->answerOf(StrategyParityKernel::BOTH, $voters, $decisionManager);

        $this->assertSame($expected, $security, 'Security did not answer what this test assumes.');
        $this->assertSame($security, $both, 'Installing the bundle changed the answer.');

        if (null === $accessControl) {
            return;
        }

        $alone = $this->answerOf(StrategyParityKernel::ACCESS_CONTROL, $voters, [], $accessControl);

        $this->assertSame($security, $alone, 'The component alone does not answer like Security.');
    }

    /**
     * @param list<bool>   $voters
     * @param array<mixed> $decisionManager
     * @param array<mixed> $accessControl
     */
    private function answerOf(string $shape, array $voters, array $decisionManager, array $accessControl = []): string
    {
        self::$shape = $shape;
        self::$voters = $voters;
        self::$decisionManager = $decisionManager;
        self::$accessControl = $accessControl;
        self::ensureKernelShutdown();

        $client = static::createClient();
        $client->request('GET', '/strategy-parity', server: ['PHP_AUTH_USER' => 'alice', 'PHP_AUTH_PW' => 'pa$$word']);

        return $client->getResponse()->getContent();
    }
}
