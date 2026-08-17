<?php

declare(strict_types=1);

namespace AccessControl\Tests\DataCollector;

use PHPUnit\Framework\TestCase;
use AccessControl\AccessControlManager;
use AccessControl\AccessEnvironment;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\AccessRequest;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\All;
use AccessControl\Attribute\AtLeastOneOf;
use AccessControl\Bridge\Security\VoterAdapter;
use AccessControl\DataCollector\AccessControlDataCollector;
use AccessControl\Handler\AccessPolicyHandler;
use AccessControl\Handler\AllHandler;
use AccessControl\Handler\AtLeastOneOfHandler;
use AccessControl\Listener\AccessDecisionLoggerListener;
use AccessControl\RequesterBoundChecker;
use AccessControl\Strategy\DenyOverridesStrategy;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\PostVoter;
use AccessControl\Tests\Fixtures\SecurityPostVoter;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use AccessControl\Voter\ClosureVoter;
use AccessControl\Voter\RBAC\RoleVoter;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class AccessControlDataCollectorTest extends TestCase
{
    private EventDispatcher $dispatcher;
    private AccessDecisionLoggerListener $logger;

    protected function setUp(): void
    {
        $this->dispatcher = new EventDispatcher();
        $this->logger = new AccessDecisionLoggerListener();
        $this->dispatcher->addSubscriber($this->logger);
    }

    public function testARequestThatDecidesNothingStillListsTheVoters()
    {
        $collector = $this->collect([new RoleVoter()]);

        $this->assertCount(0, $collector->getQueries());
        $this->assertSame(0, $collector->getDecisionCount());
        $this->assertSame(0, $collector->getGrantedCount());
        $this->assertSame(0, $collector->getDeniedCount());
        $this->assertSame('permit_overrides', $collector->getDefaultStrategy());
        $this->assertSame([RoleVoter::class], $this->voterClasses($collector));
    }

    public function testAGrantedDecisionKeepsTheQuestionItAnswered()
    {
        $voters = [new PostVoter()];
        $this->manager($voters)->decide(new AccessRequest(new StandaloneRequester(), 'read', new Post()));

        $decision = $this->decisions($this->collect($voters))[0];

        $this->assertSame('ACCESS_GRANTED', $decision['decision']);
        $this->assertSame('read', $decision['attribute']);
        $this->assertSame('Hello', $decision['subject']['title']);
        $this->assertSame('permit_overrides', $decision['strategy']);
        $this->assertSame(0, $decision['depth']);
    }

    public function testTheCountsSeparateGrantsFromDenials()
    {
        $voters = [new RoleVoter()];
        $manager = $this->manager($voters);
        $manager->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));
        $manager->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_SUPER_ADMIN'));

        $collector = $this->collect($voters);

        $this->assertSame(2, $collector->getDecisionCount());
        $this->assertSame(1, $collector->getGrantedCount());
        $this->assertSame(1, $collector->getDeniedCount());
    }

    /**
     * The whole point of the panel: the response says the door was closed, this says who closed it.
     */
    public function testADenialNamesTheVoterThatCastIt()
    {
        $voters = [new RoleVoter()];
        $this->manager($voters)->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_SUPER_ADMIN'));

        $votes = $this->decisions($this->collect($voters))[0]['votes'];

        $this->assertCount(1, $votes);
        $this->assertSame(RoleVoter::class, (string) $votes[0]['voter']);
        $this->assertSame('ACCESS_DENIED', $votes[0]['decision']);
        $this->assertSame('The user does not have the required role.', $votes[0]['reason']);
    }

    /**
     * A composite asks a question per branch, and a flat log cannot say that the two belong
     * together. They land under one query, whose verdict is the composite's and not either branch's.
     */
    public function testACompositeGroupsItsBranchesUnderOneQuestion()
    {
        $voters = [new RoleVoter()];
        $policy = new AtLeastOneOf([new AccessPolicy('ROLE_SUPER_ADMIN'), new AccessPolicy('ROLE_ADMIN')]);

        $this->evaluator($voters)->evaluate($policy, new AccessPolicyContext(new StandaloneRequester(['ROLE_ADMIN'])));

        $queries = $this->collect($voters)->getQueries();

        $this->assertCount(1, $queries);
        $this->assertSame('ACCESS_GRANTED', $queries[0]['decision']);
        $this->assertCount(2, $queries[0]['decisions']);
        $this->assertSame('ROLE_SUPER_ADMIN', $queries[0]['decisions'][0]['attribute']);
        $this->assertSame('ROLE_ADMIN', $queries[0]['decisions'][1]['attribute']);
    }

    public function testTwoPoliciesAreTwoQuestions()
    {
        $voters = [new RoleVoter()];
        $evaluator = $this->evaluator($voters);
        $context = new AccessPolicyContext(new StandaloneRequester(['ROLE_ADMIN']));

        $evaluator->evaluate(new AccessPolicy('ROLE_ADMIN'), $context);
        $evaluator->evaluate(new AccessPolicy('ROLE_SUPER_ADMIN'), $context);

        $queries = $this->collect($voters)->getQueries();

        $this->assertCount(2, $queries);
        $this->assertSame('ACCESS_GRANTED', $queries[0]['decision']);
        $this->assertSame('ACCESS_DENIED', $queries[1]['decision']);
    }

    public function testTheOriginOfTheContextNamesTheQuestion()
    {
        $voters = [new RoleVoter()];
        $context = new AccessPolicyContext(new StandaloneRequester(['ROLE_ADMIN']), origin: 'App\Controller\PostController::edit');

        $this->evaluator($voters)->evaluate(new All([new AccessPolicy('ROLE_ADMIN')]), $context);

        $this->assertSame('App\Controller\PostController::edit', $this->collect($voters)->getQueries()[0]['origin']);
    }

    /**
     * Nobody closed a question here, so each call stands on its own rather than being piled into one
     * nameless group, which would read as a composite that never existed.
     */
    public function testDecisionsTakenOutsideAnyQuestionAreOneQuestionEach()
    {
        $voters = [new RoleVoter()];
        $manager = $this->manager($voters);
        $manager->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));
        $manager->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_SUPER_ADMIN'));

        $queries = $this->collect($voters)->getQueries();

        $this->assertCount(2, $queries);
        $this->assertSame('ACCESS_GRANTED', $queries[0]['decision']);
        $this->assertSame('ACCESS_DENIED', $queries[1]['decision']);
        $this->assertCount(1, $queries[0]['decisions']);
        $this->assertCount(1, $queries[1]['decisions']);
    }

    /**
     * And what asked is recovered from the stack, since no entry point was there to name itself.
     */
    public function testTheCallSiteNamesAQuestionNobodyDeclared()
    {
        $this->logger = new AccessDecisionLoggerListener(true);
        $this->dispatcher->addSubscriber($this->logger);

        $voters = [new RoleVoter()];
        $this->manager($voters)->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));

        $query = $this->collect($voters)->getQueries()[0];

        $this->assertSame(self::class.'::testTheCallSiteNamesAQuestionNobodyDeclared', $query['origin']);
        $this->assertSame(__FILE__, $query['caller']['file']);
        $this->assertIsInt($query['caller']['line']);
    }

    public function testTheCallSiteIsNotWalkedUnlessAsked()
    {
        $voters = [new RoleVoter()];
        $this->manager($voters)->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));

        $this->assertNull($this->collect($voters)->getQueries()[0]['origin']);
    }

    /**
     * A closure asking a further question leaves two decisions behind, and the votes of one must not
     * be shown under the other. An outcome does not know its voter, so the join relies on the request
     * each vote was cast on.
     */
    public function testANestedQuestionKeepsItsVotesApart()
    {
        $decisions = $this->decisions($this->collect($this->nestingVoters()));

        $this->assertCount(2, $decisions);
        $this->assertSame('ROLE_ADMIN', $decisions[1]['attribute']);
        $this->assertSame([ClosureVoter::class], $this->votersOf($decisions[0]));
        $this->assertSame([RoleVoter::class], $this->votersOf($decisions[1]));
    }

    /**
     * And it is shown under the decision that asked it rather than above it: a nested decision is
     * reached first but reads second.
     */
    public function testANestedQuestionIsShownBelowTheOneThatAskedIt()
    {
        $decisions = $this->decisions($this->collect($this->nestingVoters()));

        $this->assertSame(0, $decisions[0]['depth']);
        $this->assertSame(1, $decisions[1]['depth']);
    }

    public function testAPolicyThatPicksItsOwnStrategyIsShownWithIt()
    {
        $voters = [new RoleVoter()];
        $this->manager($voters)->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'), 'deny_overrides');

        $collector = $this->collect($voters);

        $this->assertSame('deny_overrides', $this->decisions($collector)[0]['strategy']);
        $this->assertSame('permit_overrides', $collector->getDefaultStrategy());
    }

    public function testTheEnvironmentIsCollected()
    {
        $voters = [new RoleVoter()];
        $this->manager($voters)->decide(new AccessRequest(
            new StandaloneRequester(['ROLE_ADMIN']),
            'ROLE_ADMIN',
            environment: new AccessEnvironment(['ip' => '10.0.0.1']),
        ));

        $this->assertSame('10.0.0.1', $this->decisions($this->collect($voters))[0]['environment']['ip']);
    }

    public function testResetEmptiesTheCollectedData()
    {
        $voters = [new RoleVoter()];
        $this->manager($voters)->decide(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'ROLE_ADMIN'));

        $collector = $this->collect($voters);
        $collector->reset();

        $this->assertCount(0, $collector->getQueries());
        $this->assertSame([], $collector->getVoters());
        $this->assertSame(0, $collector->getDecisionCount());
        $this->assertNull($collector->getDefaultStrategy());
    }

    /**
     * A closure voter reaching for the checker, which is the shape an expression calling
     * is_granted() takes.
     */
    private function nestingVoters(): \ArrayObject
    {
        $voters = new \ArrayObject();
        $manager = $this->manager($voters);
        $voters->append(new ClosureVoter($manager));
        $voters->append(new RoleVoter());

        $manager->decide(new AccessRequest(
            new StandaloneRequester(['ROLE_ADMIN']),
            static fn (AccessRequest $accessRequest, RequesterBoundChecker $checker): bool => $checker->isGranted('ROLE_ADMIN'),
        ));

        return $voters;
    }

    /**
     * @param iterable<object> $voters
     */
    private function manager(iterable $voters): AccessControlManager
    {
        return new AccessControlManager(
            [new PermitOverridesStrategy(), new DenyOverridesStrategy()],
            $voters,
            dispatcher: $this->dispatcher,
        );
    }

    /**
     * @param iterable<object> $voters
     */
    private function evaluator(iterable $voters): AccessPolicyEvaluator
    {
        $handlers = [new AccessPolicyHandler($this->manager($voters)), new AllHandler(), new AtLeastOneOfHandler()];

        return new AccessPolicyEvaluator($handlers, $this->dispatcher);
    }

    /**
     * Every voter written against Security is consulted through one adapter class, so the panel
     * would show the same name as many times as the application has voters. Naming the one behind
     * is what answers the question a migration actually asks.
     */
    public function testABridgedVoterIsNamedBehindItsAdapter()
    {
        $collector = $this->collect([new VoterAdapter(new SecurityPostVoter())]);

        $voters = iterator_to_array($collector->getVoters());

        $this->assertSame(VoterAdapter::class, (string) $voters[0]['voter']);
        $this->assertSame(SecurityPostVoter::class, (string) $voters[0]['bridged']);
    }

    /**
     * And a voter of this component's own carries nothing behind it, the key being left out rather
     * than set to null: a null value would come back as a Data the panel cannot test for emptiness.
     */
    public function testAVoterOfTheComponentHasNothingBehindIt()
    {
        $collector = $this->collect([new RoleVoter()]);

        $voters = iterator_to_array($collector->getVoters());

        $this->assertSame(RoleVoter::class, (string) $voters[0]['voter']);
        $this->assertNull($voters[0]->seek('bridged'));
    }

    /**
     * @param iterable<object> $voters
     */
    private function collect(iterable $voters): AccessControlDataCollector
    {
        $collector = new AccessControlDataCollector($this->logger, $voters, 'permit_overrides');
        $collector->collect(new Request(), new Response());
        $collector->lateCollect();

        return $collector;
    }

    /**
     * @return list<mixed>
     */
    private function decisions(AccessControlDataCollector $collector): array
    {
        $decisions = [];
        foreach ($collector->getQueries() as $query) {
            foreach ($query['decisions'] as $decision) {
                $decisions[] = $decision;
            }
        }

        return $decisions;
    }

    /**
     * @return list<string>
     */
    private function voterClasses(AccessControlDataCollector $collector): array
    {
        $classes = [];
        foreach ($collector->getVoters() as $voter) {
            $classes[] = (string) $voter['voter'];
        }

        return $classes;
    }

    /**
     * @return list<string>
     */
    private function votersOf(mixed $decision): array
    {
        $classes = [];
        foreach ($decision['votes'] as $vote) {
            $classes[] = (string) $vote['voter'];
        }

        return $classes;
    }
}
