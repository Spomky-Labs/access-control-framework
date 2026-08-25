<?php

declare(strict_types=1);

namespace AccessControl\Tests\Migration;

use AccessControl\AccessControlManager;
use AccessControl\AccessRequest;
use AccessControl\Bridge\Security\VoterAdapter;
use AccessControl\DecisionVote;
use AccessControl\Strategy\PermitOverridesStrategy;
use AccessControl\Tests\Fixtures\FakeToken;
use AccessControl\Tests\Fixtures\FakeUser;
use AccessControl\Tests\Fixtures\Post;
use AccessControl\Tests\Fixtures\SecurityPostVoter;
use AccessControl\Tests\Fixtures\StandaloneRequester;
use PHPUnit\Framework\TestCase;
use stdClass;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface as SecurityVoterInterface;

/**
 * An application voter written against Security, answering through this component untouched.
 *
 * Every Symfony application has such voters. Without this adapter they would stop being consulted
 * the day the decision manager is pointed at the component, silently, which is why this is the
 * piece the deprecation of Security's VoterInterface waits on.
 */
final class VoterAdapterTest extends TestCase
{
    public function testTheThreeVerdictsAreCarriedOver()
    {
        foreach ([
            SecurityVoterInterface::ACCESS_GRANTED => DecisionVote::ACCESS_GRANTED,
            SecurityVoterInterface::ACCESS_DENIED => DecisionVote::ACCESS_DENIED,
            SecurityVoterInterface::ACCESS_ABSTAIN => DecisionVote::ACCESS_ABSTAIN,
        ] as $securityVerdict => $expected) {
            $adapter = new VoterAdapter($this->voter($securityVerdict));

            static::assertSame($expected, $adapter->vote(new AccessRequest($this->token(), 'EDIT'))->decision);
        }
    }

    public function testTheReasonsAreCarriedOver()
    {
        $adapter = new VoterAdapter($this->voter(SecurityVoterInterface::ACCESS_DENIED, ['Not the author.', 'Not an editor.']));

        static::assertSame('Not the author. Not an editor.', $adapter->vote(new AccessRequest($this->token(), 'EDIT'))->reason);
    }

    public function testAnUnwrittenReasonStaysNull()
    {
        $adapter = new VoterAdapter($this->voter(SecurityVoterInterface::ACCESS_GRANTED));

        static::assertNull($adapter->vote(new AccessRequest($this->token(), 'EDIT'))->reason);
    }

    /**
     * The component allows any requester, a Security voter does not. Abstaining rather than failing
     * is what lets a bridged voter sit next to a native one in the same stack.
     */
    public function testARequesterThatIsNotATokenLeavesTheVoterWithNothingToSay()
    {
        $adapter = new VoterAdapter($this->voter(SecurityVoterInterface::ACCESS_GRANTED));

        $outcome = $adapter->vote(new AccessRequest(new StandaloneRequester(['ROLE_ADMIN']), 'EDIT'));

        static::assertSame(DecisionVote::ACCESS_ABSTAIN, $outcome->decision);
        static::assertStringContainsString('only votes on a security token', (string) $outcome->reason);
    }

    public function testACacheableVoterKeepsItsFiltering()
    {
        $adapter = new VoterAdapter(new SecurityPostVoter());

        static::assertTrue($adapter->supportsAttribute('read'));
        static::assertFalse($adapter->supportsAttribute('deploy'));
        static::assertTrue($adapter->supportsSubject(new Post('Hello')));
        static::assertFalse($adapter->supportsSubject('a string'));
    }

    /**
     * supportsAttribute() of Security is typed on a string, so anything else has to be offered to
     * the voter rather than filtered out on its behalf.
     */
    public function testANonStringAttributeIsOfferedToACacheableVoter()
    {
        $adapter = new VoterAdapter(new SecurityPostVoter());

        static::assertTrue($adapter->supportsAttribute(new stdClass()));
    }

    public function testAVoterWithoutTheCacheableContractIsNeverFilteredOut()
    {
        $adapter = new VoterAdapter($this->voter(SecurityVoterInterface::ACCESS_GRANTED));

        static::assertTrue($adapter->supportsAttribute('anything'));
        static::assertTrue($adapter->supportsSubject(new stdClass()));
    }

    /**
     * The point of the whole thing: an untouched application voter deciding inside the component's
     * stack, alongside its native voters.
     */
    public function testABridgedVoterDecidesInsideTheComponentStack()
    {
        $manager = new AccessControlManager([new PermitOverridesStrategy()], [new VoterAdapter(new SecurityPostVoter())]);

        $granted = $manager->decide(new AccessRequest($this->token(), 'read', new Post('Hello')));
        $denied = $manager->decide(new AccessRequest($this->token(), 'read', 'not a post'));

        static::assertSame(DecisionVote::ACCESS_GRANTED, $granted->decision);
        static::assertSame(DecisionVote::ACCESS_DENIED, $denied->decision);
    }

    private function token(): TokenInterface
    {
        return new FakeToken(new FakeUser(roles: ['ROLE_ADMIN']));
    }

    /**
     * @param list<string> $reasons
     */
    private function voter(int $verdict, array $reasons = []): SecurityVoterInterface
    {
        return new readonly class($verdict, $reasons) implements SecurityVoterInterface {
            public function __construct(
                private int $verdict,
                private array $reasons,
            ) {
            }

            public function vote(TokenInterface $token, mixed $subject, array $attributes, ?Vote $vote = null): int
            {
                foreach ($this->reasons as $reason) {
                    $vote?->addReason($reason);
                }

                return $this->verdict;
            }
        };
    }
}
