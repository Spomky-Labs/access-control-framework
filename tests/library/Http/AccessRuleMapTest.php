<?php

declare(strict_types=1);

namespace AccessControl\Tests\Http;

use PHPUnit\Framework\TestCase;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Http\AccessRule;
use AccessControl\Http\AccessRuleMap;
use Symfony\Component\HttpFoundation\ChainRequestMatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcher\MethodRequestMatcher;
use Symfony\Component\HttpFoundation\RequestMatcher\PathRequestMatcher;

final class AccessRuleMapTest extends TestCase
{
    public function testAnEmptyMapMatchesNothing()
    {
        $this->assertNull((new AccessRuleMap())->getRule(Request::create('/admin')));
    }

    public function testTheFirstMatchingRuleWins()
    {
        $strict = new AccessRule(new PathRequestMatcher('^/admin'), new AccessPolicy('ROLE_ADMIN'));
        $loose = new AccessRule(new PathRequestMatcher('^/'), new AccessPolicy('ROLE_USER'));

        $map = new AccessRuleMap([$strict, $loose]);

        $this->assertSame($strict, $map->getRule(Request::create('/admin/users')));
        $this->assertSame($loose, $map->getRule(Request::create('/')));
    }

    /**
     * Declaration order is the whole semantic of the map, so a rule added afterwards lands last and
     * is shadowed by anything broader declared before it.
     */
    public function testARuleAddedAfterwardsComesLast()
    {
        $map = new AccessRuleMap([$loose = new AccessRule(new PathRequestMatcher('^/'))]);
        $map->add($strict = new AccessRule(new PathRequestMatcher('^/admin')));

        $this->assertSame($loose, $map->getRule(Request::create('/admin')));
        $this->assertNotSame($strict, $map->getRule(Request::create('/admin')));
    }

    public function testARuleThatDoesNotMatchIsSkipped()
    {
        $map = new AccessRuleMap([
            new AccessRule(new ChainRequestMatcher([new PathRequestMatcher('^/admin'), new MethodRequestMatcher(['POST'])])),
            $get = new AccessRule(new PathRequestMatcher('^/admin')),
        ]);

        $this->assertSame($get, $map->getRule(Request::create('/admin', 'GET')));
    }

    public function testAMapAcceptsAnyTraversable()
    {
        $rule = new AccessRule(new PathRequestMatcher('^/'));
        $map = new AccessRuleMap(new \ArrayIterator([$rule]));

        $this->assertSame($rule, $map->getRule(Request::create('/')));
    }

    /**
     * A rule may carry a channel and no policy at all, which is a request that must be redirected
     * but that nobody has to be allowed to make.
     */
    public function testARuleCanCarryAChannelWithoutAnyPolicy()
    {
        $map = new AccessRuleMap([new AccessRule(new PathRequestMatcher('^/'), null, 'https')]);
        $rule = $map->getRule(Request::create('/'));

        $this->assertNull($rule->accessPolicy);
        $this->assertSame('https', $rule->channel);
    }
}
