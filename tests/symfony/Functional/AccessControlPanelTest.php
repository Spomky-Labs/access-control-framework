<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Functional;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use AccessControl\AccessControlManager;
use Symfony\Component\DomCrawler\Crawler;

/**
 * The panel of the AccessControl component, rendered by the real profiler controller.
 *
 * The collector is covered on its own in the component. What only a rendering can prove is that the
 * template survives what a decision actually holds, an attribute that is not a string and a subject
 * that is an object among them.
 */
class AccessControlPanelTest extends WebTestCase
{
    protected function setUp(): void
    {
        if (!class_exists(AccessControlManager::class)) {
            $this->markTestSkipped('The AccessControl component is not installed.');
        }
    }

    public function testThePanelCountsWhatWasDecided()
    {
        $metrics = $this->panel()->filter('.metrics .metric .value');

        $this->assertSame('3', $metrics->eq(0)->text(), 'questions');
        $this->assertSame('3', $metrics->eq(1)->text(), 'decisions');
        $this->assertSame('2', $metrics->eq(2)->text(), 'granted');
        $this->assertSame('1', $metrics->eq(3)->text(), 'denied');
        $this->assertSame('permit_overrides', $metrics->eq(4)->text());
    }

    /**
     * The controller names itself, and the two calls it makes on its own are named by the stack, so
     * no row is left saying only that something, somewhere, asked.
     */
    public function testEveryQuestionSaysWhatAskedIt()
    {
        $origins = $this->panel()->filter('.decision-log .query-header .origin')->each(fn ($node) => $node->text());

        $this->assertCount(3, $origins);

        foreach ($origins as $origin) {
            $this->assertStringContainsString('AccessControlPanelKernel::homepageController', $origin);
        }
    }

    /**
     * A question is not a decision: the three here happen to take one decision each, but the header
     * is what says which rows belong together.
     *
     * The first was declared by a policy, so its tree comes before its decision. The two others
     * were asked programmatically and declare none, which is why they carry no policy row.
     */
    public function testTheDecisionsAreGroupedUnderTheirQuestion()
    {
        $rows = $this->panel()->filter('.decision-log > tbody > tr')->each(fn ($node) => $node->attr('class'));

        $this->assertSame([
            'query-header', 'policy-row', 'decision-result', 'decision-details',
            'query-header', 'decision-result', 'decision-details',
            'query-header', 'decision-result', 'decision-details',
        ], $rows);
    }

    /**
     * What the decisions alone cannot say. All and AtLeastOneOf are written here on the very same
     * two policies and reach opposite verdicts, so a panel showing decisions only would present the
     * two identically, and the satisfied AtLeastOneOf would look like a lone policy since it stops
     * at its first grant.
     */
    public function testTheCompositeThatMadeTheVerdictIsNamed()
    {
        $all = $this->policyRows('/composite/all');
        $either = $this->policyRows('/composite/either');

        $this->assertStringContainsString('All', $all[0]);
        $this->assertStringStartsWith('DENIED', $all[0]);

        $this->assertStringContainsString('AtLeastOneOf', $either[0]);
        $this->assertStringStartsWith('GRANTED', $either[0]);

        // The branch that was reached is the same on both sides, so only the composite tells them apart.
        $this->assertStringContainsString('EDIT', $all[1]);
        $this->assertStringContainsString('EDIT', $either[1]);
    }

    /**
     * @return list<string>
     */
    private function policyRows(string $path): array
    {
        $rows = [];
        foreach ($this->panel($path)->filter('.decision-log .policy-row') as $node) {
            $rows[] = trim(preg_replace('/\s+/', ' ', (new Crawler($node))->text()));
        }

        return $rows;
    }

    /**
     * A When whose condition does not hold asks nothing at all, so it leaves no decision behind and
     * the page would otherwise be refused with an empty panel. It says why itself.
     */
    public function testACompositeThatStoodAsideSaysSo()
    {
        $rows = $this->policyRows('/composite/when');

        $this->assertCount(1, $rows, 'The branch never ran, so the composite is alone.');
        $this->assertStringContainsString('When', $rows[0]);
        $this->assertStringContainsString('The condition (false) does not hold.', $rows[0]);
    }

    public function testTheLogTellsWhichDecisionWentWhichWay()
    {
        $panel = $this->panel();
        $results = $panel->filter('.decision-log .decision-result td:nth-child(2)');

        $this->assertSame('GRANTED', $results->eq(0)->text());
        $this->assertSame('GRANTED', $results->eq(1)->text());
        $this->assertSame('DENIED', $results->eq(2)->text());
        $this->assertStringContainsString('ROLE_ADMIN', $panel->filter('.decision-log')->text());
        $this->assertStringContainsString('permit_overrides', $panel->filter('.decision-log')->text());
    }

    /**
     * What the response never says: who refused, and why.
     */
    public function testTheDetailsNameTheVotersAndTheirReasons()
    {
        $log = $this->panel()->filter('.decision-log')->html();

        $this->assertStringContainsString('ClosureVoter', $log);
        $this->assertStringContainsString('RoleVoter', $log);
        $this->assertStringContainsString('The user does not have the required role.', $log);
        $this->assertStringContainsString('10.0.0.1', $log);
    }

    /**
     * Two kinds of thing were being shown side by side: how the application is set up, which never
     * changes, and what it was asked during this one request. They are separated, the counts of the
     * request staying above and the rest going under its own tab.
     */
    public function testWhatIsSetUpIsSeparatedFromWhatWasAsked()
    {
        $panel = $this->panel();

        $this->assertSame(
            ['Decisions3', 'Configuration'],
            $panel->filter('#collector-content .sf-tabs > .tab > .tab-title')->each(fn ($node) => trim($node->text())),
        );

        $this->assertSame(
            ['Questions', 'Decisions', 'Granted', 'Denied'],
            $panel->filter('#collector-content > .metrics .metric .label')->each(fn ($node) => trim($node->text())),
        );

        $this->assertCount(1, $panel->filter('.sf-tabs > .tab:nth-child(1) .decision-log'));
        $this->assertCount(1, $panel->filter('.sf-tabs > .tab:nth-child(2) table.integration'));
        $this->assertCount(1, $panel->filter('.sf-tabs > .tab:nth-child(2) table.voters'));
    }

    /**
     * What the panel says about the application it is running in: which stack answers what. Here
     * there is no Security at all, so everything is this component's.
     */
    public function testThePanelSaysWhichStackAnswersWhat()
    {
        $rows = [];
        foreach ($this->panel()->filter('table.integration tbody tr') as $node) {
            $row = new Crawler($node);
            $rows[trim($row->filter('th')->text())] = trim($row->filter('td')->text());
        }

        $this->assertSame('AccessControl', $rows['Access decisions']);
        $this->assertSame('AccessControl', $rows['#[IsGranted]']);
        $this->assertSame('AccessControl', $rows['Role hierarchy']);
        $this->assertSame('nobody', $rows['URL rules'], 'This application declares none.');
        $this->assertSame('0 bridged', $rows['Voters written against Security']);
    }

    public function testTheRegisteredVotersAreListedWhetherConsultedOrNot()
    {
        $voters = $this->panel()->filter('table.voters')->text();

        $this->assertStringContainsString('RoleVoter', $voters);
        $this->assertStringContainsString('ClosureVoter', $voters);
    }

    public function testTheToolbarCountsTheDecisions()
    {
        $client = new KernelBrowser(new AccessControlPanelKernel());
        $client->request('GET', '/');

        $toolbar = $client->request('GET', '/_wdt/'.$client->getResponse()->headers->get('X-Debug-Token'))->html();

        $this->assertStringContainsString('Access Control', $toolbar);
        $this->assertStringContainsString('Default strategy', $toolbar);
    }

    public function testAPageThatDecidesNothingStillOpensThePanel()
    {
        $panel = $this->panel('/quiet');

        $this->assertStringContainsString('No access control question was asked during this request.', $panel->filter('#collector-content')->text());
        $this->assertCount(0, $panel->filter('.decision-log'));
        $this->assertStringContainsString('RoleVoter', $panel->filter('table.voters')->text());
    }

    private function panel(string $path = '/'): Crawler
    {
        $client = new KernelBrowser(new AccessControlPanelKernel());
        $client->request('GET', $path);

        return $client->request('GET', '/_profiler/'.$client->getResponse()->headers->get('X-Debug-Token').'?panel=access_control');
    }
}
