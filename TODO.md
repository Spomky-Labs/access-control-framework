# Todo

Journal de travail complet, arbitrages tranchés et mesures : `~/.claude/projects/-home-florent-Projects-access-control-framework/access-control-worklog.md`, hors dépôt pour ne pas publier un document de travail. Les diagrammes sont à côté. **À lire avant de reprendre**, pour ne pas refaire les mesures ni rouvrir ce qui est tranché.

## État

Portage hors du dépôt Symfony fait le 2026-08-17, après la clôture de symfony/symfony#59439. Suite verte sur Symfony 8.1 publié : 623 tests, 1163 assertions.

## Mise en service

1. **Créer les trois dépôts GitHub** : `spomky-labs/access-control-framework`, puis `access-control-lib` et `access-control-bundle` en read-only. Poser le secret `GITSPLIT_TOKEN`.
2. **Brancher la CI** : le workflow réutilisable de `spomky-labs/phpqa` est déjà référencé, et c'est le premier projet à utiliser le castor centralisé (`import('../phpqa/.castor/phpqa.php')`) plutôt qu'une copie locale des tâches. Vérifier que `reusable-ci.yml` trouve bien les fichiers de `.ci-tools/`.
3. **Passer l'outillage**, pas encore lancé une seule fois : `castor ecs-fix`, `castor rector-fix`, `castor phpstan-baseline`, `castor deptrac`, `castor lint`, puis `castor infect`. Le churn sera important, le code venant d'un dépôt aux conventions différentes.
4. **Recette Flex** pour `access-control-bundle`, dans `symfony/recipes-contrib`.
5. **Documentation** : le README couvre l'installation et les deux migrations ; il manque le vocabulaire XACML, `#[AccessPolicy]` et ses combinateurs, les requesters, et le panneau de profil.

## Contributions amont, indépendantes de ce projet

Deux correctifs trouvés en développant le composant, sans rapport avec l'access control, à sortir sur `8.2` :

| PR | Contenu |
|---|---|
| amont 1 | `results.html.twig` du WebProfiler ne définit pas `has_dump`, plus un kernel de test capable de démarrer en debug et un test qui rend vraiment la page |
| amont 2 | Le profilage console ne survit pas à une commande arrêtée à `ConsoleEvents::COMMAND` : défauts sur trois propriétés de `TraceableCommand`, `input` et `output` semés par `FrameworkBundle\Console\Application`, repli dans `CliRequest::getUri()` |

Les deux diffs sont sauvés dans `~/.claude/projects/-home-florent-Projects-access-control-framework/upstream-patches/`, la branche Symfony qui les portait ayant été supprimée. Le troisième fichier de ce répertoire, `abandonne-frameworkbundle-integration.patch`, est l'intégration dans FrameworkBundle qui n'a plus lieu d'être : gardé pour mémoire, pas pour être rejoué.

Amont 2 est **contourné ici** par `ConsoleAccessPolicyListener::recordTheInputOnTheTracingWrapper()`, qui renseigne le wrapper avant de refuser. Le contournement reste correct si la PR passe.

Une troisième, plus large, ne peut pas être écrite telle quelle : `FrameworkExtension` refuse les gardes de workflow sans `symfony/security-core`, avant que `WorkflowGuardPass` ne remplace l'écouteur. Il faudrait un point d'extension générique amont, pas une mention d'un paquet hors Symfony. En attendant, `symfony/security-core` doit être installé, jamais utilisé, et c'est documenté.

## Ce que le portage a changé, à ne pas réintroduire

- **`ContainerBuilder::willBeAvailable()` est inutilisable ici.** Elle lit `Composer\InstalledVersions`, registre global au processus qu'alimente chaque autoloader chargé : sous un lanceur qui embarque son propre vendor, le paquet racine n'est plus celui de l'application et le pont Security cessait d'être chargé, en silence. Le monorepo Symfony ne pouvait pas le voir, la méthode ayant un cas spécial `'symfony/symfony' === $rootPackage`. Remplacée par `class_exists()`, comme les cinq autres conditions de la même méthode.
- **`AbstractController` et `ControllerHelper` exigent `AccessControlTrait`**, FrameworkBundle n'étant plus patché. La parité tient toujours : les contrôleurs de test prennent le trait et rien d'autre ne bouge.
- **`UnusedTagsPass`** ne connaît plus nos trois tags. Purement cosmétique, `debug:container` peut les signaler comme inutilisés.

## Le fond, par ordre décroissant d'importance

1. **Modéliser la délégation**, à trancher avant que RBAC quitte Security. Options et mesures dans le worklog, section « Délégation : l'arbitrage, mesuré ».
2. **Environnement typé** en remplacement de l'`AccessEnvironment` à clés libres. C'est aussi la réponse à natewiebe13 sur la désignation explicite de l'acteur.
3. **Reprendre le reste de `Security\Core\Role\*`** : `getParentRoleNames()`, `SwitchUserRole`, `Role`.
4. **L'arbre de politiques dans le profileur** : livré et non commité au moment de la clôture, voir la section du worklog du 2026-08-04. Vérifier qu'il a bien suivi le portage.

## À documenter, sinon les gens choisiront au hasard

- **Trois façons d'exprimer « A et B »** : stratégie `deny_overrides` sur les voters, attribut `All` sur les policies, `Expression`.
- **Deux écritures de règle d'URL** cohabitent, `security.access_control` et `access_control.rules`, et elles tiennent ensemble (`RulesWithSecurityTest`). La précision qui compte : `requires_channel` est enforcé par le pare-feu quand il y en a un, par notre `ChannelListener` sinon, jamais par les deux.
- **Code de sortie d'un refus en console** : 113 en dur, et l'échappatoire par un listener sur `ConsoleEvents::ERROR`.

## Arbitrages ouverts, petits

- **`role_prefix`** reste le seul réglage sans équivalent SecurityBundle.
- **`AccessDeniedException::setAttributes()` / `setSubject()` / `setAccessDecision()`** : Security les remplit, notre exception ne porte rien de tout ça. La question ne se pose plus dans les mêmes termes hors dépôt, plus rien n'étant à déprécier.
- **`access_decision()`** : divergence connue et documentée, un algorithme applicatif `Stringable` est rapporté par sa chaîne ; et `votes[].voter` nomme le manager pour tous les votes, un `AccessOutcome` ne connaissant pas son voter.

## Sans objet depuis la clôture de #59439

Le découpage en PR, la PR de dépréciation, et l'arbitrage `AccessControlBundle` contre câblage dans SecurityBundle. Gardés dans le worklog pour leurs mesures, pas pour leur plan.
