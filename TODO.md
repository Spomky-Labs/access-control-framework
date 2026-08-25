# Todo

Journal de travail complet, arbitrages tranchés et mesures : `~/.claude/projects/-home-florent-Projects-access-control-framework/access-control-worklog.md`, hors dépôt pour ne pas publier un document de travail. Les diagrammes sont à côté. **À lire avant de reprendre**, pour ne pas refaire les mesures ni rouvrir ce qui est tranché.

## État

Portage hors du dépôt Symfony fait le 2026-08-17, après la clôture de symfony/symfony#59439. Suite verte sur Symfony 8.1 publié : 623 tests, 1163 assertions, sur PHP 8.4 comme sur 8.5. Outillage passé, CI branchée, dépôt aligné sur les autres frameworks : il ne reste que la création des dépôts GitHub.

## Mise en service

1. **Dépôts GitHub** : `Spomky-Labs/access-control-framework` est **créé et public**, branche par défaut `1.0.x`. Restent les deux cibles de split, `access-control-lib` et `access-control-bundle`, et le secret `GITSPLIT_TOKEN`. Sans eux le workflow gitsplit échouera, mais il ne se déclenche qu'au tag ou à la publication d'une release : rien ne presse tant qu'on ne tague pas.
2. ~~**Brancher la CI**~~ **fait le 2026-08-17**. Deux choses manquaient, pas une. Les tâches d'abord : `castor.php` importait un dépôt frère qu'`actions/checkout` ne ramène pas, il est désormais **autonome**, sur le patron de webauthn-framework, et n'a besoin que de l'image, qui fournit castor et tous les outils. `.phpqa-config.php` est supprimé, plus personne ne le lisait. Le workflow ensuite : `reusable-ci.yml` de `spomky-labs/phpqa` **ne marche pas**, le premier push a échoué en une seconde avant le moindre job. Toutes les entrées qu'on lui passe existent, aucune n'est obligatoire, aucun secret n'entre en jeu, et le fichier est du YAML valide identique à la copie locale : la faute n'est pas dans l'appel, ce workflow n'a simplement aucun utilisateur, et webauthn-framework, son modèle, définit ses jobs lui-même. **Donc celui-ci aussi**, ce qui est de toute façon la pratique des autres frameworks. Infection n'est pas câblé, voir plus bas.
3. ~~**Passer l'outillage**~~ **fait le 2026-08-17**. Voir « L'outillage, ce qu'il a trouvé » plus bas : lint, ECS, Rector, PHPStan, Deptrac, validate et check-licenses sont verts. Infection est mis de côté.
3bis. ~~**Aligner le dépôt sur les autres frameworks**~~ **fait le 2026-08-17**, sur le patron de webauthn-framework : `.editorconfig`, `RELEASES.md`, et les fichiers de santé communautaire, des gabarits d'issue au guide de contribution, plus dependabot, renovate, les bots stale et lock-closed-issues, la revue de dépendances et le scorecard. **Les deux cibles de split disent maintenant qu'elles sont read-only là où ça compte** : chacune porte son `.github` avec le gabarit de PR qui renvoie ici, le workflow qui ferme une PR ouverte chez elle, le bot stale, et celui qui déplace la branche par défaut à chaque tag ; leur `.gitattributes` garde tout ça hors de l'archive distribuée. Un écart assumé : le `config.yml` des gabarits d'issue est du YAML invalide en amont, `about:|` sans espace, ce qui fait que GitHub jette le lien de contact sans rien dire. Corrigé ici, à remonter chez webauthn-framework.
4. **Recette Flex** pour `access-control-bundle`, dans `symfony/recipes-contrib`.
5. **Documentation** : le README couvre l'installation et les deux migrations ; il manque le vocabulaire XACML, `#[AccessPolicy]` et ses combinateurs, les requesters, et le panneau de profil.

## L'outillage, ce qu'il a trouvé

Premier passage le 2026-08-17, sur la suite verte de départ (623 tests, 1163 assertions). Elle l'est restée à l'arrivée, mêmes comptes, ce qui est le contrôle qui compte : un outil qui réécrit du code peut retirer une assertion sans rien casser.

**Trois règles Rector écartées, chacune pour une raison mesurée**, motifs dans le `withSkip()` de `.ci-tools/rector.php` :

| Règle | Ce qu'elle faisait |
|---|---|
| `RenameStringRector` | Réécrivait `'ROLE_PREVIOUS_ADMIN'` en `'IS_IMPERSONATOR'` sur la table de renommage de Symfony, qui confond les deux vocabulaires que le composant sépare : un nom de rôle, lu par `RoleVoter` à son préfixe, et un état d'authentification, lu par `AuthenticatedVoter`. `RoleVoterTest` a cassé ; `SecurityParityTest` a **fusionné deux assertions distinctes en la même, deux fois, en restant vert** |
| `GetDebugTypeRector` | Réduisait la clé du sujet à `get_debug_type()` là où `AccessDecisionManager::getVoters()` calcule `is_object($object) ? $object::class : get_debug_type($object)`. `VoterAdapter` recopie cette ligne exprès, pour que le `supportsType()` d'un voter applicatif reçoive la même chaîne des deux piles ; les réponses divergent sur les classes anonymes |
| `GetFiltersAndFunctionsToAsTwigAttributeRector` | Retirait `AbstractExtension` au profit de `#[AsTwigFunction]`, qui exige Twig 3.21 et resserrerait le `^3.12\|^4.0` publié, sans rien apporter, sur la seule intégration qu'une divergence silencieuse a déjà mordue |

**Un défaut trouvé par PHPStan**, corrigé : `AccessDecision::grant()`, `deny()` et `abstain()` annonçaient `@param iterable<AccessOutcome>` alors qu'elles passent au constructeur qui attend `iterable<CastVote>`, et que le corps lit `$vote->outcome`. Docblocks restés en arrière quand `CastVote` est apparu (`684fdf23d80`). 21 des 156 erreurs venaient de là.

Les 135 restantes sont en baseline. Rien d'alarmant dedans : l'essentiel est du `mixed` venu des tableaux de configuration Symfony et des idiomes `!$array` que les règles strictes refusent. Deux familles à ne pas relire comme des manques : le `debug_backtrace` d'`AccessDecisionLoggerListener` **est** la fonctionnalité d'origine et d'appelant du journal, et les cinq traits « utilisés zéro fois » sont l'outillage public de test plus `AccessControlTrait`, que seuls les consommateurs utilisent.

**Deptrac : 0 violation, 366 dépendances autorisées.** La séparation Library / Bundle / Security tient telle qu'elle est déclarée. Les 6 « uncovered » du premier passage étaient PHPUnit, dont les espaces de noms `Test/` dépendent légitimement puisqu'ils sont publiés : une couche a été ajoutée plutôt qu'une dérogation.

**Un test qui n'assertait plus rien à chaud**, corrigé : `WorkflowGuardTest::guardListenerClassOf()` observe la classe de l'écouteur par une passe de compilation, mais son kernel partageait son répertoire de cache. Au deuxième lancement le conteneur venait du dump, la passe ne tournait pas, et l'assertion portait sur `null`. Mesuré en lançant le même test deux fois de suite : vert puis rouge. C'est exactement la famille « vérifier l'appel plutôt que le résultat » du journal. Le kernel observateur a désormais son répertoire, vidé avant boot. La suite entière est répétable, trois passages de suite dans le même conteneur.

**Infection : mis de côté, mais voici ce qu'un passage a donné.** Aucun job de mutation n'est câblé dans `ci.yml` ; la tâche marche à la main. Le chiffre est **83 % de MSI** pour 100 % de couverture de mutation, donc aucune partie de `src/` n'échappe aux tests ; ce sont les mutants qui survivent qui restent à regarder, 130 sur les 811 évalués, rapport dans `.ci-tools/infection.txt`.

Le chiffre n'a de sens qu'avec son budget de temps. Le `"timeout": 3` recopié de webauthn-framework est trop court ici, la suite étant dominée par des tests fonctionnels qui démarrent des kernels : **1026 mutants sur 1370 n'étaient jamais évalués**, et le MSI affiché, 74 %, ne portait que sur un quart d'entre eux. Passé à 30, 673 mutants sont tués au lieu de 250 et le MSI monte à 83 %, pour 2 min 15 au lieu de 58 s. **559 restent hors budget** : les monter demanderait plus de temps encore, et c'est un arbitrage de durée de CI, pas de qualité de test. La valeur est à 30 dans `.ci-tools/infection.json.dist`.

Deux réglages de ce fichier étaient faux et empêchaient tout lancement, corrigés : `source.directories` valait `src` au lieu de `../src`, Infection résolvant les chemins depuis le répertoire de sa configuration, et il manquait `phpUnit.configDir`. Pour la même raison, l'option `--coverage=.ci-tools/coverage` que passe la tâche castor donne `.ci-tools/.ci-tools/coverage` : c'est `--coverage=coverage` qu'il faut.

## Rien n'est emprunté à phpqa, et pourquoi

L'import `__DIR__ . '/../phpqa/.castor/phpqa.php'` visait un dépôt frère qu'`actions/checkout` ne ramène pas : mesuré, castor échouait avant toute tâche, donc tous les jobs tombaient. La réponse n'est pas de rapatrier ce dépôt en CI mais de ne rien lui demander : **l'image `ghcr.io/spomky-labs/phpqa` fournit castor et tous les outils**, les tâches vivent dans le dépôt. C'est ce que fait webauthn-framework.

`castor.php` porte donc les tâches en clair, sous le namespace `qa`, et `phpqa()` passe par l'image quand on est dehors, directement quand on est dedans, ce qui est le cas des jobs. Vérifié en copiant le fichier seul dans un répertoire sans dépôt frère : les 18 tâches se chargent.

**Le workflow réutilisable de phpqa a suivi le même chemin**, pour la même raison, une fois mesuré qu'il ne démarrait pas : voir le point 2 de la mise en service. Les jobs sont définis dans `ci.yml`, sur le patron de webauthn-framework, et appellent les tâches d'ici. Une conséquence à connaître : le job « Exported Files Check » compare l'archive à une liste écrite en dur, donc **ajouter un fichier à la racine sans l'`export-ignore` fait rougir la CI**, ce qui est le but.

Quatre corrections au passage, chacune mesurée, à remonter chez phpqa dont la copie centralisée les porte encore.

1. **`qa:phpunit` appelait `phpunit-11` en dur**, le binaire de l'image, pas celui du projet. Sous PHPUnit 11 la suite montre **27 échecs** qui ne sont pas des régressions : les tests utilisent `expectExceptionMessageIsOrContains()`, API de PHPUnit 12+. `composer exec -- phpunit` résout `vendor/bin/phpunit`, soit 13.3.1, et la suite est verte sur PHP 8.4. Un projet se teste avec le PHPUnit qu'il embarque.
2. **`qa:validate` cassait** sur `run(..., allowFailure: true)` : castor v1.7 veut `context()->withAllowFailure()`. Corrigé, et `composer normalize` passe maintenant par l'image, où le greffon existe, au lieu de l'hôte où il manquait et où la vérification ne disait donc rien. Les trois `composer.json` sont normalisés.
3. **`qa:infect` passait `--coverage=.ci-tools/coverage`**, alors qu'Infection résout ce chemin depuis le répertoire de sa configuration : il cherchait `.ci-tools/.ci-tools/coverage`. C'est `--coverage=coverage`, ce qu'écrit d'ailleurs webauthn-framework.
4. **Sans TTY, tout ECS mourait** sur `str_repeat(' ', -2)` : la largeur de terminal vaut 0, et le rapporteur d'erreur casse en rapportant la casse. `COLUMNS` est posé, et `-it` n'est demandé que s'il y a un terminal.

`.phpqa-config.php` a disparu avec l'import : plus rien ne le lisait, et la version de PHP qu'il épinglait est maintenant `DEFAULT_PHP_VERSION` dans `castor.php`, alignée sur le `default_php_version` de la CI.

**Reste un blocage qui n'appartient à personne ici : Infection 0.32.7 contre PHPUnit 13.** Infection écrit `executionOrder="defects,random"` avec `cacheResult="false"` dans la configuration qu'il génère ; PHPUnit 13 refuse la combinaison, prévient que l'historique n'est pas enregistré et n'exécute **aucun** test, donc Infection conclut que la suite est rouge. Contourné dans la tâche par `--test-framework-options=--order-by=default`. C'est la raison, avec le budget de temps, pour laquelle aucun job de mutation n'est câblé dans `ci.yml` ; la tâche marche à la main.

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
