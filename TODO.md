# Todo

Journal de travail complet, arbitrages tranchés et mesures : `~/.claude/projects/-home-florent-Projects-access-control-framework/access-control-worklog.md`, hors dépôt pour ne pas publier un document de travail. Les diagrammes sont à côté. **À lire avant de reprendre**, pour ne pas refaire les mesures ni rouvrir ce qui est tranché.

## État

Portage hors du dépôt Symfony fait le 2026-08-17, après la clôture de symfony/symfony#59439. Suite verte à 623 tests et 1163 assertions sur PHP 8.4 comme sur 8.5, et sur la résolution la plus basse comme sur la plus haute. Outillage passé, CI branchée et verte, dépôt aligné sur les autres frameworks, les trois dépôts créés. **La mise en service est faite** : restent la recette Flex et la documentation.

## Mise en service

1. ~~**Créer les trois dépôts GitHub**~~ **fait le 2026-08-25**. `Spomky-Labs/access-control-framework` est public, branche par défaut `1.0.x`, et les deux cibles de split, `access-control-lib` et `access-control-bundle`, sont créées publiques et non archivées : gitsplit doit pouvoir y pousser, donc l'archivage n'est pas la façon de les rendre read-only, c'est leur `.github` qui s'en charge. **`GITSPLIT_TOKEN` n'était pas à poser** : il existe déjà comme secret de l'organisation `Spomky-Labs` et les trois dépôts le voient. Le workflow gitsplit est identique à celui de webauthn-framework aux noms près, et ne se déclenche qu'au tag ou à la publication d'une release : il n'a donc encore jamais tourné.
2. ~~**Brancher la CI**~~ **fait le 2026-08-17**. Deux choses manquaient, pas une. Les tâches d'abord : `castor.php` importait un dépôt frère qu'`actions/checkout` ne ramène pas, il est désormais **autonome**, sur le patron de webauthn-framework, et n'a besoin que de l'image, qui fournit castor et tous les outils. `.phpqa-config.php` est supprimé, plus personne ne le lisait. Le workflow ensuite : `reusable-ci.yml` de `spomky-labs/phpqa` **ne marche pas**, le premier push a échoué en une seconde avant le moindre job. Toutes les entrées qu'on lui passe existent, aucune n'est obligatoire, aucun secret n'entre en jeu, et le fichier est du YAML valide identique à la copie locale : la faute n'est pas dans l'appel, ce workflow n'a simplement aucun utilisateur, et webauthn-framework, son modèle, définit ses jobs lui-même. **Donc celui-ci aussi**, ce qui est de toute façon la pratique des autres frameworks. Infection n'est pas câblé, voir plus bas.
3. ~~**Passer l'outillage**~~ **fait le 2026-08-17**. Voir « L'outillage, ce qu'il a trouvé » plus bas : lint, ECS, Rector, PHPStan, Deptrac, validate et check-licenses sont verts. Infection est mis de côté.
3bis. ~~**Aligner le dépôt sur les autres frameworks**~~ **fait le 2026-08-17**, sur le patron de webauthn-framework : `.editorconfig`, `RELEASES.md`, et les fichiers de santé communautaire, des gabarits d'issue au guide de contribution, plus dependabot, renovate, les bots stale et lock-closed-issues, la revue de dépendances et le scorecard. **Les deux cibles de split disent maintenant qu'elles sont read-only là où ça compte** : chacune porte son `.github` avec le gabarit de PR qui renvoie ici, le workflow qui ferme une PR ouverte chez elle, le bot stale, et celui qui déplace la branche par défaut à chaque tag ; leur `.gitattributes` garde tout ça hors de l'archive distribuée. Un écart assumé : le `config.yml` des gabarits d'issue est du YAML invalide en amont, `about:|` sans espace, ce qui fait que GitHub jette le lien de contact sans rien dire. Corrigé ici, à remonter chez webauthn-framework.
4. **Recette Flex** pour `access-control-bundle`, dans `symfony/recipes-contrib`.
5. ~~**Documentation**~~ **écrite le 2026-08-25**, dans `~/Projects/access-control-doc`, sur la structure GitBook de webauthn-doc et jwt-doc : `README.md`, `SUMMARY.md` et 18 pages en cinq sections. Le README du dépôt est ramené à sa forme courte, badges et renvoi vers le site, et les deux README de sous-paquets pointent dessus. Publiée sur `Spomky-Labs/access-control-doc`, branche `1.0`, sur la convention de `phpwa-doc` où la branche porte le majeur et le mineur sans `.x`. GitBook est branché sur `acf.spomky-labs.com`, et les trois README y renvoient.

   Tout ce que cette liste signalait comme manquant y est : le vocabulaire XACML avec la table de correspondance et la raison pour laquelle `subject` désigne la ressource, `#[AccessPolicy]` et ses trois combinateurs, les requesters et l'acteur, le panneau de profil. Les trois points de « À documenter » aussi, plus les divergences assumées, rassemblées dans une page qui leur est consacrée. Chaque affirmation est vérifiée contre le code, pas contre le souvenir qu'on en a : la liste des états d'authentification, la signature des stratégies, le contrat des handlers et la forme de `AccessPolicyInterface` ont toutes été relues avant d'être écrites.

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

**Ce que le job « lowest deps » a trouvé, et il fallait la CI pour le voir.** Il installe la résolution la plus basse que les contraintes autorisent, et elle ne faisait pas tourner la suite : PHPUnit 10.5 et Symfony 8.0.

Deux mensonges de packaging derrière ça. **Rien ne déclarait `phpunit/phpunit`**, il arrivait par `matthiasnoback/symfony-config-test`, dont le plancher `^10.5` n'a rien à voir avec ce que nos tests exigent. Et **`^8.0` sur les paquets Symfony n'a jamais été vrai**, le portage n'ayant jamais été vert que sur 8.1 : `ControllerArgumentsEvent::evaluate()`, que le listener du pont Security appelle, et `RoleHierarchy::getParentRoleNames()` arrivent tous deux en 8.1. Les planchers sont désormais ceux qui sont mesurés, `^13.3` et `^8.1`.

**Et un vrai défaut dessous**, que seule la version basse expose : `RoleHierarchyAdapter` annonce `list<string>` et rendait ce que Security lui donnait. Or la forme de Security a changé **à l'intérieur d'un mineur**, 8.1.0 rend un tableau indexé par nom de rôle, 8.1.4 une liste. Donc sur certaines installations l'adaptateur répondait autre chose que son contrat, sans un mot. Même famille que les six dégradations silencieuses du journal, appliquée à la forme et non au contenu. Les deux tests de parité comparaient le tableau brut de Security au nôtre avec `assertSame`, donc ils vérifiaient les clés d'un tiers plutôt que les rôles ; ils comparent maintenant les valeurs.

**Deptrac : 0 violation, 366 dépendances autorisées.** La séparation Library / Bundle / Security tient telle qu'elle est déclarée. Les 6 « uncovered » du premier passage étaient PHPUnit, dont les espaces de noms `Test/` dépendent légitimement puisqu'ils sont publiés : une couche a été ajoutée plutôt qu'une dérogation.

**Un test qui n'assertait plus rien à chaud**, corrigé : `WorkflowGuardTest::guardListenerClassOf()` observe la classe de l'écouteur par une passe de compilation, mais son kernel partageait son répertoire de cache. Au deuxième lancement le conteneur venait du dump, la passe ne tournait pas, et l'assertion portait sur `null`. Mesuré en lançant le même test deux fois de suite : vert puis rouge. C'est exactement la famille « vérifier l'appel plutôt que le résultat » du journal. Le kernel observateur a désormais son répertoire, vidé avant boot. La suite entière est répétable, trois passages de suite dans le même conteneur.

**Infection : mis de côté, mais voici ce qu'un passage a donné.** Aucun job de mutation n'est câblé dans `ci.yml` ; la tâche marche à la main. Le chiffre est **83 % de MSI** pour 100 % de couverture de mutation, donc aucune partie de `src/` n'échappe aux tests ; ce sont les mutants qui survivent qui restent à regarder, 130 sur les 811 évalués, rapport dans `.ci-tools/infection.txt`.

Le chiffre n'a de sens qu'avec son budget de temps. Le `"timeout": 3` recopié de webauthn-framework est trop court ici, la suite étant dominée par des tests fonctionnels qui démarrent des kernels : **1026 mutants sur 1370 n'étaient jamais évalués**, et le MSI affiché, 74 %, ne portait que sur un quart d'entre eux. Passé à 30, 673 mutants sont tués au lieu de 250 et le MSI monte à 83 %, pour 2 min 15 au lieu de 58 s. **559 restent hors budget** : les monter demanderait plus de temps encore, et c'est un arbitrage de durée de CI, pas de qualité de test. La valeur est à 30 dans `.ci-tools/infection.json.dist`.

Deux réglages de ce fichier étaient faux et empêchaient tout lancement, corrigés : `source.directories` valait `src` au lieu de `../src`, Infection résolvant les chemins depuis le répertoire de sa configuration, et il manquait `phpUnit.configDir`. Pour la même raison, l'option `--coverage=.ci-tools/coverage` que passe la tâche castor donne `.ci-tools/.ci-tools/coverage` : c'est `--coverage=coverage` qu'il faut.

## Rien n'est emprunté à phpqa, et pourquoi

L'import `__DIR__ . '/../phpqa/.castor/phpqa.php'` visait un dépôt frère qu'`actions/checkout` ne ramène pas : mesuré, castor échouait avant toute tâche, donc tous les jobs tombaient. La réponse n'est pas de rapatrier ce dépôt en CI mais de ne rien lui demander : **l'image `ghcr.io/spomky-labs/phpqa` fournit castor et tous les outils**, les tâches vivent dans le dépôt. C'est ce que fait webauthn-framework.

`castor.php` porte donc les tâches en clair, sous le namespace `qa`, et `phpqa()` passe par l'image quand on est dehors, directement quand on est dedans, ce qui est le cas des jobs. Vérifié en copiant le fichier seul dans un répertoire sans dépôt frère : les 18 tâches se chargent.

**Le workflow réutilisable de phpqa a suivi le même chemin**, pour la même raison, une fois mesuré qu'il ne démarrait pas : voir le point 2 de la mise en service. Les jobs sont définis dans `ci.yml`, sur le patron de webauthn-framework, et appellent les tâches d'ici. Une conséquence à connaître : le job « Exported Files Check » compare l'archive à une liste écrite en dur, donc **ajouter un fichier à la racine sans l'`export-ignore` fait rougir la CI**, ce qui est le but.

Quatre corrections au passage, chacune mesurée. **Remontées chez `Spomky-Labs/phpqa` le 2026-08-25**, avec les deux blocages qui les précèdent : [#5](https://github.com/Spomky-Labs/phpqa/issues/5) l'import vers un dépôt frère, [#6](https://github.com/Spomky-Labs/phpqa/issues/6) le workflow réutilisable qui ne démarre pas, [#7](https://github.com/Spomky-Labs/phpqa/issues/7) `phpunit-11` en dur, [#8](https://github.com/Spomky-Labs/phpqa/issues/8) `allowFailure` et `composer normalize` sur l'hôte, [#9](https://github.com/Spomky-Labs/phpqa/issues/9) le chemin de couverture d'Infection, [#10](https://github.com/Spomky-Labs/phpqa/issues/10) ECS sans TTY.

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

## Le fond

Cette liste en comptait quatre. **Les quatre sont closes**, relues et vérifiées dans le code le 2026-08-25.

- ~~**Environnement typé**~~ **tranché le 2026-08-25 : on garde le sac à clés libres**, et on documente. La mesure a retourné la question. Le composant sème exactement quatre clés, `request` sur le web et `command`, `input`, `output` en console, et **n'en lit jamais aucune** : l'environnement est un transport vers l'`ExpressionVoter`, le `ClosureVoter` et le panneau, dont les consommateurs sont tous à clés-chaînes. Typer n'apporte donc rien à qui s'en sert, et mettrait HttpFoundation et Console dans des signatures d'une bibliothèque qui ne requiert que `php` et `symfony/event-dispatcher-contracts`. La faute de frappe, seule raison de typer, est déjà bruyante là où elle compte : une expression nommant une variable absente lève à la compilation. Le cas silencieux restant, `get('typo')` dans un voter applicatif, ne serait pas couvert non plus, les clés applicatives étant applicatives. Livré : les constantes `AccessEnvironment::REQUEST`, `COMMAND`, `INPUT`, `OUTPUT` et `SEEDED_KEYS`, utilisées là où les clés sont semées, et **un test par point d'entrée qui épingle le jeu de clés**, le web l'était déjà, la console ne l'était pas.

Les trois autres, avec ce qui a été vérifié plutôt que supposé :

- ~~**Modéliser la délégation**~~ **tranché et appliqué le 2026-08-03**, option A, et le portage l'a conservé intact : `DelegatedRequesterInterface::getActor()`, `Requester\Actor` comme seul endroit qui connaît les deux façons de le dire, les deux voters qui l'appellent sans rejouer la règle, la variable `actor` publiée seulement quand il y en a un, et la branche `IS_IMPERSONATOR` remontée au-dessus du garde de token. Vérifié aussi : **plus une seule référence à `SwitchUserToken` dans le cœur** hors `Requester\Actor`. Ce que la décision ne couvrait pas, la portée de la délégation, reste un ajout de fonctionnalité que Symfony ne modélise nulle part et qui ne bloque rien.
- ~~**Reprendre le reste de `Security\Core\Role\*`**~~ **fait, et plus court que la note ne le laissait croire.** `getParentRoleNames()` est implémenté sur `RoleHierarchy`, avec ses tests de parité, et délibérément **pas** déclaré sur notre interface : l'annoncer serait une obligation pour toute implémentation, que `DebugClassLoader` fait respecter, alors qu'aucun voter ne pose la question. `Role` et `SwitchUserRole` n'ont rien à reprendre : `@internal`, constructeur privé, aucun comportement, ce sont des coquilles pour relire des sessions Symfony v4.
- ~~**L'arbre de politiques dans le profileur**~~ **a bien suivi le portage**, vérifié pièce par pièce : `AccessPolicyEvent` avec son parent, l'évaluateur qui dispatche chaque nœud avec sa pile, `getPolicies()`, le collecteur qui reconstruit l'arbre en pré-ordre, le gabarit, et le vide jugé sur les questions et non sur les décisions. Douze tests verts le couvrent, dont « le composite qui a fait le verdict est nommé » et « un composite qui s'écarte le dit ».

## ~~À documenter, sinon les gens choisiront au hasard~~ fait

Les trois sont écrits, avec la règle de choix que la note réclamait plutôt qu'un simple inventaire.

- **Trois façons d'exprimer « A et B »**, dans « Combining Algorithms » : `deny_overrides` quand la conjonction est une propriété de tout le modèle, `All` quand c'est ce point d'entrée-là qui exige deux questions, `Expression` quand une moitié n'est pas une question mais une condition.
- **Deux écritures de règle d'URL**, dans « URL Rules », avec ce qui compte vraiment : les portées diffèrent, l'union est une intersection de permissions, et déplacer une règle sans supprimer l'originale est le cas qui ne lève pas. `requires_channel` est enforcé par le pare-feu quand il y en a un, par notre `ChannelListener` sinon, jamais par les deux.
- **Code de sortie d'un refus en console**, dans « Console Commands » : `RETURN_CODE_DISABLED`, soit 113, pourquoi il n'est pas réglable, et l'échappatoire par un listener sur `ConsoleEvents::ERROR`.

## Arbitrages ouverts, petits

- **`role_prefix`** reste le seul réglage sans équivalent SecurityBundle.
- **`AccessDeniedException::setAttributes()` / `setSubject()` / `setAccessDecision()`** : Security les remplit, notre exception ne porte rien de tout ça. La question ne se pose plus dans les mêmes termes hors dépôt, plus rien n'étant à déprécier.
- **`access_decision()`** : divergence connue et documentée, un algorithme applicatif `Stringable` est rapporté par sa chaîne ; et `votes[].voter` nomme le manager pour tous les votes, un `AccessOutcome` ne connaissant pas son voter.

## Sans objet depuis la clôture de #59439

Le découpage en PR, la PR de dépréciation, et l'arbitrage `AccessControlBundle` contre câblage dans SecurityBundle. Gardés dans le worklog pour leurs mesures, pas pour leur plan.
