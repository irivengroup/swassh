# Décisions courantes approuvées — C67

Les décisions datées et leurs états courants sont fournis dans chaque context-*.json et dans le document de revue détaché. Le texte ci-dessous conserve la note préparatoire initiale ; ses mentions « en attente » décrivent cette étape antérieure, pas les décisions courantes. Aucune approbation historique n’est transférée.

## Note préparatoire conservée

# Revue contextuelle individuelle — candidat C67

Archive : `ed558764fdb4d9e76c79b11e5eb5d76c68a5b7d2ec85dc87dc1042f723581240`.
Cette note prépare les décisions ; **elle n'est ni une approbation externe, ni
une qualification SAST réussie**. Les 174 décisions de l'inventaire restent en
attente jusqu'au rapprochement avec leurs preuves. Les identités des fichiers,
signaux complets et appelants sont liées par l'inventaire de 328 fichiers.

Les binaires natifs et wrappers configurés par l'opérateur sont une frontière
de confiance déclarée. Une liste argv n'est pas, à elle seule, une preuve de
confiance dans un exécutable. Les helpers de QA ne constituent pas des serveurs
acceptant des commandes d'un utilisateur distant. Les preuves de recette sont
attendues sur l'archive extraite ; les exemples C66 ne qualifient aucun signal
du projet par analogie.

| Signal | Flux et préconditions examinés | Justification contextuelle et limite |
| --- | --- | --- |
| C66-001 | `benchmarks/core.py`, import et usages dans `relay` | Deux workers au plus dans la recette, quatre au plus par validation CLI. L'import sert au lancement du pair Python local défini dans C66-002. Aucun programme fourni par un serveur. |
| C66-002 | `relay`: interpréteur courant, module fixe `swassh.infrastructure.tcp_proxy`, loopback, ports du serveur éphémère | argv sans shell ; durée de relais 15 s, communicate 12 s, arrêt et collecte dans finally. Les octets échangés sont une charge synthétique ; ce benchmark ne mesure pas la cryptographie SSH. |
| C66-003 | `auth_fixture.py`, tous les appels `run` et le daemon KDC | Le seul appelant réel est `AuthenticationGate.isolated`, PID 1 dans des namespaces PID/réseau/montage privés. Les tests hors namespace remplacent la frontière native. Le périmètre direct du helper exige cette isolation. |
| C66-004 | Helper `run(argv)` : useradd, chpasswd, kdb5_util, kadmin.local, kinit | Outils système dans PATH explicite, arguments construits localement, secrets aléatoires transmis en entrée standard, timeout 30 s et erreur propagée. Les modifications de comptes touchent l'overlay privé de `/etc`. |
| C66-005 | `krb5kdc` résolu par `shutil.which(..., path=_SYSTEM_TOOL_PATH)` | Exécutable système fixe, configuration et fichiers privés, pas de shell. Le namespace PID du lanceur contient le daemon et sa destruction le termine ; ne pas présenter cette propriété comme un nettoyage autonome du helper appelé hors de son contrat. |
| C66-006 | `install.py`, import utilisé par les deux appels relus ci-dessous | Outil de déploiement déclenché explicitement par l'opérateur ; wheel locale et index configuré sont des sources de code de confiance, pas des entrées d'inventaire distant. |
| C66-007 | Installation pip de la wheel absolue ou `swassh==VERSION` | Distribution fixe, version validée par regex numérique complète, argv sans shell, wheel `.whl`/préfixe contrôlés, `--no-index` pour la wheel locale. Le choix d'un venv et de son interpréteur appartient à l'opérateur. Le code de sortie pip est retourné. |
| C66-008 | `python -m swassh setup-path` après installation réussie | Sous-commande fixe ; `--app-venv` seulement si le venv a été demandé. Échec d'installation et option skip empêchent cet appel ; le code de sortie est propagé. Ce helper n'est pas une sandbox pour une wheel hostile. |
| C66-009 | `native_auth_gate.py`, tous les appels de la classe AuthenticationGate | Résolveur limité à mount/ip/unshare dans les répertoires système ; vérification Linux/root, puis PID 1 côté isolé. Aucun argument réseau distant ne choisit un outil local. |
| C66-010 | Montage overlay de `/etc` côté isolé | Arguments constants et répertoires d'un TemporaryDirectory ; PID 1 exigé, aucun shell, check=True. L'opération nécessite les privilèges déjà explicitement réservés à la recette privée. |
| C66-011 | Montage tmpfs privé sur `/root` | Argumentaire fixe, mode0700, check=True ; reste dans le namespace de montage privé. Ce n'est pas un montage sur l'hôte. |
| C66-012 | Activation de l'interface loopback | Outil `ip` de confiance, sous-commande fixe `link set lo up`, check=True ; namespace réseau privé. |
| C66-013 | Entrée par `unshare --mount --pid --net --fork --kill-child --mount-proc` | Timeout180 s ; interpréteur courant et script absolu, répertoire privé, PATH fixe. La fermeture de PID1 termine les descendants du namespace. Le test d'autorisation du namespace reste nécessaire. |
| C66-014 | `platform_gate.py` : import et deux sondes | Exécutables sélectionnés dans le PATH de l'opérateur, contrat explicitement limité à configuration/version, aucune preuve de provenance binaire prétendue. Deux sondes locales bornées ; pas de connexion SSH. |
| C66-015 | `rsync --version` | argv fixe après résolution locale ; timeout10 s, version et code vérifiés. N'exécute pas une chaîne distante. |
| C66-016 | `ssh -G -F CONFIG swassh-target` | CONFIG écrit dans un répertoire privé depuis les valeurs strictes du profil ; `-G` imprime la configuration sans connexion. Timeout10 s, sortie UTF8 bornée et paramètres effectifs vérifiés individuellement. |
| C66-017 | `qualify_schedule.py`, import et appels CLI de ScheduleCampaign | Tous les programmes sont l'interpréteur courant et le module SWASSH du paquet extrait. Le faux SSH est créé depuis le fichier de test détenu dans un répertoire privé ; aucun équipement distant. |
| C66-018 | `cli(*arguments)` | argv séparé, cwd privé et environnement de fixture ; timeout45 s et codes attendus contrôlés. Les commandes de scénario `ok-*` et `failed` sont constantes, non des commandes système locales. |
| C66-019 | Invocation manuelle concurrente | `python -m swassh run ok -H manual` avec le même faux SSH privé ; attente45 s, kill et collecte5 s dans finally. Vérifications d'appel exact et absence de rejeu conservées. |
| C66-020 | `scheduler_service.py`, import ElementTree | Le générateur crée et sérialise ses propres arbres XML pour SMF et Windows ; il ne désérialise aucun XML distant. Les chemins et arguments sont validés/échappés par le générateur. La validité native des plateformes exclues n'est pas prétendue. |
| C66-021 | `validate_deployment.py`, import et cinq lancements | Index HTTP limité à127.0.0.1 dans un TemporaryDirectory, wheel produite depuis les sources locales et accompagnée de son SHA. Environnement de l'opérateur isolé et serveur fermé en finally. |
| C66-022 | Premier déploiement par `scripts/install.py` | Programme détenu dans les sources extraites, version du pyproject, venv neuf ; timeout120 s. Variables pip influençant cible/index supplémentaires retirées ; index privé de loopback. |
| C66-023 | Lecture de version installée | Interpréteur du venv neuf, module et option fixes ; timeout30 s, comparaison exacte à la version canonique. |
| C66-024 | Shell de vérification du PATH POSIX | `/bin/sh -c` reçoit un programme **constant** ; le chemin du profil est un argument positionnel `$1`, jamais interpolé dans ce programme. Le profil est généré par le paquet dans HOME éphémère ; timeout30 s et sortie exacte vérifiés. |
| C66-025 | Répétition du déploiement | Même commande et environnement privés que C66-022, timeout120 s ; le test vérifie le succès et l'identité du profil avant/après. |
| C66-026 | Version volontairement absente de l'index privé | Valeur numérique fixe, timeout60 s ; échec obligatoire et profil inchangé. Aucun remplacement du code d'échec par un succès. |
| C66-027 | `validate_installation.py`, import et helper `call` | Interpréteur d'un venv neuf, arguments construits par les scénarios d'installation, cwd privé, PYTHONPATH externe retiré. Les artefacts sont la wheel/sdist de la recette, pas un upload distant. |
| C66-028 | `Popen([executable, *arguments])` | Sans shell ; communicate60 s, kill/wait5 s sur timeout ; stdout/stderr et code conservés et comparés à l'attente. Les commandes `-c` sont des programmes constants vérifiant les sources installées ; leurs données sont séparées. |
| C66-029 | `verify.py`, import dans `isolated_run` | Le seul enfant est le cas TransferTests identifié par une constante ; identité de script/test/runtime et nonce contrôlée. Une suite incomplète, modifiée, échouée ou ignorée ne peut produire un succès. |
| C66-030 | Worker de test Windows3.12 | Interpréteur courant, chemin résolu du script, arguments internes fixes et nonce aléatoire. Journal borné8MiB, budget total900 s, KillJob de parent et contrôle du reçu. Aucun choix de programme par une entrée réseau. |
| C66-031 | WorkflowSchema.down, noms `runs/steps/events` | Interpolation d'un tuple fermé de noms internes ; aucune valeur utilisateur dans un identifiant SQL. Schema validé et downgrade refusé si données ou outbox présentes. |
| C66-032 | `native_ready.py`, tous usages de subprocess | Seul usage : list2cmdline pour un callback fixe et une enveloppe base64 bornée. Ni Popen ni run ; chemin de l'interpréteur refusé s'il contient des métacaractères Windows. La réception valide chemin/token et écrit atomiquement dans un répertoire épinglé. |
| C66-033 | `process_guard.py`, import et lancement gardé | L'import sert au gardien de processus natif et à ses types d'erreurs. L'exécutable natif configuré demeure de confiance ; ne pas prétendre une vérification universelle de propriétaire du binaire SSH. |
| C66-034 | `Popen(argv)` du gardien | argv vient de la spécification privée et validée du parent, sans shell ; budget et admission acquis avant lancement, groupe POSIX privé, surveillance du parent et arrêt/collecte avant libération de la capacité. Le chiffrement/authentification restent assurés par OpenSSH choisi par l'opérateur. |
| C66-035 | Import dans NativeConnector._supports | Un seul lancement relu en C66-036, sur le helper contrôlé par `_trusted_info` et ses ancêtres, y compris sur un hit du cache. |
| C66-036 | Sonde `helper -h` | Chemin réel contrôlé, fichier régulier de propriétaire autorisé non modifiable par groupe/autres, arguments constants, session séparée. Sortie8192octets, délai1 s, leader borné2 s et groupe arrêté en finally ; preuve de non-fuite C64 conservée. |
| C66-037 | Import dans NativeConnector._nodelay | Un seul lancement relu en C66-038 ; sonde de capacité avant sélection, pas de repli après lancement de la commande cible. |
| C66-038 | Sonde réelle de descripteur helper | Même contrôle de confiance ; cible127.0.0.1 et port alloué localement, socketpair détenu, groupe propre et cleanup C64. Le test vérifie TCP_NODELAY du descripteur effectivement livré ; aucun SSH distant. |
| C66-039 | SQLiteScheduleStore.list | Liste de colonnes issue de JobInfo défini par le programme ; `limit` et `offset` validés puis liés comme paramètres. Aucun nom de colonne fourni par l'utilisateur. |
| C66-040 | PersistentSSHTransport.open, TemporaryDirectory(dir='/tmp') | mkdtemp crée un répertoire aléatoire privé0700, puis config/diagnostic0600. `/tmp` raccourcit le chemin UNIX du socket ; ce n'est pas un fichier prévisible ouvert directement. Transport POSIX uniquement, nettoyage gardé et absence de repli mux. |
| C66-041 | Import local dans tcp_proxy.proxy_command | `subprocess` sert seulement à list2cmdline sous Windows ; programme fixe, enveloppe base64 à schéma/type/budget stricts, chemin d'interpréteur sans métacaractères. Le shell POSIX utilise shlex.quote. |
| C66-042 | SQLiteWorkflowStore._row | Colonnes choisies entre deux chaînes constantes selon le booléen payload ; id validé et lié avec `?`. Aucune colonne ni expression SQL d'origine distante. |
| C66-043 | SQLiteWorkflowStore.list, clause IN | Le texte interpolé est exclusivement une suite de `?` créée à partir de1..200 lignes déjà lues ; les identifiants sont liés via tuple(grouped). Pagination validée ; aucun identifiant n'est concaténé au SQL. |
| C67-172 | Import dans scripts/sast_gate.py ; deux appels seulement, lignes 317 et 389. | Import sans lancement. Le bootstrap de confiance vérifie le SHA du gate avant chargement ; la revue externe lie les 328 entrées propres avant installation. Ni règle ni sévérité ne suffit à qualifier une alerte. Les répertoires QA préexistants sont refusés. |
| C67-173 | Interpréteur du venv opérateur -> programme constant de métadonnées sous -I -B -> JSON. | Timeout30 s/check=True ; hooks, variantes de casse des caches, jonctions et objets spéciaux refusés avant lancement. Les huit wheels, leurs fichiers et toute métadonnée supplémentaire sont contrôlés ; seuls les marqueurs inertes de pip sont attendus ; le chemin du venv POSIX reste lexical. Le runtime de l’opérateur est une frontière explicite. |
| C67-174 | Commande Bandit constante couvrant src/tests/scripts/build_support/benchmarks -> rapport brut et code réel. | Sans shell, filtre, baseline ou suppression ; --ignore-nosec et timeout300 s. Le rapport est lu une fois, son SHA porte sur les mêmes octets que la vue analysée. Toute modification de source, outil, preuve ou autorité invalide la revue. La qualification sécurité n’autorise pas la publication et ne remplace pas la recette complète. |

## Contextes de test sensibles

Ces lignes sont des scénarios de test, pas des entrées réelles. Leur revue
examine les producteurs des données et les assertions qui les consomment,
sans présumer qu'un fichier de test est automatiquement inoffensif.

| Signal | Flux examiné | Justification et limite |
| --- | --- | --- |
| C66-044 | parent_token=None dans une requête synthétique du gardien POSIX | Ce champ désactive le jeton de processus Windows dans un scénario à descripteur parent simulé ; aucune valeur d'authentification réelle. Les frontières natives sont remplacées dans ce test et les délais d'admission sont assertés. |
| C66-048 | random.Random(84723), 2000 transitions de ByteWindow | Générateur à graine fixe pour comparer le débit à un oracle indépendant ; il ne génère ni secret, ni identifiant de sécurité. |
| C66-055 | UPDATE bucket sur field pris dans six couples constants rate/credits/observed | Corruption volontaire de la base privée de la fixture ; valeur liée par `?`, erreur de reserve attendue, puis restauration des compteurs originaux. Aucun nom externe. |
| C66-056 | SELECT du même champ de bucket | Lecture d'un identifiant de colonne du tuple fermé ci-dessus ; assertion que la corruption refusée reste observable, sans réparation implicite. |
| C66-058 | random.Random(90210+rate), oracle CreditPool | Simulation déterministe de clients, remboursements et écritures retardées ; aucun usage cryptographique, aucune donnée réelle. |
| C66-061 | bind_address='0.0.0.0' soumis à replace(LocalForward) | Le scénario attend ValueError avant toute socket ; il vérifie précisément l'interdiction d'un bind universel. Les cas permis sont127.0.0.1 et::1. |
| C66-065 | bind universel dans test_configuration_matrix | Même valeur dangereuse fournie au validateur en mémoire et refus exigé ; aucune écoute universelle créée. Les ports et destinations invalides sont aussi refusés. |
| C66-076 | Import pickle dans test_credit_state_compatibility | Deux seuls loads, relus individuellement ci-dessous, portant sur les octets immédiatement produits par dumps d'un CreditPool local. Aucun fichier ou canal d'entrée pickle. |
| C66-077 | pickle.loads(pickle.dumps(value)) | value est construit dans le test depuis le type CreditPool détenu dans les sources ; comparaison d'égalité après aller/retour. Aucun octet d'origine externe. |
| C66-078 | hash(value) comparé au hash d'un aller/retour pickle | Même producteur local immédiat ; protège le contrat de représentation publique après réorganisation interne. Ne prétend pas rendre pickle sûr pour une entrée non fiable. |
| C66-079 | temporary_path='/tmp/file' dans replace(TransferReceipt) | Chaîne de modèle en mémoire, sans création, ouverture ou déplacement de fichier ; assertion de conservation du champ. Les types, longueurs et caractères invalides sont testés à côté. |
| C66-080 | Littéral attendu '/tmp/file' dans la même assertion | Deuxième signal/position conservé distinctement ; simple comparaison de texte, aucun accès au chemin. |
| C66-086 | Import pickle dans test_guardian_relay | Seul loads relu en C66-088, issu du Host construit dans le test ; le reste du module teste les limites de socket/relay séparément. |
| C66-088 | Aller/retour pickle du Host local | Producteur dumps immédiatement adjacent et type de domaine contrôlé, égalité et identité de module vérifiées ; aucun flux réseau désérialisé. |
| C66-096 | publish_command('/tmp/private','/srv/final',digest) | Le test inspecte la **chaîne générée**, il ne lance pas cette commande et ne touche pas ces chemins. Le digest est synthétique ; outil et digest invalides doivent être refusés. |
| C66-098 | parent_token=None dans le scénario POSIX du gardien | Parent identifié par os.getpid et tube réel ; aucun jeton secret codé en dur. Paramètre Windows absent volontairement ; restaurations de signaux et ressources de fixture encadrent le test. |
| C66-117 | champ secret='x' d'une procédure réseau invalide | Le décodeur doit lever ValueError : clé inattendue et valeur factice, jamais un secret utilisé pour authentifier un équipement. Aucun dialogue réseau lancé par ce cas. |
| C66-121 | Import ElementTree dans test_portability | Les deux parses signalés relisent les documents produits par le générateur du projet dans des répertoires de test ; aucune entrée XML distante. |
| C66-122 | fromstring(data) de generate('smf',...) | Octets retournés en mémoire par le générateur, utilisateur/chemins de test contrôlés ; assertions sur identité, disabled, méthode et échappement des pourcentages. Le DTD SMF est un texte de sortie, aucune résolution externe n'est demandée. |
| C66-123 | fromstring(manifest.read_bytes()) après SERVICE.main | Fichier neuf dans TemporaryDirectory, généré exclusivement par le test ; permissions et refus de réécriture vérifiés. Ne démontre pas une validation native Solaris. |
| C66-124 | '/var/tmp/state with spaces' vers generate('src') | Entrée textuelle du générateur, vérification foreground/umask ; aucun répertoire partagé créé ou service AIX activé. |
| C66-136 | parent_token=1234 dans une requête Windows simulée | Identifiant factice du double ParentProcess, aucune clé ou authentification réelle ; vérifie l'utilisation de la bonne frontière sous os.name simulé. |
| C66-137 | Même parent_token=1234 dans scénario de cleanup Windows | Les doubles ParentProcess/KillJob remplacent le noyau ; le test exige le bon code et l'ordre de fermeture/terminaison. Ce n'est pas une credential utilisable. |
| C66-138 | SELECT champ de leases pour sauvegarder l'ancienne valeur | `field` vient du tuple fermé connections/memory/bandwidth/active ; lease.identity est liée par `?`, base privée. |
| C66-139 | UPDATE du champ de leases volontairement corrompu | Valeur et identité liées ; identifiant interne constant ; lease.poll doit refuser le budget invalide. Aucune base de production. |
| C66-140 | Restauration du champ de leases en finally | Même tuple fermé et paramètres liés ; protège la suite de test contre la persistance de la corruption volontaire. |
| C66-141 | Import ElementTree dans test_scheduler_service | Les trois parses relus ci-dessous consomment exclusivement les définitions générées par le module détenu ; aucune donnée XML hostile fournie à la bibliothèque. |
| C66-142 | '/tmp/a $b%"quoted' vers generate('systemd') | Chaîne hostile synthétique pour vérifier $$, %%, guillemets, UMask et KillMode ; pas d'accès à ce chemin, pas d'activation de service. |
| C66-143 | '/tmp/state with spaces' vers generate('launchd') | Génération en mémoire d'un plist, arguments natifs inspectés ; aucun état écrit à ce chemin. |
| C66-144 | Path('/tmp/state with spaces').absolute() comme valeur attendue | Calcul et comparaison de texte uniquement ; aucun accès filesystem à cette cible. |
| C66-145 | Même chemin synthétique vers generate('windows') | Document XML retourné en mémoire, compte DOMAIN\\user synthétique et arguments vérifiés ; aucune tâche Windows inscrite. |
| C66-146 | ET.fromstring(data) du document Windows | Les octets viennent directement de generate dans le même test ; paramètres et droits minimaux sont inspectés. Aucun XML tiers. |
| C66-147 | windows_arguments sur le chemin absolu synthétique | Fonction d'encodage et comparaison de texte ; aucune exécution de la sortie et aucun fichier temporaire prévisible. |
| C66-148 | generate('windows',...,'/tmp/state') sans utilisateur explicite | Test de la valeur par défaut dans un document en mémoire ; aucun service activé ou fichier à cette cible. |
| C66-149 | generate('invalid',...,'/tmp/state') | Plateforme invalide qui doit lever ValueError ; le chemin ne donne lieu à aucun accès. |
| C66-150 | absolute('/tmp/state\n') | Contrôle négatif de caractère interdit, ValueError obligatoire ; aucune création de chemin avec retour ligne. |
| C66-151 | fromstring sur les définitions Unicode fraîchement générées | Parcours du répertoire privé de fixture créé par SERVICE.main ; octets non vides, contenu Unicode et affichage sur trois encodages vérifiés. Aucun document externe. |
| C66-152 | fromstring(original) après erreur de sortie synthétique | original est lu dans le fichier exclusif fraîchement généré ; le test exige que l'erreur d'affichage reste observable et qu'une répétition refuse l'écrasement. Aucun parse de réponse distante. |
| C66-153 | UPDATE jobs de canary/report_path/command_sha256 | Tuple fermé de colonnes, valeurs liées, magasin privé. Corruption de métadonnées hors payload pour vérifier invalid_job_snapshot et traitement du prochain job valide. |
| C66-154 | SELECT de l'ancien timestamp de jobs | field appartient à due_at/created_at/deadline/started_at/finished_at ; identité liée. Base privée de test. |
| C66-155 | UPDATE timestamp non canonique | Valeur liée '2030-01-01T00:00:00Z', refus explicite attendu ; ne modifie aucune donnée de production. |
| C66-156 | SELECT du timestamp corrompu | Identifiant du tuple fermé et id lié ; assertion que le refus n'a pas normalisé silencieusement la donnée. |
| C66-157 | UPDATE de restauration du timestamp | Même colonne interne et paramètres liés ; remet en place la valeur sauvegardée entre scénarios. |
| C66-158 | finish_failure avec {'secret':'not accepted'} | Diagnostic volontairement invalide et non secret ; ScheduleError exigée avant conservation d'un diagnostic non autorisé. |
| C66-165 | Comparaison de kwargs.pop('dir') à '/tmp' dans le double d'allocation | L'assertion vérifie la politique de chemin court ; le double retire `dir` puis appelle le vrai TemporaryDirectory dans son espace de test. Aucun fichier partagé à nom fixe. |
| C66-167 | INSERT leases avec join(columns) | columns est un tuple constant de sept identifiants internes ; les sept valeurs corrompues sont liées avec des placeholders. Refus de nouvelle réservation, absence de transaction/lock résiduel et nettoyage de la base privée exigés. |

## Lancements de processus des tests

| Signal | Flux examiné | Justification et limite |
| --- | --- | --- |
| C66-046 | Interpréteur courant, `-c` et programme d'import constant | Vérifie que domaine/application n'importent aucune infrastructure/interface/bootstrap. PYTHONPATH est la source détenue ; sortie JSON attendue vide. Aucun code ni exécutable provenant d'un inventaire. |
| C66-049 | Programme Python constant de transaction interrompue | Spécification de budget privée transmise comme argument JSON, timeout10 s ; os._exit(37) volontaire, code37 et intégrité SQLite après crash exigés. |
| C66-050 | Lanceur du module tcp_proxy vers un serveur loopback de fixture | argv construit depuis la spécification locale, connexion2 s et lifetime explicite ; enfants enregistrés pour cleanup. Mesure de plafond partagé sur données synthétiques, pas de cible externe. |
| C66-051 | OpenSSH `-G -F` de la fixture | Binaire NativeTools, configuration privée générée et timeout5 s ; aucune connexion, sortie et placement du ProxyCommand vérifiés. |
| C66-053 | Programme Python constant de décès avec crédit incertain | Données JSON privées en argument, timeout15 s, os._exit(37) attendu ; assertions sur lease, marqueur et refus de changement de politique. |
| C66-054 | Programme local tenant un verrou puis attendant un octet stdin | Interpréteur courant, spécification en argument JSON ; publication de readiness bornée15 s, propriétaire et nettoyage testés sur base temporaire. Aucun programme réseau. |
| C66-059 | Programme constant interrompu entre réservation et finalisation | JSON de budget local, timeout10 s ; code37, débit restant et récupération des leases vérifiés. Ne désérialise aucun code depuis JSON. |
| C66-062 | `channel_exit_probe.py` détenu dans tests | Interpréteur courant, chemin de fichier construit depuis __file__, racine temporaire passée comme donnée ; timeout8 s et échec explicite si le cleanup dépasse ce budget. |
| C66-064 | `python -m swassh --version` | Module du paquet, cwd du projet et arguments fixes ; timeout15 s, code0, version exacte et stderr vide requis. |
| C66-068 | Programme constant de contrôle de couverture enfant | Fixture PATH connue passée en argument, timeout20 s, décès17 attendu ; vérifie pid et conservation des seules unités réellement observées. Pas d'entrée Python distante. |
| C66-071 | Import d'une fixture de couverture via chemin détenu | Programme constant avec représentation Python sûre du chemin local, timeout10 s ; assertions sur valeurs et compteurs de conditions indépendants. Aucun choix de source par un tiers. |
| C66-072 | Boot de ChildObserver volontairement interrompu | `-S`, programme constant et phase provenant de write/publish, arguments de campagne privée ; timeout10 s, codes43/44 et absence de mesures fabriquées exigés. |
| C66-073 | runpy d'une fixture lambda détenue | Chemin local passé en argument, timeout10 s ; résultat2 et exactement une fonction observée sur deux attendus. Pas d'upload ou d'évaluation d'une chaîne externe. |
| C66-074 | Programme de fixture avec exec(compile(...)) | Le seul source exécuté est coverage_cases/choice.py détenu ; timeout10 s, sortie31 volontaire, conservation exacte des deux issues booléennes observées exigée. La règle de production contre exec n'est pas affaiblie. |
| C66-075 | Programme de fixture modifié après catalogage | Fichier temporaire `answer=41`, puis `answer=42`, timeout10 s ; l'enfant doit échouer avant mesure et conserver zéro unité observée. Cas négatif de source périmée, pas une admission de code arbitraire. |
| C66-082 | Interpréteur et fixture extended_cases | Programme constant, source du dépôt et timeout20 s ; décès17, pid et compteurs réels vérifiés. |
| C66-084 | Module relay_connect avec port littéral0 | Timeout15 s ; code125, stdout vide et diagnostic fixe exigés. Validation avant ouverture de connexion. |
| C66-085 | Helper natif nc dans sonde de descripteur | Exécutable local de QA, arguments constants, cible127.0.0.1 et port éphémère. Socketpair borné2 s ; descripteurs fermés, kill/wait en finally. Le contrat fait confiance au système d'opérateur pour le binaire. |
| C66-089 | Module relay_connect vers serveur éphémère local | Interpréteur courant, stdin nul, socketpair ; tests sur descripteur et octets binaires bruts, deadlines de sockets et terminaison détenue par le test. Aucun secret ni commande déchiffrée transmis au helper. |
| C66-091 | CLI avec commande volontairement trop longue et --plan-only | Timeout5 s, code2 et absence de répétition du contenu sensible exigés ; aucun SSH lancé. |
| C66-093 | Binaire ssh local, `-G -F` d'une config privée | Timeout5 s, check code et options strictes ; le client ne se connecte pas. La provenance du client reste celle du système d'opérateur. |
| C66-095 | Dix clients Python d'une spécification de budget privée | Programme constant, chemins d'événements séparés en arguments, communicate20 s ; le test vérifie la sérialisation réelle et collecte ses enfants. Les dix clients sont une charge locale explicitement bornée. |
| C66-097 | Parent Python et enfant de test du gardien | Programmes constants, chemins locaux encodés par repr puis données séparées ; décès du parent et disparition de l'enfant/absence de rejeu vérifiés. Le sleep60 s représente la charge à arrêter, pas un retry illimité. |
| C66-099 | Pair Python tenant trois leases | Source constant et readiness atomique dans la fixture privée ; délai de readiness10 s, entrée standard comme barrière de fin, nettoyage des processus détenus. Vérifie qu'un propriétaire vivant n'est pas effacé. |
| C66-101 | Benchmark sous `-I -B -O` avec trois résultats volontairement faux | Programme constant, root détenu et mode fermé failed/incomplete/overcommitted ; timeout30 s. Le test exige QUALITY_RESULT_REFUSED pour chaque cas, même sous optimisation. Aucun SSH. |
| C66-104 | Diagnostic Kerberos par OpenSSH NativeTools | Seulement lors d'échec d'une session de fixture localhost ; clé/config/realm privés, cible alias détenue, timeout10 s. Les traces sont synthétiques et le vrai résultat d'authentification demeure obligatoire. |
| C66-105 | Exécution du fournisseur askpass créé par la fixture | Chemin privé détenu, stdin sans donnée externe, timeout5 s ; les tests avec espaces/quotes et PATH hostile vérifient le lecteur système absolu. Aucun mot de passe réel d'un opérateur. |
| C66-106 | Adaptateur launch du test de frontière d'outils | argv provient du résolveur de la classe AuthenticationGate dont les outils système sont remplacés par des scripts inoffensifs dans le répertoire `trusted` de la fixture ; le PATH hostile ne doit jamais être sélectionné. |
| C66-107 | Faux daemon de la fixture de frontière KDC | Programme `krb5kdc` factice créé sous le répertoire trusted de test, timeout5 s ; enregistre l'argv et vérifie que la résolution ignore le PATH hostile. Ne démarre pas le KDC de l'hôte. |
| C66-109 | Callback native_ready avec une enveloppe fraîche de NativeReady | Interpréteur courant, module fixe, timeout10 s ; silence, code0 et acknowledgement exact exigés dans le répertoire de test. |
| C66-110 | Même callback avec enveloppe invalide synthétique | Timeout10 s ; échec, diagnostic sans la requête invalide et fichier d'acknowledgement inchangé exigés. Aucun code exécuté depuis l'enveloppe. |
| C66-112 | ssh-keygen NativeTools pour deux clés de fixture | Clés ed25519 neuves sous TemporaryDirectory, passphrase vide réservée à cette identité éphémère locale ; programme système et options fixes. Aucune clé de production chargée. |
| C66-113 | Serveur sshd NativeTools en foreground | Configuration créée par le test avec ListenAddress127.0.0.1 et port alloué, clés privées éphémères ; serveur détenu et terminé par les fixtures. Répertoire /run/sshd privé dans la recette de namespace. |
| C66-114 | SSH de readiness vers le serveur éphémère | Programme NativeTools, config/clé/known_hosts privés, alias local et commande fixe ; StrictHostKeyChecking obligatoire, code de readiness vérifié. N'utilise pas l'identité SSH réelle de l'opérateur. |
| C66-115 | CLI shell dans un pseudo-terminal local | Host utilisateur@127.0.0.1:port de la fixture, clés et known_hosts privés, budget commande15 s ; données de terminal synthétiques, restauration et terminaison dans finally. Exécute le shell de test explicitement demandé, sans concaténation dans un shell local. |
| C66-116 | rsync NativeTools --version | Options constantes et check=True ; comparaison au minimum3.5.0 réel, aucun banner simulé dans les tests authentifiés. Le binaire système de QA reste une dépendance de confiance. |
| C66-119 | Fixture NOP et programme de décès17 | Chemin local détenu, timeout20 s ; compteur de Return manquants et conservation d'observations vérifiés pour les deux observateurs. Aucun source externe. |
| C66-125 | `/bin/sh` exécutant le worker_script généré | Interpréteur factice privé, chemin volontairement hostile contenant quote/$(touch...). Le test exige argv exact et marqueur absent ; timeout10 s. Le shell est utilisé pour tester son échappement réel, pas pour interpréter un inventaire. |
| C66-126 | Méthode SMF générée avec worker privé qui sort7 | `/bin/sh`, programme de sortie fixe, timeout10 s ; le wrapper doit détecter l'échec initial et sortir1. Aucun service SMF réel activé. |
| C66-127 | Programme constant du pont de certification sur une fixture | Root et scripts de marqueur temporaires, plateforme simulée AIX ; timeout15 s et ordre exact des six gates vérifiés. Ce test local de contrat ne prouve pas une exécution native AIX. |
| C66-128 | Même pont sous `-O` après source modifié ou module ajouté | Timeout15 s, échec avec drift et marqueur inexistant exigés ; le test empêche de transformer une dérive de source en succès sous optimisation. |
| C66-130 | `/bin/sh -cu` avec programme constant et profil en argument `$1` | Profil généré dans HOME temporaire, PATH désinitialisé ; sortie limitée au répertoire scripts. Aucune interpolation du chemin du profil dans le programme shell. |
| C66-132 | Trois états PATH constants et commande de PathConfigurator | Le seul texte variable vient du générateur détenu, pour un chemin temporaire validé ; le test exige l'absence de répertoire courant dans PATH et refuse les chemins contenant `:`. Pas de donnée distante. |
| C66-134 | Shell sourçant deux fois le profil via argument `$1` | Programme shell constant, profil privé généré ; backup et idempotence vérifiés, PATH final exact. Aucun profil réel de l'opérateur modifié. |
| C66-161 | Worker durable CLI dans un Popen détenu | Python courant, magasin temporaire, tâche future2099 et faux client explicitement configuré ; readiness du verrou bornée5 s, arrêt/collecte contrôlés. Aucune connexion distante. |
| C66-163 | Soumission CLI avec/sans délai de démarrage injecté2,25 s | Programme constant, faux SSH créé depuis tests/fake_ssh.py, arguments séparés ; timeout10 s conservé et succès d'enregistrement exigé. Le délai n'est pas un relèvement de budget. |
| C66-164 | Worker CLI --once sur le magasin précédent | Timeout15 s ; échec canary et comptage exact d'une seule commande failed exigés. Aucun rejeu masqué, aucune cible externe. |
| C66-168 | Pair Python tenant un FileLock privé jusqu'à un octet stdin | Programme constant, chemin transmis comme argument ; readiness bornée et communicate/cleanup vérifiés. Le scénario contrôle qu'un lock vivant est conservé puis retiré après fin de propriétaire. |
| C66-169 | Interpréteur courant, programme fixe acquire/close d'un FileLock | Chemin de fixture en argument, timeout10 s/check=True ; stdout JSON et stderr vide exigés. Permet une vérification de verrou par un processus indépendant. |
| C66-171 | Programme constant de décision/itération async de couverture | Préfixe construit depuis la fixture détenue, timeout15 s ; sorties, enfants et unités booléennes exactes vérifiées. Ne reçoit aucun texte Python d'une source distante. |

## Imports subprocess des tests — examen de leurs usages

Chaque import ci-dessous est rattaché à ses usages effectivement recherchés
dans son fichier. Aucun groupe de règles B404 n'est approuvé automatiquement.

| Signal | Usages examinés | Justification et limite |
| --- | --- | --- |
| C66-045 | test_architecture : un run, C66-046 | Source Python constante limitée aux imports de couches et à la sortie JSON des modules chargés ; l'exécutable est l'interpréteur du test. |
| C66-047 | test_bandwidth : C66-049/050/051 et constantes PIPE | Crash transactionnel local, deux relais de loopback et lecture de configuration ssh-G ; tous les programmes et données ont leurs producteurs de fixture relus. |
| C66-052 | test_byte_budget_failures : C66-053/054 | Interpréteur courant et programmes constants pour crash/réservation/verrou ; JSON privé en argument, cleanup et budgets contrôlés. Aucun exécutable choisi par le fichier JSON. |
| C66-057 | test_byte_credits : C66-059 | Le seul lancement est le programme constant d'interruption d'une réservation ; l'autre alerte concerne un oracle pseudo-aléatoire de test, pas une credential. |
| C66-060 | test_channels : C66-062, types de pipe et mocks | Le lancement réel est le probe de sortie de canal détenu dans tests, borné8 s. Les faux processus des autres scénarios sont des doubles de la frontière native, pas du code livré au runtime. |
| C66-063 | test_cli : C66-064 et test d'entrée __main__ | Le seul processus réel imprime la version canonique du module ; aucune option ne permet de choisir une commande externe dans ce test. |
| C66-066 | Import local test_connector_contracts, TimeoutExpired | Le module est utilisé pour construire une erreur de timeout synthétique ; les lancements du connecteur sont remplacés par des doubles, et les assertions sur arrêt/groupe/tube sont conservées. L'import ne lance aucun enfant. |
| C66-067 | test_control_coverage : C66-068 | Programme de fixture constant pour vérifier le journal de couverture après décès17 ; aucun source non détenu n'est chargé. |
| C66-069 | test_convergence, appel passé à asyncio.to_thread | Un run indirect reçoit l'interpréteur courant, un programme constant et un répertoire privé, timeout10 s ; il sort9 après mutation d'intention, puis la reprise doit conserver pending. Ce site indirect a été relu bien que Bandit ne le signale pas comme B603. |
| C66-070 | test_coverage_metrics : C66-071..075 et constantes d'erreurs | Chaque enfant mesure une fixture locale ou provoque une interruption/mutation de source attendue ; le refus de mesures fabriquées et les compteurs indépendants sont vérifiés. |
| C66-081 | test_extended_coverage : C66-082 | Source et fixture contrôlées, programme constant, journal enfant lié au pid ; aucun choix de code par une entrée tierce. |
| C66-083 | test_fdpass_socket_contract : C66-084/085 | Validation de port0 puis sonde de socket loopback du helper local. Les descripteurs, processus et attentes sont détenus par le test et nettoyés. |
| C66-087 | test_guardian_relay : C66-089 | Lance uniquement le module relay_connect du paquet pour un serveur loopback privé ; pickle est examiné séparément et ne reçoit pas les octets du réseau. |
| C66-090 | test_hardening : C66-091 | CLI en --plan-only pour vérifier le refus d'une commande surdimensionnée ; pas de transport SSH réel, programme fixe. |
| C66-092 | test_hardening_massive : C66-093 | Appel ssh-G local avec configuration générée dans TemporaryDirectory ; aucun utilisateur distant ni commande d'inventaire. |
| C66-094 | test_improvements : C66-095/097/099, PIPE et types | Dix clients de capacité locaux, gardien/parent interrompu et pair de leases privés. Les programmes sont constants ou intègrent uniquement des chemins de fixture encodés avec repr ; les sorties sont des observations synthétiques. |
| C66-100 | Import local dans test_installation_boundary_contracts : C66-101 | Benchmark sous -O et résultat de transport volontairement incorrect ; ce test protège un refus de contrôle, sans SSH. |
| C66-102 | Import local test_installation_probe, alias execute=subprocess.run | Wrapper d'inspection de soumission CLI réelle ; il conserve timeout45/60 s, args construits localement et faux SSH privé. Les dates expirées sont des cas de refus ; SubmissionObserved arrête après l'observation, sans relance silencieuse. L'alias non signalé B603 a été relu. |
| C66-103 | test_native_auth : C66-104..107, CompletedProcess/PIPE | SSH de diagnostic vers le realm local, fournisseur askpass privé et outils factices de test de PATH ; aucune identité réelle ni équipement externe. Les sous-tests authentifiés doivent aussi réussir dans leur namespace, sans skip. |
| C66-108 | Import local test_native_readiness_contracts : C66-109/110 | Exécute le callback fixe avec une enveloppe créée localement, puis une enveloppe invalide ; exige silence, refus et absence de fuite de l'entrée invalide. |
| C66-111 | test_native_ssh : C66-112..116 et deux create_subprocess_exec | Les deux lancements asynchrones supplémentaires exécutent le CLI SWASSH vers le même sshd127.0.0.1 éphémère : sortie progressive et rapport CLI, avec attente20 s/cleanup. Clés/config/known_hosts privées, binaire NativeTools et aucun équipement réel. |
| C66-118 | test_nop_coverage : C66-119 | Le seul lancement réel concerne la fixture locale d'unités NOP et sa sortie17 attendue. Pas de code fourni par une entrée distante. |
| C66-120 | test_portability : C66-125..128 | Shells réels pour vérifier l'échappement du worker généré et pont de certification sur une fixture détenue ; aucune activation de service ni exécution distante AIX/Solaris/macOS. |
| C66-129 | Import local, profil incomplet et PATH absent, C66-130 | Shell constant et profil privé passé par `$1` ; le test contrôle backup, valeur exacte du PATH et refus d'un marqueur modifié. |
| C66-131 | Import local, PATH vide/désinitialisé, C66-132 | Trois états PATH fixes et commande générée par PathConfigurator ; absence du répertoire courant dans PATH obligatoire. Les chemins contenant `:` sont refusés. |
| C66-133 | Import local, configuration automatique idempotente, C66-134 | Shell constant source deux fois le profil de fixture ; le backup original et le PATH final exact sont vérifiés. Aucun profil de l'utilisateur de la recette modifié. |
| C66-135 | test_process_guard_contracts, TimeoutExpired et mocks | L'import fournit seulement l'exception TimeoutExpired ; Popen et create_subprocess_exec du gardien sont remplacés par des doubles. Vérifie erreurs, capacité, arrêt et ownership sans lancer un binaire externe depuis une requête de test. |
| C66-159 | Import local, crash après claim durable | run passé à asyncio.to_thread avec interpréteur courant, programme constant et magasin privé ; timeout10 s, SIGKILL sur son propre pid et code-9 attendus. Reprise impose INTERRUPTED et zéro appel métier, donc pas de rejeu. |
| C66-160 | Import local, worker SIGTERM, C66-161 | Worker SWASSH sur tâche future2099, readiness5 s, terminate/communicate5 s et contrôle de l'état PENDING ; aucun SSH réellement dû. |
| C66-162 | Import local, campagne CLI canary, C66-163/164 | Faux client créé depuis tests/fake_ssh.py, date future et bootstrap constant ; délais10/15 s, report et nombre exact d'appels contrôlés. |
| C66-166 | test_shared_budget_failures : C66-168/169 | Pair de FileLock local et sonde indépendante acquire/close ; aucune commande ou programme fourni par des valeurs de base. Les corruptions SQL sont examinées séparément. |
| C66-170 | test_source_coverage : C66-171 | Programme de test constant et fixtures de décisions détenues ; vérifie source/raw et les conditions réellement observées. L'import n'est pas un chemin d'exécution de commande distante. |

## Réexamen C67v4

Les 171 signaux C66 et les octets complets de leurs fichiers sont identiques ; ce rapprochement ne transfère aucune approbation. Les trois contextes du gate ont été relus sur le SHA e5b75446872bd89952d63b280e8e097341f22e538ae1a14f93a22a98d0b54803. Les 174 signaux complets sont identiques entre Windows et le conteneur Linux courant. La recette et les preuves doivent encore être liées individuellement avant approbation.
