# Architecture DDD et ressources

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / reference / Architecture DDD et ressources

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Organisation de src/swassh](#organisation-de-srcswassh)
- [Interface publique et migration des imports](#interface-publique-et-migration-des-imports)
- [Concurrence et GIL](#concurrence-et-gil)
- [OpenSSH](#openssh)
- [Export et audit](#export-et-audit)
- [Transferts](#transferts)
- [Corrections 1.3.1](#corrections-131)
- [Extensions 1.4.0](#extensions-140)
- [Reconnexion réseau 1.8.0rc2](#reconnexion-réseau-180rc2)
- [Clients Python 1.8.0rc3](#clients-python-180rc3)
- [Dialogue applicatif rc4](#dialogue-applicatif-rc4)



Le contexte métier couvre l’exécution de commandes et la synchronisation de fichiers sur une flotte SSH. Les termes
partagés sont `Host` (cible), `Result` (issue par cible), `Status` (statut) et
`ExecutionReport` (résultat d’exécution). Les valeurs de domaine sont immuables.
L’inventaire impose unicité, cohérence des identités et limites de flotte.
La planification ajoute un agrégat persistant Job avec états et admission au plus
une fois. Son store SQLite privé conserve les snapshots et une outbox d'audit.
Les agrégats DesiredState et Workflow ajoutent les contrôles/actions explicites,
les dépendances et les checkpoints durables, dans des bases distinctes du scheduler.
Le spool des rapports reste temporaire ; aucun serveur de base de données
ou CQRS externe n'est nécessaire.

## Organisation de src/swassh

| Couche / module | Responsabilité |
| --- | --- |
| `domain/convergence.py`, `workflows.py`, `bandwidth.py` | États désirés, DAG borné et comptage entier des octets |
| `application/convergence.py`, `workflows.py`, `workflow_contracts.py`, `durable.py` | Orchestration, claims et outbox avant effets |
| `infrastructure/convergence.py`, `workflow_store.py`, `workflow_execution.py` | Intents, snapshots et exécution native |
| `infrastructure/database/migration/` | Schémas v1 distincts, Up/Down sans suppression de preuves |
| `interfaces/convergence.py`, `workflows.py`, `channels.py` | API et scopes publics intégrés |
| `infrastructure/channels.py`, `tcp_proxy.py`, `bandwidth.py` | Canaux, tunnels et relais chiffré à plafond partagé |
| `domain/byte_credits.py`, `credit_state.py`, `infrastructure/native_budget.py`, `socket_relay.py`, `relay_connect.py` | Droits prépayés durables, arithmétique partagée sans métadonnées inutiles au gardien, préparation locale et relais détenu par le gardien |
| `infrastructure/admission_deadline.py` | Reçu local atomique et comptabilité bornée de la préparation/admission avant lancement SSH |
| `application/task_ownership.py`, `infrastructure/lifecycle.py` | Attente, annulation et fermeture de tâches ou fichiers dont le propriétaire reste explicite |
| `domain/scheduling.py` | Instants UTC, fuseaux/DST, identifiants et états de tâche |
| `application/scheduling.py`, `schedule_contracts.py` | Worker serial, récupération, DTO et ports de persistance/exécution |
| `infrastructure/schedule_store.py` | SQLite durable et borné, claim transactionnel, verrou et outbox |
| `infrastructure/scheduled_execution.py` | Chemins absolus, snapshots et réutilisation du moteur de flotte |
| `interfaces/scheduling.py` | API Scheduler, rendu compact et signaux du worker |
| `domain/models.py` | Valeurs `Host`, `Result`, `Status` et invariants d’identité |
| `domain/inventory.py` | Service de domaine : parsing d’identité, unicité et validation des cibles |
| `domain/report.py` | Résultat métier immuable, succès et groupes par statut |
| `application/options.py` | Configuration validée d’une exécution |
| `application/contracts.py` | DTO `ResourcePlan` et `RunSummary` |
| `application/ports.py` | Contrats transport, audit, budgets et reporting |
| `application/swarm.py` | Cas d’usage : plan, résultats asynchrones, rapport mémoire ou disque |
| `domain/transfers.py` | Transfert immuable, chemins littéraux et identités locales isolées |
| `application/transfers.py`, `transfer_settings.py` | Cas d’usage push/pull, budgets et orchestration via ports |
| `infrastructure/transfers.py` | rsync/SFTP natifs, staging et choix de backend avant transfert |
| `interfaces/transfers.py` | API publique FileSwarm, push_to_file et pull_to_file |
| `application/pacing.py` | Admission des connexions sans rafale |
| `infrastructure/ssh.py` | Adaptateur OpenSSH via processus natifs |
| `infrastructure/inventory.py` | Lecture TXT/CSV/JSON/sous-ensemble YAML |
| `infrastructure/resources.py` | Mesure système et calcul des plafonds mémoire/descripteurs |
| `infrastructure/audit.py` | Journal JSONL privé, rotation et compression gzip |
| `infrastructure/report.py` | Formats JSON/CSV/texte et export atomique du petit rapport mémoire |
| `infrastructure/spool.py` | Déduplication SQLite et export disque par curseurs |
| `infrastructure/process_reporter.py` | Implémentation asynchrone du port de reporting, processus séparé |
| `interfaces/api.py` | API Python stable et wrappers synchrones |
| `interfaces/cli.py` | Analyse d’arguments, affichage et codes de sortie |
| `bootstrap.py` | Assemblage explicite des ports et des adaptateurs |
| `__init__.py`, `__main__.py` | Exports publics différés et `python -m swassh` |

Les dépendances vont vers l’intérieur : `domain` ne connaît que le domaine,
`application` connaît le domaine et ses propres ports, `infrastructure` implémente
ces ports, et `interfaces` appelle les cas d’usage assemblés dans `bootstrap.py`.
Ni le domaine ni l’application n’importent un adaptateur concret ou une couche externe. Un import du cœur ne charge pas OpenSSH, SQLite ou l’interface CLI.
Ces frontières et l’absence de cycles sont vérifiées automatiquement en CI.

La mesure de qualité reste extérieure au runtime livré dans la wheel.
`scripts/coverage_source.py` inventorie les décisions du source et projette
uniquement les observations vérifiées de `coverage_metrics.py`. Le rapport
conserve intégralement la vue Python brute sous `raw_python`. Les journaux
enfants lient aussi les issues des boucles asynchrones au catalogue exact ;
une exception ou un arrêt anticipé ne vaut pas fin normale. Une correspondance
incomplète bloque les cinq seuils de 98 %, sans crédit supposé. Le contrat et
les limites sont détaillés dans [VALIDATION.md](../../../VALIDATION.md).

`application.swarm.Swarm` reçoit les factories transport/audit/reporting et le
planificateur par injection. Il peut fonctionner avec des ports mémoire de test,
sans fichier, SQLite ni SSH. `interfaces.api.Swarm` fournit les adaptateurs système
par défaut. Le transport OpenSSH est créé à chaque exécution ; `plan()` n’exige
pas d’exécutable SSH et une instance publique peut servir plusieurs exécutions.

## Interface publique et migration des imports

L’entrée console pointe vers `swassh.interfaces.cli:main` et reste nommée
**swassh**. `python -m swassh` fonctionne également. Les exports
`from swassh import Host, Options, Swarm, execute, execute_to_file, Report`
sont conservés. Les anciens contrats publics sont conservés ; les API de la version 2 sont additives. La forme CLI est désormais
`swassh run 'commande ou script avec options' -i hosts.txt` ; les options
`-c`, `--command` et `--commande` sont retirées à la demande de l’utilisateur.
Les sous-commandes argparse run/push/pull/schedule sont obligatoires ; les options
longues doivent être complètes. `Report` étend le résultat de domaine avec
les méthodes de sérialisation. Le schéma JSON reste `schema_version=1` et les
codes de sortie sont inchangés.

Les dix anciens modules plats et leurs redirections ont été supprimés. Les
imports directs passent désormais par les chemins canoniques :

| Import précédent | Import DDD |
| --- | --- |
| `swassh.models.Host`, `Result`, `Status` | `swassh.domain.models` |
| `swassh.models.Options` | `swassh.application.options.Options` |
| `swassh.engine.Swarm`, `execute`, `execute_to_file` | `swassh.interfaces.api` |
| `swassh.cli` | `swassh.interfaces.cli` |
| `swassh.ports` | `swassh.application.ports` |
| `swassh.resources.ResourcePlan` | `swassh.application.contracts.ResourcePlan` |
| `swassh.resources.ConnectionPacer` | `swassh.application.pacing.ConnectionPacer` |
| `swassh.resources.resource_plan` | `swassh.infrastructure.resources.resource_plan` |
| `swassh.spool.RunSummary` | `swassh.application.contracts.RunSummary` |
| `swassh.spool.ReportStore` | `swassh.infrastructure.spool.ReportStore` |
| `swassh.inventory.parse_host`, `normalize_hosts`, `InventoryError` | `swassh.domain.inventory` |
| `swassh.inventory.load_inventory` | `swassh.infrastructure.inventory.load_inventory` |
| `swassh.ssh`, `swassh.audit`, `swassh.report` | `swassh.infrastructure.ssh`, `audit`, `report` |

La racine de `src/swassh` ne contient que `__init__.py`, `__main__.py`,
`bootstrap.py`, `py.typed` et les quatre couches DDD. Les tests vérifient cette
structure et les exports publics canoniques.

## Concurrence et GIL

H hôtes et C workers : O(H) métadonnées d’inventaire ; O(C) workers, clients SSH
et éléments en file. La CLI ne conserve pas O(H × sorties) en mémoire. Un lot
de min(C,32) résultats est transmis au processus écrivain ; aucune nouvelle
écriture n’est soumise tant que le lot précédent n’est pas acquitté.

L’I/O est asynchrone. Le chiffrement SSH s’effectue dans les processus natifs
OpenSSH, hors de l’interpréteur. La sérialisation JSON/CSV et SQLite s’effectuent
dans un interpréteur séparé via ProcessPoolExecutor(max_workers=1), contexte
spawn compatible multi-plateforme. Le parent ne confond pas threads et
parallélisme CPU. La compression gzip d’audit est une opération native zlib
libérant le GIL, déplacée hors de la boucle dans un thread ; événements courts
et file de 64 enregistrements au plus.

Budget estimé par worker natif : 48 Mio + 16 × max_output_bytes ; +8 Mio si saut.
Un transport injecté utilise sa base historique de 8 Mio. Les coûts natifs incluent
les gardiens et le relais de payload chiffré ; le maître multiplexé garde son
allocation supplémentaire. Le [plafond réseau](../operations/BANDWIDTH.md) est local au compte.
Le plafond effectif est le minimum de : demande, 256, budget/coût estimé et
capacité de descripteurs avec réserve. Sur Linux, le budget est limité à 10 %
de la mémoire disponible et de la disponibilité des cgroups v2 imbriqués et de leurs ancêtres lisibles.
Repli prudent quand ces informations ne sont pas disponibles. Le budget concerne
une estimation de la concurrence ; ce n’est pas un quota RSS système. Inventaire,
interpréteurs, allocations tierces de l’OS et autres processus restent à mesurer.

## OpenSSH

Fichier de configuration privé généré par invocation, aucun ssh_config ambiant.
BatchMode (sauf authentification explicite par fournisseur de mot de passe),
clés d’hôte strictes, aucun transfert d’agent/X11, aucun PTY, aucun
multiplexage persistant dans run par défaut. Le contexte Session facultatif
possède un maître gardé, un socket privé et une réservation jusqu’à fermeture ;
ses canaux sont séquentiels et refusent toute reconnexion de secours. Un alias cible applique les options de son profil ;
l’alias saut conserve les clés et known_hosts globaux, avec son port et son
utilisateur. Les profils ne modifient pas les budgets de ressources.
Le DEBUG1 cible est dirigé vers un diagnostic temporaire séparé de stderr distant.

Sur POSIX direct sans GSSAPI, le relais appartient au gardien et le connecteur
transmet son socket à OpenSSH, sans remplacer l'adresse cible ni sa confiance.
Les capacités d'un outil natif facultatif sont vérifiées avant la commande,
y compris TCP_NODELAY sur son descripteur réel. Les sauts, GSSAPI, sessions
persistantes et Windows gardent leurs chemins spécifiques. Le démarrage du
gardien diffère les imports asynchrones inutiles à son entrée synchrone.

Retries uniquement avant toute preuve d’authentification/lancement, avec diagnostic
complet et erreur réseau reconnue. Un diagnostic ambigu n’autorise pas de relance.
Un code de commande distant 255 ne constitue pas une panne réseau. Une sortie
stderr distante ne peut pas fabriquer une raison de retry. Code, timeout et perte
de connexion ne garantissent pas l’arrêt d’un processus distant.

ConnectTimeout OpenSSH concerne TCP/négociation ; command_timeout SWASSH couvre
l’invocation complète, y compris authentification et éventuel saut, après admission.
La création du processus gardien reste comptée dans ce délai. Une fois ce
processus créé, sa préparation locale, son attente de capacité et la préparation
du relais possèdent une allowance distincte, plafonnée à la même valeur de
command_timeout. Un reçu privé atomique donne l'instant monotone de fin de cette
phase ; seul son temps réel est ajouté à l'échéance initiale. L'authentification,
le lancement du client natif, les callbacks et les flux ne reçoivent aucun
nouveau délai. Le gardien impose aussi le plafond natif indépendamment du parent.
Un reçu invalide, futur, absent à la fin du gardien ou une admission expirée
provoque un échec explicite ; stderr distant ne participe jamais à ce calcul.
Une somme de délais finis qui dépasse la plage de l'horloge est aussi refusée,
sans programmer une échéance infinie ni appliquer un plafond de repli silencieux.
La file conserve ses règles FIFO, de cadence, de mémoire et de connexions.
Une annulation arrête le groupe de processus sur POSIX, puis escalade de TERM à
KILL, avec une attente maximale de 2 s pour le client. Sur Windows, l’arrêt du client repose sur les primitives natives
et la fermeture des pipes ; la fin des descendants ProxyJump doit être vérifiée
sur la version OpenSSH installée. Les diagnostics sont lus à 128 Kio maximum et
surveillés à 100 ms ; une brève croissance au-delà du seuil peut précéder l’arrêt.

La suppression du staging attend la fin de son propriétaire. Sur Windows, la
récolte du gardien peut précéder la fermeture effective du fichier diagnostic
par un descendant de son Job Object. Seules les erreurs de partage Win32 32/33
sont réessayées, dans une fenêtre de deux secondes ; les autres erreurs et un
verrou persistant restent des échecs. L'annulation attend cette fermeture puis
reste visible à l'appelant. Cette fenêtre ne rend pas une opération disque
bloquée interruptible et ne modifie aucun délai de commande.

## Export et audit

SQLite : cache 2 Mio, requêtes paramétrées, déduplication des réponses, index sur
statut et identité de réponse. Transactions et compteurs cohérents, plafond
physique SQLite via max_page_count. RPC sérialisés avec échéance et arrêt forcé
de l’écrivain bloqué. Export par curseurs, JSON/CSV complet, texte compact.
Écriture finale temporaire privée puis os.replace. Annulation coopérative du
processus écrivain avant publication ; un processus interrompu est fermé et son
répertoire temporaire supprimé. Un rapport préexistant reste intact.

Si l'arrêt de l'écrivain n'est pas confirmé, le parent conserve le spool,
l'exécuteur et les références initiales à son gestionnaire et ses processus.
Ces références restent nécessaires même après shutdown(wait=False), qui peut
les retirer de l'exécuteur. Une nouvelle ouverture est refusée jusqu'à la fin
confirmée ; un nouvel essai de fermeture peut rejoindre ces mêmes propriétaires.
Les attentes de tâches détenues par un scope n'en transfèrent pas l'annulation
et n'inventent pas un succès à la place d'une erreur tardive.

Audit : UTC, PID, run_id et métadonnées, sans commande en clair ni sortie distante.
Rotation 100 Mio, trois gzip, verrou écrivain par fichier. SIGKILL peut perdre
un lot non flushé et laisser des fichiers temporaires à nettoyer après vérification.
Les ACL Windows restent du ressort de l’exploitation.

## Transferts

Le port FileTransport est créé une fois par flotte ; il partage le snapshot de
fichier source et le rythme d’admission. TransferService adapte ce port au moteur
borné existant. TransferReceipt est conservé par le spool sans empêcher la
déduplication des réponses. Le profil rsync et les limites du repli SFTP sont
décrits dans [TRANSFERS.md](../usage/TRANSFERS.md).

Les modules commands, filesystem et lifecycle portent les nouveaux invariants
de validation et de nettoyage. Voir [HARDENING.md](../history/hardening/HARDENING.md) pour leurs tests
et les différences POSIX/Windows.

La version 1.2.0 active aussi un canary de 1 cible par défaut, configurable par
`--canary 5`. La flotte est libérée après réussite de toute la première vague ;
sinon les cibles restantes sont skipped. Voir [CANARY.md](../usage/CANARY.md) pour la
sélection, les phases de rapport, les limites et les tests.

La version 1.3.0 ajoute la planification ponctuelle persistante sans modifier
les ports d'exécution et de reporting. Le worker appelle les transactions SQLite
et l'export d'audit hors de la boucle asyncio ; l'exécution utilise toujours
OpenSSH et le processus de reporting séparé. Les snapshots sont des métadonnées
bornées, pas les sorties complètes d'une flotte. Voir [SCHEDULING.md](../usage/SCHEDULING.md).

## Corrections 1.3.1

Voir [HARDENING-1.3.1.md](../history/hardening/HARDENING-1.3.1.md) : parents des chemins, source/staging, synchronisation
des publications et de l’audit, checkpoints avant admission, configuration SSH
et invariants du scheduler. Les ports injectés restent compatibles ; les
capacités optionnelles prepare/flush des adapters système renforcent les
frontières sans ajouter de dépendance à une couche extérieure au cœur.

## Extensions 1.4.0

application/admission.py porte le régulateur et les métriques à mémoire constante.
application/boundaries.py porte la frontière optionnelle d'invocation. Les ports
sont assemblés par bootstrap, sans import d'infrastructure depuis le cœur.
infrastructure/bastion.py coordonne les ressources locales entre processus ;
process_guard.py détient les leases des clients et windows.py fournit les
primitives Job Object, handles et DACL. filesystem.py assure les opérations
épinglées et AtomicOutput. preview.py parse une itemisation bornée ; integrity.py
calcule et valide les empreintes avec les outils natifs. progress.py rend les
mesures sur stderr. Les snapshots schedule anciens reçoivent les défauts des
nouveaux champs, sans changement destructif de schéma persistant.

## Reconnexion réseau 1.8.0rc2

Le domaine porte `ReconnectPolicy` et les invariants des étapes de redémarrage.
L'adaptateur `NetworkTransport` sépare activation unique et nouvelles connexions
de vérification. Chaque connexion réutilise les gardiens et budgets existants ;
un `DialogueBudget` conserve le plafond de sortie entre connexions. Les retries
cessent dès la première commande de vérification, avec une échéance globale
monotone. La sérialisation des anciennes procédures reste inchangée.

## Clients Python 1.8.0rc3

Client et AsyncClient assemblent Swarm avec des options immuables et une factory
de transport différée. ResultStream possède un producteur unique et une file
de taille un ; le contexte attend sa fermeture. Les exceptions de résultat
restent dans le domaine. Une frontière de réservation indépendante empêche
un appel SDK de consommer implicitement la capacité de la session englobante.
Les contrats CLI et les schémas de rapports restent inchangés.

## Dialogue applicatif rc4

OutputEvent est un objet immuable du domaine. AsyncClient assemble le transport
natif via InteractionFactory ; les protections du planner restent actives.
SSHTransport conserve son cycle de vie et branche ses lecteurs bornés sur
Interaction. Les callbacks sont sérialisés par hôte, sans file supplémentaire ;
le démarrage, les lecteurs et le watchdog partagent le délai et le nettoyage.
Les commandes ordinaires ne créent aucun callback et gardent leurs contrats.
