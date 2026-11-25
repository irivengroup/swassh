# Sécurité

Lire `docs/wiki.d/history/hardening/HARDENING.md` et `docs/wiki.d/history/hardening/HARDENING-1.3.1.md` pour les constats,
corrections, tests et limites, et `VALIDATION.md` pour les preuves exécutées.

## Contrôle SAST de la publication

Le contrat SAST v2 distingue le résultat brut de Bandit de la qualification
individuelle de ses avertissements. Cette évolution a été expressément
autorisée sous condition de vérification ; elle n'approuve aucune alerte et
ne dispense d'aucun autre contrôle de publication. Le contrat v1, ses quatre
tests et ses sources sont conservés octet pour octet dans
`tests/sast_v1_reference/` ; les quatre tests restent exécutés sur cette référence.

Le job `security` exécute Bandit 1.9.4 sur **tous** les fichiers Python de
`src`, `tests`, `scripts`, `build_support` et `benchmarks`, avec `--ignore-nosec`,
sans filtre, baseline, seuil de sévérité, règle retirée ou exclusion nouvelle.
Le JSON original, les sorties du processus et son vrai code de sortie sont
conservés, même en cas de refus. Un timeout est distinct d'un code de sortie.
Le contrôle refuse tout fichier omis, erreur d'analyse, installation échouée,
rapport absent ou incohérent. Le code brut 0 exige zéro alerte ; le code brut
1 exige un rapport cohérent et la revue complète décrite ci-dessous. Tout autre
code reste bloquant. Le résultat brut 1 demeure visible même si la revue aboutit.

Le scan part d'un arbre **propre de fichiers maintenus**, avant les commandes
de qualité et de construction. Un membre de racine inconnu, un cache compilé
applicatif ou un artefact préconstruit est refusé plutôt qu'ignoré. Cela inclut
`dist/`, `validation/` et `MANIFEST.json` : les artefacts sont vérifiés séparément
par la recette de livraison. Pour analyser une archive complète, vérifier son
identité et son manifeste, puis copier ses fichiers maintenus dans un arbre
de scan neuf ; conserver les artefacts et preuves hors de cet arbre. Ne jamais
effacer des fichiers de travail de l'opérateur pour satisfaire ce contrôle.
Seuls `.git`, `.qa-bandit` et `.qa-approved-review` sont réservés aux métadonnées
de l'opérateur et de la QA ; l'outil et la revue restent vérifiés séparément.

Chaque alerte doit recevoir une qualification individuelle démontrée :
avertissement sans défaut confirmé dans ce contexte, revue approuvée, aucun
risque ouvert. Un défaut confirmé, un risque accepté ou non levé, une preuve
manquante, une revue en attente ou périmée refuse la qualification. Une faible
sévérité, un import légitime, un nombre constant ou une revue historique ne
suffisent jamais. Les décisions couvrent exactement les signaux bruts, avec
leurs contextes, empreintes, flux, frontières de confiance, preuves positives
et négatives, limites, auteur et dates. Tous les fichiers maintenus, y compris
les appelants, contrôles et documents, ainsi que le runtime et les wheels QA
évalués sont liés à la revue. Leur modification impose une nouvelle revue.

La chaîne QA est séparée du runtime : environnement virtuel privé, Python 3.12,
versions et empreintes verrouillées dans `.github/bandit-requirements.txt`,
wheels uniquement et contrôle `pip check`. L'installation utilise `--no-compile` :
le vérificateur refuse les hooks d'import et tout cache compilé non issu des
wheels avant de lancer l'interpréteur. `-B` seul n'empêche pas le chargement d'un
cache existant. Les octets installés sont comparés aux wheels verrouillées et
revérifiés après le scan. Les variantes de casse des caches et hooks sont
également refusées : sous Windows, un fichier `.PYC` peut être chargé par le
chemin canonique `.pyc`. Un état spécial non régulier est refusé avant lancement.
L'inventaire vérifie aussi tous les fichiers des huit outils : ajouter une
métadonnée de plugin, même sans modifier les fichiers originaux, invalide l'outil.
Seuls `RECORD` réécrit par pip et ses marqueurs inertes `INSTALLER`/`REQUESTED`
constituent les métadonnées d'installation attendues. Le runtime et son bootstrap
pip restent une frontière de confiance de l'opérateur. Les dépendances applicatives restent
vides. Les empreintes PyYAML ciblent CPython 3.12 sur Linux x86_64 et Windows
AMD64 ; une autre plateforme nécessite une revue explicite du verrouillage.
L'absence d'accès à l'index ou d'une wheel autorisée est un refus, sans fallback.

La CI exige que `.qa-bandit` et `.qa-approved-review` n'existent pas, y compris
sous forme de liens pendants, avant de créer l'environnement ou de lire la revue.
Elle refuse un état préinstallé fourni par le checkout au lieu de l'effacer ou
de le réutiliser. Le venv est créé par le Python de l'opérateur sous `-I -B`,
avant tout lancement de son interpréteur privé ; un candidat ne peut donc
précharger un hook d'import dans ce répertoire réservé.
L'autorité détachée du vérificateur, de la revue et des sources complètes,
notamment le verrou QA, est vérifiée **avant** cette installation. Une nouvelle
wheel déclarée dans un verrou candidat non approuvé n'est donc pas installée
en attendant que le scan la refuse plus tard. Cette prévalidation n'approuve
aucun résultat SAST : le scan complet et les décisions restent obligatoires.

### Autorité de revue détachée

Un fichier candidat contenant `approved=true` n'est pas une autorité. L'opérateur
conserve **hors du candidat** l'empreinte attendue du vérificateur et celle du
document de revue. Son lanceur vérifie les octets du vérificateur **avant** son
chargement ; le vérificateur contrôle ensuite la revue et ses preuves détachées.
Le lanceur, ses paramètres attendus, le runtime Python et le compte opérateur
constituent la frontière de confiance. Calculer ces attentes depuis le candidat
à chaque lancement annulerait cette garantie et n'est pas une procédure admise.

Sur GitHub, un administrateur doit protéger le workflow requis et établir les
variables de dépôt `SWASSH_SAST_GATE_SHA256`, `SWASSH_SAST_REVIEW_SHA256` et
`SWASSH_SAST_REVIEW_REF` à partir de la revue vérifiée. La dernière désigne un
commit immuable de 40 caractères contenant `.sast-approval/review.json` et ses
fichiers `evidence/`, relus dans un checkout distinct puis détachés de la source
candidate. Ces valeurs ne viennent ni d'un manifeste candidat ni d'une entrée
de pull request. Leur absence refuse le job. Aucune protection de branche ou
configuration distante n'est déclarée effectuée par la seule présence du YAML.
Un workflow modifiable et exécuté sans cette protection n'offre pas cette
frontière ; aucune résistance à un propriétaire capable de réécrire le workflow,
le lanceur et leurs attentes n'est revendiquée.

En local, employer le lanceur et les empreintes conservés dans le reçu externe
de revue, avec `SWASSH_SAST_GATE_SHA256` et `SWASSH_SAST_REVIEW_SHA256` fournis par
l'opérateur. Les options de `scripts/sast_gate.py --help` désignent les sources,
l'interpréteur QA privé, les huit wheels verrouillées, la revue, ses preuves et
un répertoire de sortie neuf. Revue, preuves et sorties résident hors des sources.
Le JSON `security.json` indique uniquement la qualification SAST et conserve
`publication_authorized=false` : il ne remplace jamais une admission de livraison.

Le job `quality` reste dépendant de `security`, et la release de la CI entière.
Les tests, les cinq couvertures indépendantes ≥98 % avant arrondi, globalement,
par composant et par module, l'intégrité du paquet, l'installation et la
reproductibilité restent obligatoires. Ni `production_ready=true` ni
`production_ready=false` n'exemptent de ces contrôles. Aucun paquet refusé ne
doit être publié, y compris par retour à une révision antérieure.

## Prérequis d’exploitation

Python 3.11+ et clients OpenSSH maintenus, clés d’hôte vérifiées hors bande,
compte dédié avec les droits minimaux, répertoires et ancêtres administrés.
Les transferts rsync exigent 3.5.0+ aux deux extrémités. SFTP est réservé aux
fichiers simples. Les binaires natifs, wrappers éventuels et leur PATH sont des
composants de confiance, pas du code téléchargé depuis un inventaire.

Le fournisseur externe SSH_ASKPASS est également un composant de confiance :
il ne doit divulguer le mot de passe ni dans ses diagnostics, ni dans ses propres
arguments ou journaux. Le secret n’est pas une option SWASSH. Kerberos utilise
le ticket du compte d’exécution sans délégation ; surveiller son expiration.
Les profils ne peuvent relever les budgets globaux ni remplacer le fournisseur.
Le flux progressif JSONL reste une sortie distante potentiellement sensible ;
son échappement terminal ne constitue pas un masquage des secrets métier.

Prévoir des quotas système mémoire/disque et une supervision du bastion.
Les plafonds applicatifs limitent la concurrence, les captures, le spool et
certaines allocations ; ils ne garantissent pas la RSS totale ni le volume
réseau de plusieurs instances. Mesurer sur la flotte et l’arbre de fichiers
réels. Les limites Windows diffèrent des groupes de processus POSIX.

Les rapports peuvent contenir des secrets. Les logs sont privés, rotatifs,
100 Mio avec trois archives gzip ; leur rétention locale n’est pas immuable.
Chaque instance doit avoir son chemin d’audit distinct. Ne pas partager ses
répertoires en écriture avec d’autres comptes.

Les sessions réutilisables 1.7.0 conservent les réservations du maître, bornent
sa durée et refusent tout repli TCP lorsque le socket disparaît. Elles ne
survivent pas volontairement au contexte qui les possède. Le shell interactif
affiche directement les séquences terminales de la cible : il exige une cible
de confiance, une seule à la fois, et ne journalise ni frappes ni contenu.
Les limitations des arrêts brutaux et de l’état distant restent applicables.
Voir `docs/wiki.d/history/releases/RELEASE-1.7.0.md` pour les restrictions de plateforme et de terminal.

`--delete` supprime les entrées excédentaires du répertoire de destination.
Employer exclusivement une destination dédiée. Un déploiement de répertoire
partiel doit être traité par le protocole applicatif de l’opérateur ; SWASSH
ne rejoue pas une opération dont l’état distant est ambigu.

## Frontières ajoutées en 2.0.0rc1

Les contrôles DesiredState et reconcile_check sont des entrées de confiance :
leur absence d’effet de bord et leur vérité métier appartiennent à l’opérateur.
Un intent durable précède la mutation ; un état ambigu n’autorise aucun rejeu.
Les workflows vérifient l’intégrité de leurs métadonnées de dépendance et
conservent les rapports initiaux lors de la réconciliation. Les SHA-256 locaux
détectent une altération accidentelle ; ils ne protègent pas contre le compte
propriétaire capable de réécrire le code et la base.

Chaque Session/canal/tunnel possède sa réservation. Les scopes natifs imbriqués
sont refusés. Les tunnels écoutent uniquement loopback ; le service destination
garde son authentification et son TLS. Le relais chiffré ne traite pas les
secrets SSH : OpenSSH conserve la confiance et l’authentification. Le plafond
partagé concerne le payload remis par SWASSH, pas la carte réseau ni les autres
processus. Voir le [Wiki](docs/index.md) pour les limites et procédures.

## Signalement

Le projet ne fournit pas encore de canal privé de signalement vérifié. Au
mainteneur du dépôt de définir ce canal avant une publication publique. Un
rapport doit préciser la version, le scénario de reproduction et l’impact ;
ne pas y publier de clés, inventaires réels, commandes sensibles ou sorties
confidentielles.

La version 1.3.0 active aussi un canary de 1 cible par défaut, configurable par
`--canary 5`. La flotte est libérée après réussite de toute la première vague ;
sinon les cibles restantes sont skipped. Voir [docs/wiki.d/usage/CANARY.md](docs/wiki.d/usage/CANARY.md) pour la
sélection, les phases de rapport, les limites et les tests.

## Planification persistante (1.3.0)

Voir [SCHEDULING.md](docs/wiki.d/usage/SCHEDULING.md) pour le worker supervisé, le claim durable sans relance automatique,
les retards d’échéance, la copie des inventaires, les droits du stockage et
les journaux par tâche. Les fichiers contenant les commandes restent privés
mais ne sont pas chiffrés. Une seule flotte planifiée est admise par répertoire
d’état. Depuis 1.4.0, les invocations manuelles et les workers du même compte
partagent aussi le budget local lorsqu'ils utilisent la même racine de coordination.

## Corrections 1.3.1

Voir [HARDENING-1.3.1.md](docs/wiki.d/history/hardening/HARDENING-1.3.1.md) : parents des chemins, source/staging, synchronisation
des publications et de l’audit, checkpoints avant admission, configuration SSH
et invariants du scheduler. Les ports injectés restent compatibles ; les
capacités optionnelles prepare/flush des adapters système renforcent les
frontières sans ajouter de dépendance à une couche extérieure au cœur.

## Changements 1.4.0

Le coordinateur partagé ne stocke aucune commande ni instruction de reprise.
Ses UUID/verrous OS ne dépendent pas d'un timeout de heartbeat ou d'un PID seul.
Les guardians et reporters retiennent la mémoire du parent disparu jusqu'à leur
arrêt. Windows utilise des Job Objects sans breakaway et des handles de chemins
sans partage de suppression ; POSIX publie par descripteurs. Preview et SHA-256
échouent explicitement sur capacités non supportées ou données invalides.
Les comptes privilégiés et les programmes du même UID restent de confiance ;
les limites exactes sont documentées dans docs/wiki.d/history/hardening/HARDENING-1.4.0.md.

## Procédures réseau 1.8.0rc1

Le digest de revue lie procédure et cibles mais ne remplace pas une autorisation.
Les commandes sont des entrées de confiance : aucun secret ne doit figurer dans
le plan. Les sorties peuvent contenir des configurations sensibles. Le moteur
exige un écho cohérent et des preuves séparées de cet écho, borne les lectures et
arrête sur erreur ou rupture sans rejouer de modification. Les dialogues sont
annulés avant l’attente de destruction des processus. Les gardiens conservent
leurs réservations jusqu’à l’arrêt des descendants. Une restauration distante
reste propre au modèle ; voir docs/wiki.d/usage/NETWORK.md pour les limites firmware.

## Reconnexion firmware 1.8.0rc2

La reconnexion est opt-in, après preuve d'acceptation et fermeture de la session.
L'activation et les commandes de vérification ne sont jamais rejouées. Les
erreurs de confiance et d'authentification sont terminales. Délais globaux,
nombre de connexions, sorties cumulées et réservations interprocessus restent
bornés. Les preuves de modèle/version sont des lignes entières, séparées de
l'écho. Une reconnexion réussie ne suffit jamais à déclarer la procédure réussie.
Les commandes opaques et les rapports sensibles restent sous contrôle opérateur.

## Clients Python 1.8.0rc3

Les clients publics conservent les gardiens du transport natif et isolent les
réservations entre opérations indépendantes. Une interruption attend le nettoyage ;
un échec de fermeture reste visible. Les erreurs typées ne recopient pas les
sorties sensibles dans leur message, mais leur résultat attaché peut en contenir.
La factory de transport est une extension de confiance et ne garantit pas les
protections natives pour du code injecté. Voir docs/wiki.d/usage/PYTHON-SDK.md.

## Dialogue applicatif rc4

Les callbacks sont du code de confiance exécuté dans la boucle de l’application.
Le canal stdin est lié à la tâche du callback et révoqué avant le nettoyage.
Les fragments, envois et budgets cumulés sont bornés ; aucune file événementielle
illimitée n’est créée. Les erreurs de callbacks sont traduites en diagnostics
sans leur message. Les sorties restent potentiellement sensibles. Les gardiens
ne peuvent pas empêcher un callback utilisateur de bloquer la boucle ou de
réaliser lui-même une opération extérieure ; ces comportements sont hors contrat.
