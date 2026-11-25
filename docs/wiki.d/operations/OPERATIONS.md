# Exploitation

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / operations / Exploitation

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Reprise et scopes de la version 2](#reprise-et-scopes-de-la-version-2)
- [Planification persistante (1.3.0)](#planification-persistante-130)
- [Corrections 1.3.1](#corrections-131)
- [Portabilité 1.3.2](#portabilité-132)
- [Coordinateur partagé et supervision (1.4.0)](#coordinateur-partagé-et-supervision-140)



Installer le wheel sans dépendances sur un bastion possédant Python 3.11+ et
OpenSSH maintenu (7.3+ pour les fonctionnalités utilisées). Pour une installation hors ligne, transférer le wheel : aucune
résolution de dépendance Python n’est nécessaire.

```bash
python -m pip install --no-index --no-deps swassh-2.0.0rc1-py3-none-any.whl
```

Provisionner known_hosts après vérification des empreintes hors bande. Un port
non standard est noté `[hôte]:port`. Charger les clés chiffrées dans l’agent
local ou choisir une clé accessible en BatchMode. Le mot de passe exige un
fournisseur askpass externe explicitement configuré ; GSSAPI utilise les tickets
préparés par l’opérateur. Aucun parcours MFA arbitraire ni outil sshpass n’est
fourni. Le mode d’authentification choisi ne bascule pas vers un autre mode.

Démarrer avec `-j 32 --connect-rate 20 --memory-budget-mib 128`, puis lire le
plafond via `--plan-only` et mesurer CPU, RSS, FD, stockage, RTT et taux d’erreur.
Le coût natif inclut le relais réseau de la version 2. Les profils réservent
au moins 4 Mio, puis quatre fois leur métadonnée UTF-8 bornée, jusqu’à 16 Mio.
Un petit profil avec entrée fichier et sortie en direct tient dans le budget
par défaut ; une grande table ou un saut peut exiger un budget explicite
supérieur. Un budget insuffisant refuse l’exécution avant toute connexion.
Les processus OpenSSH ont un coût supérieur à une coroutine : augmenter la
concurrence sans mesurer ce coût serait contre-productif. Le saut double les
connexions et réduit la cadence d’invocation. Plusieurs SWASSH simultanés ont
leur réservation propre et partagent les plafonds du compte quand ils emploient
la même racine locale. L’administrateur doit aussi tenir compte des autres logiciels.

`--report-timeout` borne chaque opération du processus de rapport (60 s par
défaut). Augmenter cette valeur pour les exports lents sur volume administré.
Les commandes sont limitées à 16 Kio UTF-8 : pousser les scripts plus longs.

La CLI utilise un spool privé sur disque et un processus écrivain. Choisir un
volume `--spool-dir` existant, avec espace pour le spool et le rapport final.
`--max-report-mib` borne le spool, pas la somme de tous les fichiers temporaires.
Les rapports contiennent les sorties demandées ; appliquer les droits adaptés.
Un dépassement de budget ou une erreur d’audit interrompt le traitement.

Logs par défaut dans le répertoire d’état utilisateur. Choisir par exemple
`--log-file /var/log/swassh/swassh.jsonl` après avoir créé un répertoire réservé
au compte. Actif plus `.1.gz` à `.3.gz`, 100 Mio par segment avant compression.
La marque `.lock` est conservée mais son verrou OS disparaît à la fermeture.
Utiliser un chemin distinct par processus actif. Le run_id JSON lie les événements
au rapport. Les dernières entrées en mémoire peuvent être perdues après SIGKILL.

Les timeouts et annulations ne prouvent pas l’arrêt des processus distants.
Une commande non idempotente doit définir son propre protocole applicatif de
reprise. SWASSH ne rejoue pas une commande commencée.

CI : unittest standard, contrôles AST/imports, compilation, trace et distributions.
Les tests authentifiés nécessitent un sshd local opérationnel et les capacités
requises par sa séparation de privilèges. Le journal de validation distingue
ces gates des tests réellement exécutés.

Publication : configurer le Trusted Publisher du projet PyPI contrôlé, nom du
dépôt, workflow release.yml et environnement pypi. Le tag vX.Y.Z doit correspondre
à pyproject.toml. La disponibilité du nom PyPI swassh n’a pas été vérifiée ;
si nécessaire, adapter le nom de distribution avant publication. La commande
reste `swassh`. Aucune publication n’est effectuée pendant cette livraison.

Bilan des corrections et limites : [HARDENING.md](../history/hardening/HARDENING.md). Les transferts
rsync exigent désormais 3.5.0+ aux deux extrémités. Aucun contournement du seuil
n’est fourni ; un répertoire sans rsync compatible échoue explicitement.

La version 1.3.0 active aussi un canary de 1 cible par défaut, configurable par
`--canary 5`. La flotte est libérée après réussite de toute la première vague ;
sinon les cibles restantes sont skipped. Voir [CANARY.md](../usage/CANARY.md) pour la
sélection, les phases de rapport, les limites et les tests.

## Reprise et scopes de la version 2

Les [workflows](../usage/WORKFLOWS.md) nécessitent leur worker au premier plan ;
leurs steps interrompus doivent être vérifiés avant reprise. Le journal
[d’idempotence](../usage/CONVERGENCE.md) ne relance jamais une mutation ambiguë.
Conserver bases, rapports et définitions privées sur stockage local fiable.
Les [tunnels](../usage/CHANNELS.md) n’écoutent que sur loopback et ne prouvent
pas la disponibilité du service destination. Le [relais réseau](BANDWIDTH.md)
limite le payload chiffré cumulé, pas les paquets de tous les logiciels du bastion.

## Planification persistante (1.3.0)

Voir [SCHEDULING.md](../usage/SCHEDULING.md) pour le worker supervisé, le claim durable sans relance automatique,
les retards d’échéance, la copie des inventaires, les droits du stockage et
les journaux par tâche. Les fichiers contenant les commandes restent privés
mais ne sont pas chiffrés. Une seule flotte planifiée est admise par répertoire
d’état. Depuis 1.4.0, les invocations manuelles et les workers du même compte
partagent aussi le budget local lorsqu'ils utilisent la même racine de coordination.

## Corrections 1.3.1

Voir [HARDENING-1.3.1.md](../history/hardening/HARDENING-1.3.1.md) : parents des chemins, source/staging, synchronisation
des publications et de l’audit, checkpoints avant admission, configuration SSH
et invariants du scheduler. Les ports injectés restent compatibles ; les
capacités optionnelles prepare/flush des adapters système renforcent les
frontières sans ajouter de dépendance à une couche extérieure au cœur.

## Portabilité 1.3.2

Voir [PORTABILITY.md](PORTABILITY.md) : sondes Linux réservées à Linux,
replis mémoire/descripteurs conservateurs, supervision Solaris SMF/AIX SRC,
Windows Proactor/SFTP et WSL pour le profil rsync complet. Les gates natifs
Solaris/AIX sont lancés explicitement via SSH sur un checkout identique ; aucune
certification de ces OS n'est déduite d'un test simulant leur API sous Linux.

## Coordinateur partagé et supervision (1.4.0)

Les invocations du compte partagent désormais un budget local, configuré par les
options --bastion-*. Utiliser le même --budget-dir sur un filesystem local pour
CLI et schedule, et des --log-file distincts entre CLI simultanées. Un conflit
avec une politique active est refusé. Ne jamais supprimer un état ou ses locks
pendant une exécution : laisser la récupération OS constater la mort des leases.
Les réservations mémoire sont des estimations incluant les helpers, complétées
par les quotas OS. --adaptive réduit les admissions sans rejouer les commandes ;
--progress reste agrégé et utilise stderr. Voir HARDENING-1.4.0.md.
