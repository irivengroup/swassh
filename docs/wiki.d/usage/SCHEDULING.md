# Planification persistante — SWASSH 1.3.0

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / usage / Planification persistante — SWASSH 1.3.0

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Enregistrer et consulter](#enregistrer-et-consulter)
- [Heure, changements d'heure et délais](#heure-changements-dheure-et-délais)
- [Worker et protection du bastion](#worker-et-protection-du-bastion)
- [Reprise et absence de relance automatique](#reprise-et-absence-de-relance-automatique)
- [Stockage, rapports et audit](#stockage-rapports-et-audit)
- [Supervision native : générer puis activer](#supervision-native--générer-puis-activer)
  - [Linux : service utilisateur systemd](#linux--service-utilisateur-systemd)
  - [macOS : LaunchAgent](#macos--launchagent)
  - [Windows : Task Scheduler, compte connecté](#windows--task-scheduler-compte-connecté)
- [API Python](#api-python)
- [Solaris et AIX (1.3.2)](#solaris-et-aix-132)
- [Budget et options 1.4.0](#budget-et-options-140)
- [Diagnostic et persistance 1.5.1](#diagnostic-et-persistance-151)



`swassh schedule` enregistre une commande ou un script distant pour une date et
une heure précises, sur les cibles d'un inventaire. La commande rend la main
avec un identifiant. Un worker **doit rester actif sous supervision** :
l'enregistrement seul ne lance pas de processus en arrière-plan et n'installe
pas de service système. La planification est ponctuelle, sans récurrence.

## Enregistrer et consulter

```bash
swassh schedule 'sudo -n /opt/scripts/deploy.sh --env production' -i hosts.txt --at '2026-10-08 02:00' --timezone Europe/Paris --canary 5
swassh schedule 'uname -r' -i hosts.txt --at '2026-10-08T02:00:00+02:00' --format json
swassh schedule 'uname -r' -i hosts.txt --at '2026-10-08 00:00' --plan-only
swassh schedule --list
swassh schedule --list --limit 20 --offset 20 --format json
```

Choisir une date future lors de l'utilisation. Sans fuseau, l'heure est UTC.
La commande complète constitue un seul argument positionnel ; `-c`, `--command`
et `--commande` sont refusés. Les options habituelles de `run` restent disponibles :
`--canary`, `-j`, `--connect-rate`, budgets, délais, clés, utilisateur et saut SSH.
Un script doit être présent sur les cibles ; utiliser `push` auparavant pour un
script local. `schedule` planifie seulement des commandes, pas les transferts.

L'affichage par défaut contient une ligne par tâche, sans commande ni inventaire,
avec une limite de 20 lignes (maximum 200). JSON/CSV donnent les métadonnées,
compteurs et chemin du rapport ; les sorties des serveurs restent dans le rapport.
Les identifiants retournés sont complets, 32 caractères hexadécimaux.

```bash
# JOB_ID désigne l'identifiant retourné par l'enregistrement.
swassh schedule --show JOB_ID --format json
swassh schedule --cancel JOB_ID
swassh schedule --purge JOB_ID
```

`--cancel` accepte seulement une tâche pending. `--purge` accepte seulement un
état terminal, supprime son enregistrement et conserve ses rapports et traces.
Les indicateurs de gestion refusent les options d'exécution pour éviter qu'une
limite de charge soit ignorée. `--limit/--offset` concernent seulement `--list` ;
`--once/--poll-interval` concernent seulement `--worker`.

## Heure, changements d'heure et délais

Les dates sont normalisées en UTC lors de l'enregistrement, avec une précision
maximale de six décimales de seconde. `--at` accepte
`YYYY-MM-DD HH:MM[:SS[.microsecondes]]`, `T` à la place de l'espace, et un suffixe
`Z` ou `+HH:MM/-HH:MM`. Un suffixe explicite ne peut pas être combiné à
`--timezone` ou `--fold`. `--timezone` accepte aussi un décalage fixe.

Un nom IANA comme Europe/Paris exige les données de fuseaux du système via
`zoneinfo` standard. Sur un système sans ces données, notamment certaines
installations Windows, utiliser UTC ou un décalage explicite ; aucune dépendance
Python de fuseaux n'est requise. Une heure inexistante au passage à l'heure d'été
est refusée. Une heure répétée à l'heure d'hiver exige `--fold 0` (première
occurrence) ou `--fold 1` (seconde). L'instant UTC enregistré reste fixe après
une éventuelle mise à jour des données de fuseaux.

Le worker vérifie les échéances toutes les secondes par défaut ;
`--poll-interval` accepte 0.1 à 60 secondes. Il ne démarre jamais une tâche avant
son échéance, mais ne garantit pas une exécution à la milliseconde près. L'heure
système doit être synchronisée. Des corrections d'horloge peuvent avancer ou
retarder le lancement. Après l'admission d'une tâche, le rythme SSH et le canary
peuvent retarder le lancement sur les autres serveurs.

`--misfire-grace 300` autorise un démarrage jusqu'à 300 secondes après l'échéance
(1 à 86 400 secondes). Si le worker est arrêté ou occupé trop longtemps, la tâche
passe en **missed** sans aucune connexion. Le délai porte sur le début de la
flotte, pas la fin des commandes ni le début de chaque connexion.

## Worker et protection du bastion

```bash
swassh schedule --worker
# Variante pour supervision/pilotage externe : au plus une tâche échue.
swassh schedule --worker --once
```

Un verrou natif exclusif autorise un seul worker par répertoire d'état. Les
flottes planifiées s'exécutent **l'une après l'autre**, par échéance puis ordre
d'enregistrement. Le moteur asyncio existant limite chaque flotte en concurrence,
cadence et ressources, et réévalue les ressources du bastion au lancement.
Le canary par défaut reste 1. Aucun résultat par serveur n'est imprimé par le
worker ; le rapport conserve les détails. Un échec canary échoue la tâche et
marque les autres cibles skipped avec zéro tentative.

`--once` termine avec 0 si le worker fonctionne, même si la commande distante a
échoué ; consulter `--show` et le rapport pour le résultat métier. Le code 2
signale une entrée, un stockage, un verrou ou un journal indisponible. Un worker
continu traite aussi les tâches enregistrées pendant qu'il fonctionne.

Les invocations manuelles run/push/pull et les workers d'autres répertoires d'état
ont des budgets indépendants. Éviter leur cumul sur le même bastion ou imposer
un quota système global. Les benchmarks fournis utilisent des transports simulés.

## Reprise et absence de relance automatique

| Transition | Comportement |
| --- | --- |
| pending → running | Claim SQLite durable avant tout lancement SSH |
| running → succeeded | Rapport publié, toutes les cibles réussies |
| running → failed | Échec cible/canary, exécution ou export en erreur |
| pending → cancelled | Annulation opérateur avant le claim |
| pending → missed | Échéance + grâce dépassée |
| running → interrupted | Arrêt actif ou récupération d'un worker interrompu |

Le claim est validé avant le premier SSH. Au redémarrage, tout enregistrement
running devient interrupted ; **il n'est jamais rejoué**, même si l'arrêt s'est
produit avant la première connexion. Il s'agit d'une admission au plus une fois,
pas d'une garantie exactly-once sur les serveurs. Pour relancer, inspecter les
cibles et créer explicitement une nouvelle tâche. Les retries de connexion
existants restent limités aux échecs réseau établis avant authentification.

SIGINT/SIGTERM provoquent un arrêt coopératif sur POSIX. Un arrêt forcé ou une
coupure de machine est détecté à la prochaine prise du verrou. Sur Windows,
Ctrl+C bénéficie de l'annulation asyncio ; l'arrêt forcé du service nécessite la
récupération au prochain démarrage. Fermer SSH localement ne garantit pas l'arrêt
des processus distants. Une réussite distante suivie d'un échec d'export laisse
la tâche failed ; aucune relance automatique n'est effectuée.

## Stockage, rapports et audit

Par défaut : sous-dossier `schedules` du dossier d'état SWASSH, soit
`$XDG_STATE_HOME/swassh/schedules`, sinon `~/.local/state/swassh/schedules` sur
Unix, et `%LOCALAPPDATA%/swassh/schedules` sur Windows. Utiliser le même
`--state-dir` pour l'enregistrement, la gestion et le worker, sous le même compte.
Le répertoire doit se trouver sur un disque local fiable, sans partage NFS/SMB.

L'inventaire normalisé et les options sont copiés à l'enregistrement. La commande
est conservée telle quelle. Les chemins locaux (exécutable SSH, clés, known_hosts,
rapport, spool, journal) deviennent absolus ; les clés et known_hosts restent lus
au lancement et peuvent évoluer. La configuration d'agent SSH n'est pas copiée :
le worker doit disposer de l'agent attendu ou de clés utilisables sans interaction.

- `schedule.sqlite` : transactions FULL, requêtes paramétrées, schéma versionné,
  1 000 enregistrements maximum, 128 Mio de pages maximum, snapshot limité à 10 Mio.
- `runs/JOB_ID/report.text` par défaut CLI, `.json` ou `.csv` selon `--format` ;
  `-o` permet un autre chemin absolu dont le parent doit déjà exister.
- `runs/JOB_ID/audit.jsonl` pour l'exécution ; `--log-file` permet un autre journal.
- `scheduler.jsonl` pour les créations, claims, issues, annulations et purges.

Les événements de planification sont enregistrés dans la même transaction que
les changements d'état, puis exportés par le worker. Ils persistent dans SQLite
si le journal est indisponible ; le worker refuse alors de poursuivre les lancements.
L'export est au moins une fois face à un arrêt du processus : un arrêt entre
écriture et acquittement peut
répéter un événement avec le même event_id. À partir de 1.3.1, le flush synchronise aussi le journal avant acquittement ;
les états et événements non acquittés bénéficient de SQLite FULL. La durabilité
physique dépend toujours du filesystem et du stockage, voir HARDENING-1.3.1.md. Les journaux excluent commandes et
sorties en clair ; rotation 100 Mio, trois archives gzip chacun.

Sous POSIX : état/runs privés 0700, fichiers 0600, liens refusés pour les fichiers
sensibles. Les ACL Windows doivent être restreintes au compte d'exploitation.
Les commandes et inventaires sont stockés en clair : le compte du worker et
root/administrateur restent de confiance. Le SHA-256 du snapshot détecte les
corruptions, pas une modification volontaire par ce compte.

La purge libère les places et les pages réutilisables, pas nécessairement la
taille physique du fichier. La limite des pages n'inclut pas le journal de
transaction temporaire, les rapports finaux ou les rotations d'audit. Les rapports
et journaux de chaque tâche restent sur disque jusqu'au nettoyage opérateur ;
prévoir une politique de conservation et surveiller l'espace total.

## Supervision native : générer puis activer

Installer d'abord le wheel dans un environnement stable et exécuter ces commandes
depuis la distribution source. Le générateur écrit un fichier complet, sans
installer le service, et refuse d'écraser un fichier existant. `--python` choisit
l'interpréteur où SWASSH est installé, sinon l'interpréteur du générateur.
Ne pas déplacer cet environnement après activation.

### Linux : service utilisateur systemd

```bash
python scripts/scheduler_service.py --platform systemd --state-dir "$HOME/.local/state/swassh/schedules" --output-dir "$HOME/.config/systemd/user"
systemctl --user daemon-reload
systemctl --user enable --now swassh-scheduler.service
systemctl --user status swassh-scheduler.service
journalctl --user -u swassh-scheduler.service
```

Le service tourne sous le compte courant. Pour fonctionner sans session ouverte,
l'exploitation peut activer le linger du compte selon sa politique. Le service
redémarre après une erreur, avec KillMode=control-group et un délai d'arrêt de
30 secondes. Provisionner la disponibilité des clés/agent pour ce contexte.

### macOS : LaunchAgent

```bash
python scripts/scheduler_service.py --platform launchd --state-dir "$HOME/.local/state/swassh/schedules" --output-dir "$HOME/Library/LaunchAgents"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/org.swassh.scheduler.plist"
launchctl kickstart "gui/$(id -u)/org.swassh.scheduler"
```

Cet agent dépend de la session de l'utilisateur ; un service LaunchDaemon sous
un compte dédié nécessite une configuration d'exploitation adaptée. Les sorties
ne contiennent pas les détails par cible ; consulter les journaux SWASSH.

### Windows : Task Scheduler, compte connecté

```powershell
python scripts/scheduler_service.py --platform windows --state-dir "$env:LOCALAPPDATA/swassh/schedules" --output-dir "$env:LOCALAPPDATA/swassh/services"
$definition = Get-Content -Raw -Encoding UTF8 "$env:LOCALAPPDATA/swassh/services/swassh-scheduler.xml"
Register-ScheduledTask -TaskName "SWASSH Scheduler" -Xml $definition
Start-ScheduledTask -TaskName "SWASSH Scheduler"
Get-ScheduledTaskInfo -TaskName "SWASSH Scheduler"
```

La définition démarre le worker à la connexion de l'utilisateur, sans limite de
durée, et redémarre jusqu'à trois fois après erreur. Elle utilise InteractiveToken,
sans stocker de mot de passe : le compte doit être connecté. Un worker sans
session exige une politique de compte/service native, à configurer par l'exploitation.
`--user DOMAIN\compte` permet de préciser l'identité lors de la génération.

Les définitions générées sont vérifiées par les tests (arguments et XML/plist),
mais leur activation réelle reste à valider sur chaque OS cible. Aucun service
n'est installé automatiquement par cette livraison.

## API Python

```python
from swassh import Scheduler, Options

with Scheduler('/srv/swassh-state') as scheduler:
    job = scheduler.schedule(
        ['admin@srv01', 'admin@srv02'],
        '/opt/scripts/check.sh --verbose',
        '2026-10-08 02:00',
        timezone='Europe/Paris',
        options=Options(canary=1),
    )
    print(job.id)
```

L'API d'enregistrement est synchrone ; le worker `SchedulingService.serve()`
est asynchrone. La CLI supervise ses signaux et ferme le store proprement.
Voir tests/test_scheduling.py pour les ports injectés et la simulation d'horloge.

## Solaris et AIX (1.3.2)

Le générateur accepte aussi --platform smf (Solaris : XML et méthode du contrat)
et --platform src (AIX : lanceur foreground pour SRC). Les commandes d'activation,
droits, signaux, prérequis et gates natifs figurent dans [PORTABILITY.md](../operations/PORTABILITY.md).
Ces nouvelles définitions n'installent ni n'activent de service automatiquement.

## Budget et options 1.4.0

Les nouveaux paramètres --bastion-*, --budget-dir, --adaptive et --progress
sont conservés dans le snapshot. La racine du budget est épinglée en chemin
absolu à l'enregistrement ; le worker l'applique avant le reporter et le canary.
Les snapshots 1.3.x restent lisibles avec les valeurs par défaut des nouveaux
champs, sans migration destructive. Un ancien budget mémoire supérieur au
plafond partagé courant doit être replanifié avec une politique adaptée ; aucune
relaxation automatique d'une protection ni replay d'un job interrompu.

## Diagnostic et persistance 1.5.1

Pour un job dont `reason` vaut `execution_or_report_error`, rechercher son
`job_id` dans `scheduler.jsonl`, situé dans le répertoire d'état du worker.
L'événement `schedule_failed` inclut désormais `diagnostic.category`,
`diagnostic.error_type` et `diagnostic.errno` : ils distinguent notamment délai,
permissions, fichier absent et erreur d'entrée/sortie sans enregistrer le message
potentiellement sensible de l'exception. La catégorie `unexpected` ne constitue
pas un diagnostic causal complet : conserver aussi le rapport et les journaux
privés du job pour l'investigation.

Une erreur de persistance du résultat terminal remonte au superviseur. Un succès
déjà enregistré reste un succès ; un claim non confirmé est interrompu sans
rejeu. Une commande peut avoir réussi sur la cible même si le job est ensuite
`interrupted` : vérifier son effet avant toute replanification manuelle.

Les critères de promotion, les contrôles de panne et l'incident historique
non expliqué sont détaillés dans [RELEASE-1.5.1.md](../history/releases/RELEASE-1.5.1.md).
