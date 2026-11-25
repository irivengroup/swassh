# SWASSH 1.4.1 — reprise et vérification native

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / releases / SWASSH 1.4.1 — reprise et vérification native

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Fonctionnalités intégrées](#fonctionnalités-intégrées)
- [Corrections issues de la revue 1.4.1](#corrections-issues-de-la-revue-141)
- [Impact, menaces et exploitation](#impact-menaces-et-exploitation)
- [Installation, mise à niveau et retour arrière](#installation-mise-à-niveau-et-retour-arrière)
- [Reproduire les contrôles](#reproduire-les-contrôles)



Cette livraison part de l'archive 1.3.2 fournie, dont les 101 entrées du
manifeste ont été vérifiées. Les modifications 1.4.0 ont été récupérées dans
l'historique accessible du développement, puis relues et corrigées localement.
Les résultats de tests historiques ne sont pas réutilisés comme preuves.
Voir [VALIDATION.md](../../../../VALIDATION.md) pour les contrôles de cette livraison.

## Fonctionnalités intégrées

- Budget partagé entre invocations et workers schedule du même compte local :
  SQLite transactionnel, files FIFO bornées, verrous système, réservations de
  connexions, rythme, mémoire estimée et débit. Les sauts SSH ne créent pas de
  pools indépendants. Les processus guardians conservent les réservations pendant
  la vie des clients et récupèrent les orphelins sans rejouer les commandes.
- Traversée locale sécurisée, publication atomique et parents épinglés ; sous
  Windows, refus des reparse points, DACL privées et Job Objects hérités par les
  clients avant leur lancement.
- `push/pull --dry-run` : comptage borné des ajouts, modifications et suppressions
  rsync, sans synchronisation des données. Le résultat décrit un état observé,
  pas une réservation de l'état pour une exécution ultérieure.
- `push/pull --verify-sha256` pour un fichier, vérification avant publication ;
  `run/push/pull --adaptive` pour réduire l'admission face aux pannes réseau,
  remonter progressivement et respecter les plafonds partagés.

Les commandes positionnelles, inventaires, canary, schedule, rapports JSON/CSV
et architecture DDD `src/` sont conservés. Aucune dépendance Python d'exécution
externe n'est ajoutée. Les options et invariants détaillés sont dans
[HARDENING-1.4.0.md](../hardening/HARDENING-1.4.0.md).

## Corrections issues de la revue 1.4.1

Les handles Windows demandent aussi l'accès de parcours pour empêcher réellement
le renommage d'un parent pendant une publication. Les noms de périphériques,
flux alternatifs et noms normalisés ambigus sont refusés. La lecture du hash
local utilise la même ouverture sans suivi de liens que les fichiers sensibles.

Le snapshot Windows compare des métadonnées provenant de descripteurs cohérents :
le décalage `lstat/fstat` de `ctime` rencontré avec CPython ne provoque plus de faux
rejet. Les contrôles d'identité et de modification pendant la copie demeurent.
Référence : [défaut CPython 157671](https://github.com/python/cpython/issues/157671).

Un hash distant tronqué ne peut plus produire un succès ni lancer les données.
Un preview pull n'applique pas de nouvelles permissions à la destination.
Les compteurs corrompus du coordinateur échouent explicitement avant admission.
Un coordinateur resté ouvert sans réservation ne peut pas réutiliser une ancienne
politique après une réduction des plafonds ; les réservations mortes de l'ancienne
politique sont récupérées avant le changement à froid.
Les tests natifs couvrent aussi la mort forcée du parent Windows et la récupération
de sa réservation après terminaison du client.

Les distributions ont des timestamps et permissions d'archive déterministes ;
un test compare les octets après modification des dates des sources. La CI
installe désormais wheel et sdist dans des environnements neufs, hors ligne.
Les fixtures normalisent leurs propres sorties et chemins pour Windows, sans
modifier les octets des commandes distantes en production.

## Impact, menaces et exploitation

| Domaine | Garantie / décision | Limite et action d'exploitation |
| --- | --- | --- |
| Concurrence | Admission transactionnelle, verrous de vie, files bornées | Même compte, même racine et politique ; filesystem local avec verrous, pas NFS ni budget distribué multi-utilisateur |
| Arrêt | Guardians et Job Objects, aucune reprise mutante automatique | Une commande distante peut continuer ; contrôler son état avant toute reprise |
| Mémoire | Réservation avant inventaire/snapshot/report et coût des guardians | Estimations, pas quotas RSS ; compléter par limites OS et disque |
| Chemins | Parents épinglés, ouvertures sans liens, publication atomique | Root, SYSTEM et compte courant fiables ; pas isolation contre un processus hostile du même compte |
| Suppression | Preview rsync explicite, comptage sans liste de noms | La vraie exécution conserve `--delete` ; sauvegarder la destination et relire le preview avant déploiement |
| Intégrité | SHA-256 du staging avant publication | Fichier seulement, espace distant fiable, shell POSIX et outil SHA requis ; pas preuve face à un serveur malveillant |
| Réseau | Pacing, plafonds communs, adaptation et circuit | Les travaux déjà admis terminent ; pas de garantie d'annulation côté serveur |
| Compatibilité | CLI et snapshots schedule compatibles | Qualification native macOS/Solaris/AIX et profil réseau rsync à compléter selon VALIDATION.md |

## Installation, mise à niveau et retour arrière

Arrêter les admissions CLI et workers schedule, attendre la fin des clients et
conserver les rapports/audits. Sauvegarder les états schedule et les destinations
avant toute synchronisation destructive. Installer le wheel 1.4.1 dans un nouvel
environnement, vérifier `swassh --version` puis les plans des commandes prévues.
Exécuter `python scripts/platform_gate.py --expected windows` ou `--expected linux`
selon le bastion. Les détails des autres OS figurent dans PORTABILITY.md.

Configurer une racine `--budget-dir` commune sur disque local et des fichiers
d'audit distincts. Ne pas effacer une base ou des verrous pendant l'exécution.
Déployer d'abord sur un canary et contrôler les résultats avant la flotte.

Pour revenir à 1.3.2, arrêter complètement 1.4.1, restaurer l'environnement et
l'état schedule sauvegardés, puis vérifier les jobs avant de relancer le worker.
Ne pas mélanger les deux versions actives : 1.3.2 ne participe pas au nouveau
coordinateur. Le retour de version ne restaure pas les fichiers supprimés ou
modifiés à distance ; utiliser la sauvegarde de ces données. Les temporaires
distants d'une publication ambiguë doivent être inspectés manuellement.

## Reproduire les contrôles

Depuis la racine extraite, avec Python 3.11+ 64 bits et OpenSSH :

```sh
python scripts/verify.py
python scripts/coverage.py
python scripts/build.py
python scripts/validate_installation.py
python scripts/package.py
```

Le seuil de couverture historique de 90 % est conservé. Le traçage porte sur les
lignes du processus parent, pas les branches ni les processus enfants. Sous POSIX,
`SWASSH_TEST_SFTP_SERVER` peut désigner un binaire `sftp-server` préprovisionné
pour les tests locaux `sftp -D` ; cette variable n'affecte pas le produit.
