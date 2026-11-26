# Qualification SWASSH 1.5.0

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.5.0

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Contrôles réellement exécutés](#contrôles-réellement-exécutés)
- [Réserve de stabilité sur le contrôle d'installation Linux](#réserve-de-stabilité-sur-le-contrôle-dinstallation-linux)
- [Contrôles encore nécessaires](#contrôles-encore-nécessaires)
- [Contrats et limites](#contrats-et-limites)



Campagne des 10–11 octobre 2026 ; installation et contrôle des artefacts nettoyés repris le 22 octobre 2026. Moteur figé avant les suites finales ; un message défensif setup-path, un diagnostic de test et le repli d’encodage texte Windows ont ensuite été ajoutés et contrôlés par tests ciblés.
Les preuves de versions antérieures ne sont pas utilisées comme validations de
cette version. La livraison 1.4.2 reste conservée pour retour arrière.

## Contrôles réellement exécutés

| Contrôle | Statut | Résultat observé |
| --- | --- | --- |
| Windows 11 / CPython 3.11.9 | EXÉCUTÉ | 300 tests ; zéro échec ; 52 ignorés ; 234.537 s |
| Windows 11 / CPython 3.12.10 | EXÉCUTÉ | 300 tests ; zéro échec ; 52 ignorés ; 232.686 s |
| Windows 11 / CPython 3.13.16 | EXÉCUTÉ | 300 tests ; zéro échec ; 52 ignorés ; 166.360 s |
| Windows 11 / CPython 3.14.7 | EXÉCUTÉ | 300 tests ; zéro échec ; 52 ignorés ; 173.468 s |
| Linux WSL2 / CPython 3.12.3 | EXÉCUTÉ | 300 tests ; zéro échec ; 5 ignorés ; 208.596 s |
| Couverture Linux | EXÉCUTÉ | 91.83 % (4553/4958 lignes), code final incluant les messages défensifs et le repli d’encodage texte ; seuil existant 90 % inchangé ; 299 tests hors benchmark |
| Réseau natif | EXÉCUTÉ | 11 tests, zéro ignoré ; OpenSSH 9.6p1, rsync 3.5.1, SFTP, ProxyJump, push/pull SHA-256, preview puis --delete |
| Installation/PATH POSIX | EXÉCUTÉ | Profils réels dans un home temporaire : sauvegarde, idempotence, shell réel, espaces/apostrophes/dollar, refus de liens/fifo/permissions dangereuses ; flux pip testé séparément |
| Présentation | EXÉCUTÉ | JSON indenté progressif, CSV multiligne avec séparateurs, synthèse par exception, changed explicite, sorties réussies via --show-output, NO_COLOR, contrôles terminal neutralisés |
| Multiprocessus/asynchrone | EXÉCUTÉ | Rapports écrits dans un vrai processus enfant ; aucune collecte de flotte complète pour l'export ; annulation et limites existantes |
| Non-régression fonctionnelle | EXÉCUTÉ | run, push/pull, schedule, canary, inventaires, budgets communs, chemins épinglés, descendants Windows, SHA-256, preview et admission adaptative |
| Pacer | EXÉCUTÉ | Nouveau test déterministe : échoue sur le code 1.4.2 (un échec attendu), réussit sur 1.5.0 ; échéance revérifiée après réveil anticipé |
| Flotte simulée | EXÉCUTÉ | 50 000 commandes et 10 001 transferts ; contrôle du nombre exact de résultats, mémoire et concurrence conservé |
| Qualité et architecture | EXÉCUTÉ | 78 modules : syntaxe, règles statiques/imports standard, frontières DDD et absence de cycles ; aucune dépendance Python ajoutée |
| Sondes de plateforme | EXÉCUTÉ | Windows quatre runtimes et Linux avec rsync requis : configuration SSH, ressources, stockage et processus rapport |

Les 52 skips Windows couvrent les fixtures POSIX, serveurs/rsync locaux, profils
shell POSIX et base IANA indisponible. Les cinq skips Linux sont spécifiques à
Windows. Les listes exactes sont dans `validation/qa-*.json`. Un skip n'est pas
une validation. Les contrôles de couverture ne mesurent pas les branches et ne
tracent pas directement les enfants ; ceux-ci ont leurs tests d'intégration.

Les preuves des installations **des distributions exactes contenues dans le ZIP**
se trouvent dans `validation/installation-windows.json` et
`validation/installation-linux.json`, avec statut, nombre de contrôles, SHA-256
et environnements neufs. La preuve externe `release-verification-1.5.0.json`
identifie le ZIP, son manifeste et sa reproductibilité. Ces attestations sont
produites après construction et ne sont pas des auto-attestations internes à la
wheel. Les commandes de reproduction sont : `python scripts/verify.py`,
`python scripts/coverage.py`, `python scripts/native_network_gate.py` (laboratoire
Linux SSH/rsync requis), `python scripts/build.py`,
`python scripts/validate_installation.py`, `python scripts/package.py`.

Les paquets Linux signés sont extraits dans des montages/processus/réseau privés,
sans installation persistante de serveur dans la distribution hôte. Clés SSH et
fixtures sont temporaires. Les empreintes des prérequis figurent dans validation.
Les résultats en boucle locale et flottes simulées ne prouvent ni la RSS globale
ni la capacité d'un bastion en production.

## Réserve de stabilité sur le contrôle d'installation Linux

**ÉCHOUÉ — stabilité globale non établie.** Une première installation des
artefacts a échoué sur l'assertion d'état final d'une tâche schedule. Le test
n'imprimait alors ni l'état observé ni la cause ; son répertoire temporaire a
été nettoyé. Le diagnostic a été renforcé, sans modifier le moteur ni l'assertion
attendant succeeded. L'exécution instrumentée suivante a réussi pour les deux
distributions, mais la cause de l'échec initial reste indéterminée. Les résultats
réussis ne sont pas présentés comme une correction de cette instabilité.
Avant promotion en production : reproduire avec le diagnostic ajouté dans
scripts/validate_installation.py, conserver l'état/reason/counts de tout échec,
identifier sa cause et ajouter le test de régression correspondant. Risque
restant : échec intermittent du scénario de planification installé, ou de sa
fixture de qualification, non départagé. L'archive est un **candidat à qualifier**,
pas une certification de production.

## Contrôles encore nécessaires

| Contrôle | Statut et raison | Procédure / prérequis / attendu / risque restant |
| --- | --- | --- |
| macOS, Solaris et AIX natifs | NON EXÉCUTÉ : machines non fournies | CPython 3.11+ 64 bits et OpenSSH ; verify.py, build.py, validate_installation.py, platform_gate.py avec l'OS attendu ; codes 0 attendus ; API/permissions/filesystems natifs non qualifiés ici |
| Autres Python Linux | NON EXÉCUTÉ : laboratoire Linux 3.12 uniquement | Exécuter CI Python 3.11, 3.13 et 3.14 ; mêmes contrôles sans échec ; autres combinaisons non prouvées |
| CI distante / publication | NON EXÉCUTÉ : aucun dépôt/runner activé | Exécuter les workflows prévus, publication après toutes les gates ; aucune publication effectuée |
| Superviseurs natifs déployés | NON EXÉCUTÉ : aucun service de production autorisé | Suivre docs/wiki.d/usage/SCHEDULING.md, permissions, démarrage/arrêt, reprise sans rejeu ; intégration SMF/SRC/launchd/Task Scheduler à qualifier sur cible |
| Charge et réseau réels | NON EXÉCUTÉ : flotte non fournie | Canary puis charge représentative avec clés vérifiées et quotas OS ; mesurer erreurs, latence, RSS et débit ; boucle locale non représentative du réseau cible |
| Audit externe de sécurité | NON EXÉCUTÉ : audit indépendant indisponible | Revue spécialisée du code et déploiement ; aucun constat critique attendu ; règles AST et tests ne prouvent pas une sécurité exhaustive |

## Contrats et limites

Le moteur conserve les plafonds et options existants. changed est un booléen
additif, déclaré par un adaptateur uniquement pour un succès ; aucune heuristique
sur une commande opaque. Le texte masque par défaut les sorties des succès ;
`--show-output` les affiche pour chaque hôte. Dix lignes et 240 caractères par
ligne par défaut ; `--output-lines 0` retire uniquement la limite de lignes.
JSON/CSV conservent les données capturées et les marqueurs de troncature réseau.
CSV ajoute une colonne changed et des séparateurs vides : les consommateurs
positionnels doivent adapter leur schéma et ignorer les lignes vides.

Le wheel pip ne modifie pas le shell parent. L'installateur explicite configure
les prochaines sessions POSIX ; appliquer l'export imprimé au shell courant.
Windows et environnements virtuels utilisent leur configuration/activation
native (`--skip-path`). Les profils modifiés sont sauvegardés ; aucun profil
réel de l'utilisateur n'a été modifié pendant cette qualification.

Le budget partagé est local au même compte et à la même racine, pas distribué
ni multi-utilisateur. Les budgets mémoire sont des estimations. La vérification
SHA-256 vise un fichier, avec shell POSIX et outil natif distant ; elle ne protège
pas contre un serveur malveillant. Le preview ne réserve pas l'état distant et
ne remplace pas une sauvegarde avant --delete. Les autres limites opérationnelles
figurent dans docs/wiki.d/history/hardening/HARDENING-1.4.0.md.

**Qualification de toutes les plateformes : NON TERMINÉE.** Les contrôles locaux
ci-dessus ont été exécutés avec les résultats indiqués ; les validations
NON EXÉCUTÉ restent requises pour une qualification globale. Matrice d'impact,
compatibilité, installation et rollback : docs/wiki.d/history/releases/RELEASE-1.5.0.md.
