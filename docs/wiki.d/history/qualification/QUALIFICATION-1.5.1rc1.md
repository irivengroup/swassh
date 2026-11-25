# Qualification SWASSH 1.5.1rc1

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.5.1rc1

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Contrôles observés](#contrôles-observés)
- [Incident ouvert](#incident-ouvert)
- [Contrôles restant à exécuter](#contrôles-restant-à-exécuter)
- [Reproduction et exploitation](#reproduction-et-exploitation)



Campagne du 22 octobre 2026. **Version candidate ; qualification globale NON TERMINÉE.** Les preuves 1.5.0 conservées dans `validation/history-1.5.0/` ne valident pas cette version.

## Contrôles observés

| Contrôle | Statut | Résultat |
| --- | --- | --- |
| Windows Python 3.11.9, 3.12.10, 3.13.16 | EXÉCUTÉ | 307 tests chacun, zéro échec, 54 ignorés ; sondes de plateforme réussies |
| Windows Python 3.14.7 | EXÉCUTÉ | Suite finale étendue : 313 tests, zéro échec, 54 ignorés ; plateforme réussie |
| Évolution pip/PATH Windows | EXÉCUTÉ | 35 tests ciblés par runtime 3.11 à 3.14, zéro échec, cinq profils POSIX ignorés ; registre réel dans une clé jetable |
| Linux Python 3.12.3 | EXÉCUTÉ | 313 tests, zéro échec, six tests Windows ignorés |
| Couverture Linux | EXÉCUTÉ | 91,80 % : 4646/5061 lignes avant les ultimes gardes ciblées ; seuil existant 90 % inchangé ; branches et enfants non tracés directement |
| Réseau natif | EXÉCUTÉ | 11 tests sans ignorés : SSH, ProxyJump, SFTP, rsync, SHA-256 push/pull, prévisualisation et suppression réelle dans le laboratoire |
| Déploiement pip | EXÉCUTÉ | Index local réel, wheel dans un venv neuf, commande installée, redéploiement idempotent, échec pip propagé ; profil puis vrai shell sous Linux |
| Non-régression | EXÉCUTÉ | Quatre nouveaux tests échouent sur la 1.5.0 immuable ; deux tests PATH échouent aussi sur cette version ; corrections contrôlées séparément |
| Concurrence | EXÉCUTÉ | Dix processus, propriété des verrous, migration d'horloge, délai pondéré long, contention en début et en validation de transaction |
| Qualité statique | EXÉCUTÉ | 80 modules : syntaxe, règles AST, imports standard et frontières DDD ; aucune dépendance Python ajoutée |
| Planifications répétées | EXÉCUTÉ | 40 jobs, deux passages worker chacun, deux hôtes exécutés exactement une fois par job, rapports réussis |

Les suites ont accompagné des changements successifs. Les dernières gardes (contention au commit et refus d'une installation masquée dans PATH) ont des contrôles ciblés supplémentaires. Les résultats détaillés et les contrôles des distributions exactes sont consignés dans `validation/hardening.json`, `validation/installation-*.json` et la preuve externe de livraison. Une preuve historique ou absente ne vaut pas validation du code final. Les logs bruts ne sont pas livrés.

Les tests ignorés couvrent les fonctions propres à l'autre système, les outils natifs indisponibles et la base IANA Windows absente. Aucun ignoré ne compte comme réussite. Le registre utilise une clé jetable et la notification Windows une doublure : aucun PATH réel du compte de qualification n'a été modifié.

## Incident ouvert

**ÉCHOUÉ — stabilité historique de la planification non établie.** Une campagne 1.5.0 avait observé un état différent de `succeeded`, sans conserver la cause. Les 40 jobs et les installations suivantes réussissent, mais ne prouvent pas la résolution de cet incident. La contention du budget corrigée ici est une cause possible, pas démontrée de cet événement. La sonde conserve désormais état, raison, compteurs et dates. La version reste candidate.

## Contrôles restant à exécuter

| Contrôle | Statut, raison et procédure | Attente et risque restant |
| --- | --- | --- |
| macOS, Solaris, AIX natifs | NON EXÉCUTÉ : machines absentes ; Python >=3.11 et outils natifs requis ; lancer `scripts/verify.py`, `scripts/platform_gate.py --expected macos` (ou `solaris`, `aix`) et docs/wiki.d/operations/PORTABILITY.md | Aucun échec ; différences de noyau, verrou et processus non prouvées |
| Autres Python Linux et CI distante | NON EXÉCUTÉ : laboratoire Linux 3.12 seulement, aucun dépôt/runner activé ; exécuter la matrice CI fournie | Toutes les étapes réussies avant publication ; autres combinaisons non qualifiées |
| Publication PyPI/index privé | NON EXÉCUTÉ : droits et destination non fournis ; vérifier tag/version, CI puis workflow release avec les autorisations du propriétaire | Distributions disponibles sur l'index ; installation publique par nom non promise avant publication |
| Services et flotte cible | NON EXÉCUTÉ : machines de production absentes ; suivre docs/wiki.d/usage/SCHEDULING.md, canary et quotas sur une flotte autorisée | Arrêt/reprise sans rejeu, ressources et latence acceptables ; laboratoire non représentatif du réseau cible |
| Audit indépendant | NON EXÉCUTÉ : auditeur indisponible ; revue externe du code et du déploiement | Aucun constat critique ; tests et règles AST ne prouvent pas une sécurité exhaustive |

## Reproduction et exploitation

Exécuter `python scripts/verify.py`, `python scripts/coverage.py`, `python scripts/native_network_gate.py` avec les prérequis natifs, puis `python scripts/build.py`, `python scripts/validate_installation.py`, `python scripts/validate_deployment.py` et `python scripts/package.py`.

Le déploiement utilise pip ; PATH est configuré pour les nouvelles sessions, jamais pour le shell parent déjà ouvert. Installation, sauvegardes, compatibilité et rollback : docs/wiki.d/operations/INSTALLATION.md et docs/wiki.d/history/hardening/HARDENING-1.5.1rc1.md.

Le budget reste local au même compte et à la même racine. La mémoire est estimée. SHA-256 vérifie un fichier et suppose un serveur distant de confiance. Le preview ne réserve pas l'état distant et ne remplace pas une sauvegarde avant suppression. `--show-output` et JSON/CSV conservent leurs possibilités et limites de capture. Aucun défaut connu n'est déclaré résolu par une simple relance réussie.
