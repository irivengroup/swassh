# Qualification SWASSH 1.5.1rc2

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.5.1rc2

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Performance et résilience](#performance-et-résilience)
- [Contrôles encore manquants](#contrôles-encore-manquants)
- [Livraison et retour arrière](#livraison-et-retour-arrière)



Campagne du 22 octobre 2026. **Candidate ; qualification globale NON TERMINÉE.**
Les preuves des versions antérieures sont conservées dans les répertoires
`validation/history-*` ; elles ne qualifient pas les distributions actuelles.

| Contrôle | Statut | Résultat observé |
| --- | --- | --- |
| Suite complète Windows Python 3.14.7 | EXÉCUTÉ | 318 tests, zéro échec, 54 ignorés, 189.32 s |
| Suite complète Linux Python 3.12.3 | EXÉCUTÉ | 318 tests, zéro échec, 6 ignorés, 221.341 s |
| Cinq régressions Windows Python 3.11.9 / 3.12.10 / 3.13.16 / 3.14.7 | EXÉCUTÉ | Cinq réussites par runtime ; cinq échecs attendus sur l'archive 1.5.1rc1 intacte |
| Couverture Linux du code final | EXÉCUTÉ | 91.90 %, seuil existant 90 % inchangé ; 317 tests hors benchmark |
| Réseau natif isolé | EXÉCUTÉ | 11 tests, zéro échec et zéro ignoré : SSH, ProxyJump, rsync/SFTP, SHA-256, prévisualisation et suppressions |
| Qualité statique et architecture | EXÉCUTÉ | 81 modules, syntaxe, règles AST, dépendances standard et frontières DDD |
| Installation et déploiement Linux | EXÉCUTÉ | Sept étapes du laboratoire réussies, dont pip/index local, wheel/sdist, PATH POSIX et plateforme |

Les ignorés sont indiqués dans les journaux : fonctions propres à l'autre OS,
outils natifs indisponibles sous Windows et base IANA absente. Ils ne sont pas
comptés comme réussites. La couverture mesure les lignes avec `trace`, pas les
branches ni directement les processus enfants ; les stores ont leurs tests directs.

## Performance et résilience

Le scénario simulé de 50 000 hôtes contrôle le nombre de workers, les 50 000
résultats exportés et un pic mémoire Python principal inférieur à 96 Mio.
Les mesures exactes Windows/Linux figurent dans `validation/review.json`.
Elles ne mesurent ni le débit SSH réel, ni la mémoire totale des processus natifs.
Aucun gain de performance par rapport à rc1 n'est revendiqué : les changements
portent sur les chemins d'erreur et de fermeture.

La suite couvre également les quotas interprocessus, la récupération après mort
du propriétaire, la contention SQLite, les limites de sorties, l'annulation,
les descendants, les chemins locaux et les rapports atomiques. Les cinq nouveaux
défauts sont détaillés dans `docs/wiki.d/history/hardening/HARDENING-1.5.1rc2.md`.

## Contrôles encore manquants

| Contrôle | Statut | Raison, procédure, prérequis, attente et risque |
| --- | --- | --- |
| Incident historique de planification 1.5.0 | ÉCHOUÉ | L'échec reste sans cause établie, ses diagnostics initiaux ayant été perdus. Reproduire sous charge en conservant état, raison et journal privés ; attendre une cause et un test déterministe. Risque de récidive non exclu. |
| Suites complètes finales Windows 3.11–3.13 | NON EXÉCUTÉ | Seules les nouvelles régressions sont rejouées sur ces runtimes pendant cette passe. Exécuter `python scripts/verify.py` avec chacun ; attendu zéro échec. Risque de combinaison propre au runtime. |
| macOS, Solaris, AIX natifs | NON EXÉCUTÉ | Hôtes indisponibles. Sur chaque système avec Python >=3.11 et OpenSSH pris en charge : `python scripts/verify.py`, `python scripts/platform_gate.py --help`, puis la sonde adaptée et `python scripts/validate_installation.py`. Attendu zéro échec applicable. Risque de différences noyau, ACL, outils et services. |
| CI distante et publication | NON EXÉCUTÉ | Pas de lancement distant ni publication demandée ; exécuter les workflows CI puis release avec les accès requis. Attendre succès des contrôles et installation depuis l'index. L'archive locale n'est pas une publication PyPI. |
| Charge d'un parc SSH réel | NON EXÉCUTÉ | Parc représentatif et fenêtre de test indisponibles. Exécuter un canary puis une montée bornée avec métriques et seuils convenus. Attendre plafonds respectés et aucune fuite ; débit réel et dimensionnement restent à mesurer. |
| Analyse externe de vulnérabilités des outils natifs | NON EXÉCUTÉ | Pas de scanner externe exécuté. Inventorier les versions OpenSSH/rsync/Python déployées, confronter aux avis éditeurs et appliquer la politique de correctifs. Les règles AST locales ne remplacent pas cet audit. |

## Livraison et retour arrière

La preuve d'installation des distributions exactes est ajoutée séparément après
leur construction dans `validation/installation-review-*.json`. Le manifeste
du ZIP et les SHA-256 permettent de vérifier son contenu. Les logs bruts,
environnements, caches et clés du laboratoire ne sont pas livrés.

Arrêter les invocations et le worker avant de réinstaller une wheel précédente
avec le même Python applicatif. Garder bases et rapports : aucun schéma n'a changé.
Les erreurs de stockage restent visibles ; un fichier impossible à supprimer
peut nécessiter une intervention après arrêt. Voir `docs/wiki.d/operations/INSTALLATION.md` pour
pip, PATH et ses sauvegardes. Aucune garantie « zéro bug » n'est déduite des tests.
