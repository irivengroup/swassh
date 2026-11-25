# Qualification SWASSH 1.5.3

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.5.3

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Limites restantes](#limites-restantes)



Périmètre : diagnostics SSH et vérifications locales, avant canary et avec
`--check`. Les autres fonctions et seuils sont conservés. Les preuves historiques
se trouvent dans `history-*` et ne sont pas présentées comme des essais actuels.

| Contrôle | Statut | Résultat observé |
| --- | --- | --- |
| Windows Python 3.14, suite complète et contrôles statiques | EXÉCUTÉ | 347 tests recensés, 56 ignorés, zéro échec, 199.042 s |
| Linux Python 3.12, suite de couverture | EXÉCUTÉ | 346 tests recensés, 20 ignorés, zéro échec, 134.626 s |
| Couverture de lignes | EXÉCUTÉ | 91.92 %, seuil 90 % conservé |
| SSH natif et porte de qualification Linux/rsync | EXÉCUTÉ | 11 tests SSH natifs sans exclusion ni échec ; deux étapes avec code de sortie 0, environnement isolé |
| Régression du diagnostic de format de clé | EXÉCUTÉ | Assertion échoue sur 1.5.2 et réussit sur 1.5.3 |

Les suites finales incluent les cas de clé absente, vide, non régulière,
permissions POSIX, confidentialité des diagnostics, contrôle sans création de
tâche ou réservation de budget, formats et bornes des transferts. Les tests
existants couvrent également les sorties par défaut, le canary, les budgets,
la planification et les protections de processus.

La couverture porte sur les lignes du processus observé, pas toutes les branches
ni tous les processus enfants. Les tests ignorés correspondent aux capacités
de plateforme et outils absents ; les essais natifs Linux sont exécutés à part.
Une première passe antérieure aux derniers ajustements est conservée hors
archive ; seuls les résultats finaux ci-dessus servent de preuve courante.

Les preuves des installations exactes du wheel et du sdist sont ajoutées après
construction dans `validation/installation-review-windows.json` et
`validation/installation-review-linux.json`. Elles indiquent leurs empreintes,
les environnements neufs et les codes observés. Les contrôles d'installation
incluent `--check`, l'absence de création de rapport/budget et le refus d'une
clé manquante. `dist/release-verification-1.5.3.json`, livré à côté du ZIP,
donne les empreintes et les résultats de reproductibilité. Les logs bruts
d'installation, contenant des chemins locaux, sont exclus de la livraison.

## Limites restantes

**Qualification de toutes les plateformes : NON TERMINÉE.** Aucune garantie
d'absence totale de défaut n'est formulée. Le contrôle local ne démontre pas
l'authentification distante, la confiance des clés serveur, les quotas, les
versions des outils ou la disponibilité future de l'agent du worker.

| Contrôle | Statut | Raison, procédure et risque restant |
| --- | --- | --- |
| macOS, Solaris, AIX et autres versions Python | NON EXÉCUTÉ | Machines/runtimes non mobilisés ; sur chaque cible avec SSH/rsync, lancer `python scripts/verify.py`, `python scripts/platform_gate.py` puis `python scripts/native_network_gate.py`. Attendu : zéro échec applicable. Risque : particularités OS/outils non rééprouvées. |
| CI distante et publication | NON EXÉCUTÉ | Pas de publication autorisée ; exécuter les workflows CI et release du dépôt avec runners et droits nécessaires. Attendu : tous les contrôles obligatoires réussissent avant publication. Risque : différences du runner et de l'index public. |
| Charge sur parc réel | NON EXÉCUTÉ | Parc autorisé indisponible ; procéder par canary puis lots croissants, surveiller délais, erreurs et plafonds. Attendu : aucun dépassement de budget ni rejeu de commande. Risque : saturation et latences propres au parc. |
| Audit sécurité externe | NON EXÉCUTÉ | Auditeur/outillage externe indisponible ; analyser l'archive et ses dépendances système dans l'environnement cible. Attendu : aucun défaut bloquant non résolu. Risque : vulnérabilités hors des contrôles locaux. |
| Migration de données | NON APPLICABLE | Aucun changement du schéma des tâches ni du format persistant. |

Installation et retour arrière : voir `docs/wiki.d/history/releases/RELEASE-1.5.3.md` et
`docs/wiki.d/operations/INSTALLATION.md`. Les artefacts 1.5.2 sont conservés séparément.
