# Qualification SWASSH 1.5.2

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.5.2

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Limites](#limites)



Cette livraison affiche les sorties par défaut et utilise `--hide-output` pour
la synthèse compacte. Les options des anciennes tâches sont conservées.

| Contrôle | Statut | Résultat |
| --- | --- | --- |
| Suite Windows Python 3.14 | EXÉCUTÉ | 331 tests recensés, 54 ignorés, zéro échec final |
| Couverture Linux Python 3.12 | EXÉCUTÉ | Ran 329 tests in 140.007s, 20 ignorés, 91.87 %, seuil 90 % conservé |
| CLI et présentation après renommage --hide-output | EXÉCUTÉ | 27 tests Windows, cinq ignorés, zéro échec |
| Démarrage concurrent | EXÉCUTÉ | Dix processus indépendants respectent le plafond ; reprise SQLITE_BUSY bornée, autres erreurs conservées |
| Régression affichage | EXÉCUTÉ | Nouveau défaut échoue sur l'ancienne source puis réussit sur la nouvelle ; mode compact conservé explicitement |

Les suites globales portent sur le code final avec `--hide-output`.
Les tests ciblés CLI et présentation ont aussi été exécutés sous Windows/Linux. Les premiers échecs liés aux anciennes attentes d'affichage ont
été corrigés en testant explicitement les deux modes, sans retrait de contrôle.
Des échecs réels de verrou SQLite au démarrage puis à la libération ont conduit
à une reprise limitée aux erreurs SQLITE_BUSY, testée séparément puis dans les
suites globales. Le test de sortie partielle synchronise désormais le démarrage
du processus ; un test séparé conserve la vérification du délai de démarrage.
La couverture Linux porte sur le même code de production, avant cette précision
du banc de test, vérifiée séparément sous Windows/Linux.

Les preuves d'installation finales sont ajoutées dans `validation` après build.
Les fichiers `history-*` et les qualifications 1.5.1 sont des preuves historiques.
Les logs bruts d'installation sont exclus de l'archive.

## Limites

**Qualification de toutes les plateformes : NON TERMINÉE.** Les essais natifs
SSH/rsync de 1.5.1 ne sont pas déclarés réexécutés sur 1.5.2. La suite Linux
courante ignore les outils natifs indisponibles et les tests Windows ; la suite
Windows ignore les scénarios POSIX et les outils absents. La couverture mesure
les lignes, pas les branches ni directement les processus enfants.

La campagne actuelle est limitée à Windows Python 3.14 et Linux Python 3.12.
Les autres OS et le parc réel sont indisponibles ; aucun runner distant ni
scanner externe n’a été mobilisé. Les autres runtimes Windows n’ont pas été
réexécutés dans cette campagne.

NON EXÉCUTÉ sur cette révision : autres versions Python Windows, macOS/Solaris/AIX,
réseau natif complet, charge réelle, audit externe, CI distante et publication.
Pour compléter : sur les machines et runtimes concernés, exécuter `scripts/verify.py`,
`scripts/platform_gate.py`, `scripts/native_network_gate.py` avec les prérequis
SSH/rsync, puis `scripts/validate_installation.py`. Attendu : zéro échec applicable.
Le risque restant concerne les plateformes et outils non rééprouvés. Les essais
sur parc nécessitent un parc autorisé et une montée progressive ; ils ne sont
pas remplacés par le benchmark simulé.

Pour revenir à 1.5.1 : arrêter les invocations et le worker, réinstaller sa wheel
avec le même Python et conserver les bases et rapports. Aucune migration requise.
Les sorties peuvent être rendues compactes sans rollback avec `--hide-output`.
