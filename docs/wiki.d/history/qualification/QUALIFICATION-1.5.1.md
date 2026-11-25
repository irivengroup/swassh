# Qualification SWASSH 1.5.1

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.5.1

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Limites et contrôles manquants](#limites-et-contrôles-manquants)
- [Livraison, exploitation et retour arrière](#livraison-exploitation-et-retour-arrière)



Campagne du 22 octobre 2026. Les critères locaux de stabilité définis dans
`docs/wiki.d/history/releases/RELEASE-1.5.1.md` sont satisfaits sur la matrice ci-dessous. La promotion
1.5.1 n'est pas une certification universelle ni une promesse d'absence de bugs.
**Qualification de l'ensemble des plateformes annoncées : NON TERMINÉE.**

| Contrôle | Statut | Résultat |
| --- | --- | --- |
| Windows Python 3.11.9 | EXÉCUTÉ | 327 tests, zéro échec, 54 ignorés ; 237.145 s |
| Windows Python 3.12.10 | EXÉCUTÉ | 327 tests, zéro échec, 54 ignorés ; 258.845 s |
| Windows Python 3.13.16 | EXÉCUTÉ | 327 tests, zéro échec, 54 ignorés ; 206.367 s |
| Windows Python 3.14.7 | EXÉCUTÉ | 327 tests, zéro échec, 54 ignorés ; 198.243 s |
| Linux Python 3.12.3 | EXÉCUTÉ | 327 tests, zéro échec, 6 ignorés ; 239.95 s |
| Couverture Linux | EXÉCUTÉ | 91.94 %, seuil 90 % inchangé ; 326 tests hors benchmark |
| Réseau natif | EXÉCUTÉ | 11 tests, zéro ignoré et zéro échec : SSH, ProxyJump, rsync, SFTP, SHA-256 et suppressions prévisualisées |
| Campagne de planification | EXÉCUTÉ | 50 jobs et 50 invocations manuelles concurrentes ; 45 succès, cinq échecs de canary attendus, 95 appels planifiés exacts, rapports vérifiés et aucun rejeu après deux passages supplémentaires |
| Régressions de planification | EXÉCUTÉ | Trois tests échouent sur la rc2 intacte puis réussissent sur le code corrigé |
| Pannes et confidentialité | EXÉCUTÉ | Échec avant/après commit, rollback atomique de l'outbox, diagnostics autorisés sans messages secrets, interruption, reprise sans rejeu, ancien adapter compatible |
| Banc d'installation | EXÉCUTÉ | Preuves conservées après erreur, nettoyage après succès, réveil anticipé et dérive d'horloge contrôlés |
| Statique et architecture | EXÉCUTÉ | 83 modules, syntaxe et règles AST, dépendances standard et frontières DDD |

Les tests ignorés restent exclus des réussites : différences Windows/POSIX,
outils natifs indisponibles et base de fuseaux IANA absente sous Windows.
Les tests de réseau dédiés ne comportent aucun ignoré. Les preuves historiques
dans `validation/history-*` ne sont pas utilisées comme résultats actuels.

## Limites et contrôles manquants

| Contrôle | Statut | Raison, procédure, prérequis et risque restant |
| --- | --- | --- |
| Incident historique isolé 1.5.0 | ÉCHOUÉ | Échec historique conservé, analyse causale impossible avec les preuves initiales perdues. La cause n'est pas déclarée corrigée. En cas de récidive, conserver le répertoire imprimé, la base et les journaux privés, reproduire puis ajouter une régression. Risque résiduel non quantifiable ; promotion fondée sur les critères de cette campagne. |
| macOS, Solaris, AIX natifs | NON EXÉCUTÉ | Machines indisponibles. Avec Python >=3.11 et OpenSSH approprié, exécuter verify.py, platform_gate.py avec l'OS attendu, validate_installation.py et les scénarios de service de docs/wiki.d/usage/SCHEDULING.md. Attendu zéro échec applicable. Compatibilité du code conservée, comportement noyau et superviseur non certifié ici. |
| Autres Python Linux | NON EXÉCUTÉ | Seul Python 3.12.3 Linux disponible dans le laboratoire. Exécuter la matrice CI Linux 3.11/3.13/3.14 ; attendu zéro échec. Risque spécifique au runtime. |
| CI distante et publication | NON EXÉCUTÉ | Aucun dépôt/runner distant ni index publié dans cette tâche. Exécuter CI puis release avec accès autorisés ; attendre les contrôles et l'installation depuis l'index. Version locale stable ne signifie pas publiée sur PyPI. |
| Charge sur parc réel | NON EXÉCUTÉ | Parc et fenêtre de test indisponibles. Canary puis montée bornée avec métriques et critères convenus ; attendre plafonds respectés et absence de fuite. Débit et dimensionnement réels restent à mesurer. |
| Audit externe des outils natifs | NON EXÉCUTÉ | Pas de scanner externe exécuté. Inventorier et auditer Python/OpenSSH/rsync selon les avis éditeurs avant déploiement. Les contrôles AST et tests locaux ne remplacent pas cet audit. |

La couverture utilise `trace` : lignes mesurées, branches non mesurées et
processus enfants non tracés directement. Les stores ont leurs tests directs.
Le benchmark de 50 000 hôtes vérifie les résultats, les workers bornés et la
mémoire Python principale sous 96 Mio ; il ne mesure pas le débit d'un parc SSH
ni toute la mémoire native. Les mesures figurent dans `validation/stability.json`.

## Livraison, exploitation et retour arrière

Les preuves d'installation des distributions finales figurent dans
`validation/installation-review-*.json`, ajoutées après construction. La preuve
externe de livraison contient leurs SHA-256 et la reconstruction à l'identique
avec le même runtime. Le manifeste du ZIP couvre tous ses fichiers. Les logs
bruts, clés de laboratoire, environnements et caches sont exclus.

Vérifier `python -m swassh --version` et `swassh --version` dans l'environnement
applicatif. Arrêter les invocations et le worker avant mise à niveau ou rollback.
Pour revenir à rc2, réinstaller sa wheel conservée avec le même Python ; garder
les bases et rapports, aucune migration n'est requise. Ne pas rejouer un claim
interrompu avant vérification de son effet distant. Les commandes pip et les
sauvegardes du PATH sont documentées dans `docs/wiki.d/operations/INSTALLATION.md`.
