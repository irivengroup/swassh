# Qualification SWASSH 1.6.0

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.6.0

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Limites de qualification](#limites-de-qualification)



Périmètre : entrée standard bornée, sortie progressive isolée, profils par hôte,
encodage texte, authentification par fournisseur de mot de passe et GSSAPI.
Les preuves history-* concernent uniquement les livraisons antérieures.

| Contrôle | Statut | Résultat observé |
| --- | --- | --- |
| Windows Python 3.14, suite et contrôles statiques | EXÉCUTÉ | 365 tests, 61 ignorés, zéro échec ; 178.612 s |
| Linux Python 3.12, suite de couverture | EXÉCUTÉ | 364 tests, 24 ignorés, zéro échec ; 148.667 s |
| Couverture de lignes | EXÉCUTÉ | 91.70 %, seuil existant 90 % conservé |
| SSH natif Linux | EXÉCUTÉ | 13 tests, zéro exclusion, zéro échec |
| Mot de passe/SFTP et Kerberos réels Linux | EXÉCUTÉ | 2 tests, zéro exclusion, zéro échec ; répétés via le banc autonome intégré à la CI |
| Porte de qualification Linux/rsync | EXÉCUTÉ | Code de sortie 0 dans environnement isolé |
| 50 000 hôtes simulés | EXÉCUTÉ | 70.70 s, 14 travailleurs maximum, 11413309 octets Python maximum dans le parent |

Le scénario comparable 1.5.3 mesurait 104,80 s, 14 travailleurs et 11 408 537
octets Python. Ces mesures ponctuelles ne démontrent pas le débit d’un parc SSH
réel et ne mesurent pas la RSS cumulée des processus. Les nouvelles allocations
facultatives sont prises en compte dans le budget d’admission.

Les tests incluent les fragments multioctets, l’entrée binaire, la séparation
des identités du bastion, le SHA-256 des entrées planifiées, les codecs invalides,
les profils dupliqués, les fichiers spéciaux, la saturation du flux, les sorties
avant fin de commande et l’arrêt d’un consommateur bloqué. Les tests historiques
de rendu, canary, planification, concurrence partagée et transferts sont conservés.
Les exclusions proviennent des plateformes/outils disponibles ; les portes
natives ci-dessus s’exécutent séparément sans autoriser d’exclusion.

Un test de non-régression a reproduit un mot de passe refusé classé à tort
comme panne du fournisseur ; il réussit après correction.

Les premières préparations du banc Kerberos ont échoué (paquets, option serveur,
qualification DNS du nom localhost). Les causes ont été corrigées dans le banc
sans modifier la politique d’authentification du produit. Les résultats courants
ci-dessus sont ceux des exécutions corrigées.

Les installations exactes wheel/sdist sont décrites dans les fichiers
validation/installation-review-windows.json et installation-review-linux.json,
ajoutés après construction. Ils associent empreintes, environnements neufs,
installation hors ligne sans dépendances et codes de sortie. Le justificatif
dist/release-verification-1.6.0.json livré à côté du ZIP contrôle manifeste,
propreté et reproductibilité. Les journaux bruts privés sont exclus du ZIP.

## Limites de qualification

**Qualification de toutes les plateformes : NON TERMINÉE.** Aucun engagement
d’absence totale de défaut n’est formulé. La couverture de lignes ne représente
ni toutes les branches ni tous les processus enfants.

| Contrôle | Statut | Raison, procédure, prérequis et risque restant |
| --- | --- | --- |
| macOS, Solaris, AIX, autres runtimes | NON EXÉCUTÉ | Machines indisponibles ; sur chaque plateforme équipée lancer python scripts/verify.py, scripts/platform_gate.py et scripts/native_network_gate.py. Attendu : zéro échec applicable. Risque : particularités natives non éprouvées. |
| Mot de passe/GSSAPI natifs Windows et autres OS | NON EXÉCUTÉ | Serveur/domaine et clients compatibles non mobilisés ; configurer un fournisseur ou ticket de test puis exécuter run et push/pull avec canary. Attendu : succès explicite et refus des identifiants invalides. Risque : capacités propres au client et contexte du service. |
| CI distante/publication | NON EXÉCUTÉ | Runner distant et publication non mobilisés ; exécuter les workflows avec leurs prérequis avant publication. Attendu : toutes les portes réussissent. Risque : différences de runner/index public. |
| Charge réelle et audit sécurité externe | NON EXÉCUTÉ | Parc autorisé et auditeur indisponibles ; déployer par canary et lots croissants, mesurer ressources/erreurs, auditer les clients système. Attendu : budgets respectés, aucun rejeu ambigu ni défaut bloquant. Risque : saturation réseau et vulnérabilités externes. |

Les options persistées évoluent sans changement du schéma SQLite. Les anciens
jobs restent lisibles ; finir/annuler les nouveaux jobs avant rétrogradation.
Installation, exploitation et retour arrière : docs/wiki.d/history/releases/RELEASE-1.6.0.md et
docs/wiki.d/operations/INSTALLATION.md. Les artefacts 1.5.3 restent conservés séparément.
