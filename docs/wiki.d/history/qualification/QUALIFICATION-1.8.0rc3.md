# Qualification SWASSH 1.8.0rc3

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.8.0rc3

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Périmètre SDK](#périmètre-sdk)
- [Limites et procédures restantes](#limites-et-procédures-restantes)



Version candidate : clients Python synchrones/asynchrones, flux bornés, erreurs typées et isolation des réservations. Bibliothèque standard Python uniquement.
**Qualification matérielle multiconstructeur : NON TERMINÉE.** Le mécanisme de reconnexion est implémenté et testé avec des équipements simulés.
Les preuves history-* sont historiques et ne constituent pas des tests actuels.

| Contrôle | Statut | Résultat |
| --- | --- | --- |
| Windows Python 3.14 et contrôles statiques | EXÉCUTÉ | 429 tests recensés, 72 ignorés, zéro échec ; 183.772 s |
| Linux Python 3.12 | EXÉCUTÉ | 428 tests recensés, 6 ignorés, zéro échec ; 193.091 s |
| Couverture des lignes | EXÉCUTÉ | 91.14 %, seuil 90 % conservé sans exclusion ajoutée |
| SSH natif et dialogues réseau simulés | EXÉCUTÉ | 22 tests, zéro exclusion ; clients Python natifs, sessions, neuf profils réseau, reconnexion et refus explicites |
| Mot de passe/SFTP et Kerberos | EXÉCUTÉ | 2 tests sans exclusion, également exécutés dans le banc autonome de CI |
| Linux/rsync | EXÉCUTÉ | Porte native, code de sortie 0 |
| Régressions SDK reproduites avant correction | EXÉCUTÉ | Deux tests échouent avant leurs corrections : erreur de fermeture masquée et réservation héritée ; ils réussissent après correction |
| 50 000 hôtes simulés | EXÉCUTÉ | 73.44 s ; 14 travailleurs ; 11400536 octets Python maximum dans le parent |

La simulation de flotte ne mesure pas le débit SSH réel, la RSS cumulée des
processus ni la compatibilité des équipements. La couverture mesure des lignes,
pas toutes les branches ou les processus enfants. Aucun gain de performances
n'est déduit de mesures ponctuelles sur une machine partagée.

Les tests réseau utilisent un vrai client/serveur SSH et un simulateur de CLI.
Ils vérifient les dialogues et le comportement observable du client, jamais
l'application de configurations ou d'images sur un matériel constructeur réel.
La présence d'un profil n'est pas une certification de ses modèles/versions.
Les rapports, transferts, canary, budgets, planification et sorties historiques
sont inclus dans les suites exécutées. Aucune garantie d'absence totale de bug.

Les preuves d'installation des paquets exacts seront ajoutées après construction
dans validation/installation-review-windows.json et installation-review-linux.json.
Le fichier release-verification-1.8.0rc3.json livré à côté du ZIP décrit les
empreintes et les reconstructions identiques avec le même runtime. Ne considérer
ces contrôles comme exécutés qu'en présence de leurs preuves finales.

## Périmètre SDK

Client et AsyncClient partagent le moteur existant, sans dépendance Python tierce.
Les flux exigent un contexte explicite ; fermeture et annulation attendent le
nettoyage. Chaque appel SDK possède sa réservation indépendante. Voir
docs/wiki.d/usage/PYTHON-SDK.md et docs/wiki.d/reference/ACCEPTANCE-SCALE.md.

**NON TERMINÉ :** canaux binaires publics, tunnels, entrée interactive SDK,
ordonnancement durable de dépendances et idempotence déclarative générale.
Aucun benchmark concurrentiel ne démontre une supériorité de performances.

## Limites et procédures restantes

| Contrôle | Statut | Raison, procédure, prérequis, attendu et risque |
| --- | --- | --- |
| Matériels Cisco, Juniper, Aruba, Huawei et Fortinet | NON EXÉCUTÉ | Laboratoire matériel/virtuel constructeur indisponible. Sur chaque modèle/version autorisé, identifier l'équipement, vérifier sauvegarde/restauration, appliquer une modification réversible, injecter erreur et coupure, puis comparer état et rapport. Attendu : aucun succès ambigu ni étape poursuivie après échec. Risques : invites, privilèges, pagination et sémantique propres aux versions. |
| Mise à jour firmware complète avec redémarrage | NON EXÉCUTÉ | Matériel constructeur indisponible ; le mécanisme générique est implémenté et testé sur simulateur. Fournir procédures spécifiques revues, images signées, matériel de test et accès hors bande ; appliquer la procédure network en laboratoire et vérifier le retour du système sans rejeu de l'activation. Attendu : modèle/version/digest vérifiés, version cible constatée, récupération démontrée. Risque restant : interruption ou état distant inconnu ; ne pas déployer automatiquement en production. |
| Clients macOS, Solaris, AIX et autres runtimes | NON EXÉCUTÉ | Machines indisponibles. Exécuter verify.py, coverage.py et portes natives avec leurs dépendances, puis tests de console et d'annulation. Attendu : zéro échec applicable ; risques propres aux clients et terminaux. |
| Dialogue réseau natif Windows | NON EXÉCUTÉ | Aucun serveur réseau réel mobilisé depuis le client Windows. Avec OpenSSH et cible de laboratoire autorisée, exécuter une procédure revue via network, vérifier sorties, refus, délais et descendants. Attendu : mêmes invariants que Linux ; risque restant lié au client Windows et aux équipements. |
| Console interactive Windows | NON EXÉCUTÉ | Console native et cible de test non mobilisées. Tester shell, run --pty, redimensionnement et restauration dans une console OpenSSH autorisée. Attendu : affichage/restauration corrects. Risque : particularités de console. |
| Sessions multiplexées Windows | NON APPLICABLE | Mode déjà refusé explicitement ; le nouveau dialogue réseau ne dépend pas de ControlMaster. |
| CI distante, publication et audit externe | NON EXÉCUTÉ | Runners/index/auditeur non mobilisés. Exécuter la CI complète avant publication, puis audit du paquet et de l'environnement cible. Attendu : tous les contrôles obligatoires réussissent. Risque : différences d'environnement et défauts non détectés. |
| Charge SSH sur parc réel | NON EXÉCUTÉ | Parc autorisé indisponible. Canary puis lots croissants avec CPU/RSS/latences/connexions/erreurs. Attendu : plafonds respectés, aucun rejeu. Risque : saturation réseau ou serveur. |

Installation, contrats, menaces, limitations et retour arrière : docs/wiki.d/usage/NETWORK.md,
docs/wiki.d/operations/INSTALLATION.md et SECURITY.md. L'archive 1.8.0rc2 demeure inchangée. Aucune
publication sur un index et aucune opération sur des équipements réels n'ont eu lieu.
