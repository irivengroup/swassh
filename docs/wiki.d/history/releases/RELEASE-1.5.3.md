# SWASSH 1.5.3 — diagnostics et contrôle local

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / releases / SWASSH 1.5.3 — diagnostics et contrôle local

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Limites et sécurité](#limites-et-sécurité)
- [Impact, installation et retour arrière](#impact-installation-et-retour-arrière)



Cette version ajoute `--check` à run, push, pull et à la création de tâches
schedule. Elle conserve les sorties affichées par défaut et `--hide-output`.

```sh
swassh run 'uname -r' -i hosts.txt --check
swassh run 'uname -r' -i hosts.txt -k ~/.ssh/id_ed25519 --check --format json
```

Le contrôle lit l'inventaire, vérifie les chemins et métadonnées des clés
explicitement fournies, la présence des exécutables, la lisibilité du fichier
known_hosts et les répertoires concernés. Les transferts vérifient aussi le
type de source, le plafond de taille et la forme de destination. Il ne lit pas
le contenu des clés privées, ne lance aucun processus SSH, ne réserve aucun
budget, ne crée ni tâche, ni répertoire, ni rapport. Avec `--output`, il examine
la destination prévue mais écrit le diagnostic sur stdout. Formats : text,
json et csv. Code de sortie : 0 sans erreur locale détectée, 2 sinon.
`--check` et `--plan-only` sont exclusifs ; le second conserve son rôle de
calcul de ressources. Une création schedule conserve ses arguments requis,
dont `--at` ; le contrôle ne s'applique pas aux commandes de gestion des tâches.

Avant une exécution normale ou l'enregistrement d'une tâche, les clés explicites
absentes, vides, non régulières, illisibles ou trop permissives sous POSIX sont
refusées avant le canary. Le transport et le worker revérifient ces prérequis.
Les autres observations détaillées restent propres au mode `--check`.

Les erreurs SSH donnent des indications distinctes pour une clé serveur
inconnue ou modifiée, un refus d'authentification, un format de clé invalide,
des permissions incorrectes et un agent refusant de signer. Elles conservent
les statuts existants et n'entraînent aucune nouvelle tentative automatique.
Les messages contrôlés n'exposent ni chemins privés ni diagnostics bruts.
Une sortie distante contenant ces termes après authentification reste une
sortie distante et ne devient pas une erreur d'authentification.

## Limites et sécurité

Le contrôle est une observation locale, pas une connexion de validation.
La lisibilité de known_hosts ne prouve pas qu'il contient la bonne empreinte.
La présence d'un exécutable ne prouve ni sa version ni sa compatibilité.
Les clés chiffrées, leur format et les identités chargées dans l'agent ne sont
pas sondés. L'absence d'agent confirmé reste un avertissement : une clé non
chiffrée peut fonctionner sans agent. Le diagnostic ne propose pas de désactiver
la vérification des clés serveur ou d'activer les mots de passe interactifs.

Les descendants des sources de répertoire ne sont pas parcourus. Les droits
de destination sont estimés sans écriture de test ; ACL, quotas et changements
concurrents peuvent encore faire échouer l'exécution. Les vérifications et
protections des adaptateurs restent nécessaires lors de l'opération réelle.
La planification peut rencontrer ultérieurement une clé supprimée ou un agent
indisponible dans l'environnement du worker.

## Impact, installation et retour arrière

| Domaine | Impact |
| --- | --- |
| CLI et bibliothèque | Option additive ; rejet plus précoce des clés explicites inutilisables |
| Rapports | Statuts inchangés ; descriptions d'erreur plus précises |
| Planification | Aucun changement de schéma ni migration |
| Sécurité | Métadonnées seulement, messages contrôlés, aucun affaiblissement SSH |
| Performance | Contrôles locaux bornés par le nombre de clés fournies ; aucun aller-retour réseau supplémentaire |

Installer le wheel livré avec `python -m pip install --upgrade --no-deps
dist/swassh-1.5.3-py3-none-any.whl`. La publication publique n'est pas effectuée.
Pour revenir à 1.5.2, réinstaller son wheel conservé ; retirer `--check` des
scripts concernés. Aucune migration de données n'est nécessaire.
La qualification réellement exécutée et les plateformes restantes figurent
dans [VALIDATION.md](../../../../VALIDATION.md).
