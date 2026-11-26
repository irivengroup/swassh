# SWASSH 1.7.0 — sessions réutilisables et terminal distant

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / releases / SWASSH 1.7.0 — sessions réutilisables et terminal distant

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Session SSH réutilisable](#session-ssh-réutilisable)
- [PTY pour une commande](#pty-pour-une-commande)
- [Shell interactif](#shell-interactif)
- [Impact, menaces et retour arrière](#impact-menaces-et-retour-arrière)



Les nouveaux modes sont explicites. `run` sans `--pty`, push/pull, schedule,
canary, authentifications, profils et rapports conservent leurs valeurs par
défaut. La version 1.6.0 reste conservée comme point de retour arrière.

## Session SSH réutilisable

Créer un fichier UTF-8 `commands.json` :

```json
["uname -r", "df -P", "uptime"]
```

```bash
swassh session -H admin@srv01 --commands-file commands.json --session-lifetime 300
```

Une seule cible est autorisée. Le document est limité à 1 MiB et à 1 000
commandes, toutes validées avant connexion. Les commandes s’exécutent dans
l’ordre ; la CLI s’arrête au premier échec. Chaque commande produit le rapport
habituel dans le format choisi. JSON produit des documents successifs, pas un
tableau JSON global ; CSV répète les en-têtes. `--output` et `--spool-dir` sont
refusés pour ce mode. Utiliser les API de rapport ou rediriger stdout selon le
format voulu. `--hide-output` conserve son sens pour les rapports.

API Python :

```python
import asyncio
from swassh import Options, Session

async def main():
    async with Session("admin@srv01", Options(), lifetime=300) as session:
        for command in ("uname -r", "df -P"):
            report = await session.run(command)
            print(report.to_text())
            if not report.ok:
                break

asyncio.run(main())
```

Chaque commande utilise un nouveau canal sur la même connexion authentifiée.
Le répertoire courant, les variables et l’état du shell ne persistent pas
entre commandes. Pour une commande composée, employer `run 'cd ... && ...'` ;
pour un shell avec état, utiliser le mode interactif ci-dessous.

Le contexte doit être entré et quitté par la même tâche asyncio. Les appels
run sont sérialisés. Les contextes de session imbriqués ou hérités sont refusés
pour éviter de sous-réserver la mémoire. Une session fermée ne peut pas être
rouverte. Les tâches indépendantes doivent conserver des options et budgets
compatibles ; les limites globales s’appliquent toujours.

Durée maximale du maître : 300 secondes par défaut, de 1 à 3 600 secondes,
depuis le démarrage natif après admission, authentification comprise. Le gardien
applique aussi cette borne indépendamment de la boucle Python appelante : un
affichage local bloqué ne peut pas maintenir indéfiniment la connexion.
L’expiration coupe également les canaux actifs. `--command-timeout` borne
séparément chaque commande. La connexion et son éventuel saut occupent leurs
réservations partagées jusqu’à l’arrêt du maître.
Le calcul mémoire réserve aussi 32 MiB pour le maître (40 MiB avec saut), en
plus du canal et des autres options. Une combinaison insuffisamment provisionnée
est refusée ; par exemple, augmenter `--memory-budget-mib` pour combiner session
et sortie progressive si le budget par défaut ne suffit pas.
Le socket reste dans un dossier
temporaire privé, sans nom d’hôte ni secret. ControlPersist est désactivé :
aucun maître détaché entre invocations n’est proposé.

Une connexion déjà authentifiée ne se réauthentifie pas à chaque canal : une
rotation du mot de passe ou l’expiration du ticket ne garantit pas sa fermeture
immédiate côté serveur. Choisir une durée compatible avec votre politique ;
conserver run sans session lorsque chaque opération doit se réauthentifier.

Une perte du socket/maître ne déclenche jamais une reconnexion transparente.
Un proxy de refus empêche le repli OpenSSH vers TCP. Aucun canal n’est rejoué
automatiquement. Une erreur d’E/S, un état distant incertain, un timeout ou une
annulation ferme le maître et interdit sa réutilisation. Le retour utilisateur
d’une commande non nulle n’invalide pas à lui seul la connexion.

**Compatibilité : ce mode nécessite OpenSSH avec multiplexage sur POSIX.**
Windows est refusé explicitement pour les sessions réutilisables ; run et les
autres fonctionnalités existantes ne sont pas désactivés. Les essais natifs de
cette livraison sont réalisés sous Linux ; macOS/Solaris/AIX demandent leur
qualification propre. `--check` expose cette restriction sous Windows.

## PTY pour une commande

```bash
swassh run 'tty; uname -r' -H srv01 --pty
```

L’option alloue un pseudo-terminal distant et conserve le rapport normal.
Elle peut être enregistrée avec schedule. Elle ne rend pas `run` interactif :
l’entrée reste vide ou provient de `--stdin-file`. Les transferts refusent PTY.
Le PTY fusionne stdout et stderr distants ; des notices locales OpenSSH peuvent
rester dans stderr. Les fins de ligne, l’écho et les séquences terminales peuvent
différer du mode sans PTY. Un fichier envoyé à un terminal subit sa discipline
de ligne et n’est plus un transfert binaire transparent. Une commande attendant
une saisie reste soumise au délai configuré.

## Shell interactif

```bash
swassh shell -H admin@srv01 --command-timeout 1800
```

Ce mode exige exactement une cible et un vrai terminal local en entrée et sortie.
Il alloue un PTY distant et transmet les frappes sans diffusion à une flotte.
Quitter avec `exit` ou la fin d’entrée reconnue par le shell distant. Le raccourci
OpenSSH `~.` n’est pas activé. Les frappes et sorties ne sont pas enregistrées
dans les rapports ou l’audit ; seules les métadonnées début/fin sont auditées.
Le terminal affiche directement les séquences distantes, contrairement au
rapport assaini du mode run : utiliser ce mode uniquement avec une cible de
confiance. Les outils distants et l’enregistreur de terminal de l’utilisateur
peuvent eux-mêmes conserver des données sensibles.

Pas de JSON/CSV, de sortie masquée, de progression ni de fichier de rapport pour
ce mode. Le délai maximal est celui de `--command-timeout` (60 secondes par
défaut). Les attributs du terminal sont restaurés après sortie, exception ou
annulation traitable. Sous POSIX, les redimensionnements sont relayés au client
SSH puis au serveur. Sous Windows, les modes de console sont sauvegardés et
restaurés ; l’interaction native doit être qualifiée sur le client installé.
Un SIGKILL du programme, une coupure d’alimentation ou un terminal détruit ne
permettent pas d’exécuter un nettoyage Python. L’arrêt local ne garantit jamais
l’arrêt de tous les travaux distants déjà lancés.

## Impact, menaces et retour arrière

| Domaine | Protection | Limite |
| --- | --- | --- |
| Contrats CLI | Nouvelles sous-commandes et option facultative | Pas de conversion implicite de run en shell |
| Concurrence | Maître gardé, réservation tenue, canaux séquentiels | Pas de pool persistant de milliers de connexions |
| Secrets | Configuration privée, méthodes d’authentification inchangées | Client natif et répertoires administrés de confiance |
| Reconnexion/rejeu | Repli TCP refusé, aucun retry de canal | Les effets distants après interruption peuvent être inconnus |
| Ressources | Durée, diagnostics, entrée et captures bornés | Le shell direct n’est pas un stockage de sortie |
| Terminal | Restauration et resize relayé | Séquences terminales de la cible assumées en mode interactif |
| Planification | PTY sérialisé, défaut false pour les anciennes tâches | Aucun shell interactif planifié |
| Publication | Tests, installation et reconstruction contrôlés | Voir les validations non exécutées dans VALIDATION.md |

Avant rétrogradation, fermer les sessions et terminer/annuler les nouvelles
tâches ; les versions anciennes ne reconnaissent pas le champ d’option PTY.
Sauvegarder la base de tâches de manière cohérente, puis réinstaller le wheel
1.6.0 conservé. Aucun changement de schéma SQLite n’est nécessaire. Les commandes
déjà exécutées à distance ne sont pas annulées par une rétrogradation.
