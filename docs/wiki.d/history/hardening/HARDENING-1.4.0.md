# Durcissement et améliorations — SWASSH 1.4.0

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / hardening / Durcissement et améliorations — SWASSH 1.4.0

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Contrats et architecture](#contrats-et-architecture)
- [Budget partagé](#budget-partagé)
- [Cycle de vie des processus](#cycle-de-vie-des-processus)
- [Filesystem local](#filesystem-local)
- [Prévisualisation readonly](#prévisualisation-readonly)
- [Vérification de fichier](#vérification-de-fichier)
- [Admission adaptative et métriques](#admission-adaptative-et-métriques)
- [Références des primitives](#références-des-primitives)



## Contrats et architecture

La syntaxe `swassh run 'commande ou script avec options' -i hosts.txt`, la
barrière canary par défaut de 1 serveur et l'architecture DDD sont conservées.
Les ports optionnels d'admission d'une invocation et de progression sont injectés
par bootstrap. Le cœur application reste testable sans SQLite ni processus.
Les adaptateurs système appliquent les nouvelles protections automatiquement.

Les rapports finaux gardent leur schéma JSON version 1 et leurs colonnes CSV.
Un transfert preview ou vérifié est identifié dans le descripteur de commande
par `:preview` ou `:verify-sha256` et dans les événements d'audit. Les receipts
existants conservent leur forme. Le texte de succès décrit explicitement le mode.

## Budget partagé

Toutes les invocations natives d'un même compte sur le bastion local utilisent
le même coordinateur, y compris avec des sauts SSH différents. Les identités
distantes, sauts et inventaires ne créent pas de pools séparés. Le
répertoire par défaut est `~/.swassh/budgets/<empreinte-locale>` ; `--budget-dir`
change la racine. Toutes les CLI et tous les workers schedule doivent utiliser
la même racine et la même politique. Le répertoire doit être sur un filesystem
local supportant SQLite et les verrous OS ; ce coordinateur n'est pas distribué.

| Option | Défaut | Signification |
| --- | --- | --- |
| --bastion-concurrency | 32 | Connexions locales simultanées, tous clients cumulés |
| --bastion-connect-rate | 20 | Départs par seconde, rythme commun sans rafale au retour d'inactivité |
| --bastion-memory-mib | 512 | Somme des budgets d'invocation réservés |
| --bastion-bandwidth-kib | 10240 | Somme des limites de débit allouées aux transferts |
| --budget-dir | ~/.swassh/budgets | Racine commune du compte |

Un ProxyJump réserve deux connexions et deux unités de pacing. Les probes,
retries pré-authentification et transferts utilisent les mêmes slots. Un client
réserve son débit avant d'être lancé ; sa limite native rsync/SFTP demeure active.
Une invocation réserve `--memory-budget-mib + 64 MiB` avant snapshot, hash ou
création du processus de rapport. La CLI réserve avant de charger son inventaire. La marge couvre le parent et le reporter.
Le plan natif ajoute 24 MiB par guardian ; le plan simulé à transport injecté
ne provisionne pas de processus inexistant. Ces valeurs sont des estimations,
pas des quotas RSS ou des mesures de CPU/réseau. Appliquer également les quotas
OS et disque prévus dans OPERATIONS.md pour des plafonds matériels stricts.

Deux files FIFO séparées évitent qu'une attente mémoire bloque les clients des
invocations déjà admises. Le premier ticket d'une file peut attendre sa capacité ;
les suivants ne le dépassent pas. La file est bornée à 1 024 leases, la base à
8 MiB et les scans de locks à 2 048 entrées. Un conflit de politique avec une
invocation vivante échoue. La politique peut être changée à froid lorsque toutes
les leases précédentes sont récupérables, sans effacer la base à la main.

Les leases reposent sur des verrous OS et des UUID, pas sur un PID seul ou un
heartbeat expiré. Une lease perdue ne contient aucune instruction de rejeu.
La mémoire d'une CLI morte reste chargée tant qu'un guardian ou reporter lié
possède encore sa lease. La récupération est faite lors des admissions suivantes.
L'attente d'une connexion compte dans le délai du client ; l'attente mémoire
précédant l'invocation reste interruptible et peut durer jusqu'à la fin des flottes
précédentes. Les budgets doivent être dimensionnés pour admettre une invocation.

Les journaux gardent leur protection exclusive par fichier et leur rotation
100 MiB + trois gzip. Pour plusieurs CLI actives, utiliser des `--log-file`
distincts ; partager le budget ne rend pas un même fichier d'audit multiwriter.
Les jobs schedule disposent déjà d'un audit distinct par job.

## Cycle de vie des processus

Un guardian Python standard, principalement en attente I/O, possède la lease de
chaque client natif. Sur POSIX, un pipe anonyme détecte la disparition du parent
sans ambiguïté de PID. Le guardian termine le groupe natif, y compris les enfants
ayant survécu au leader, avant de rendre sa capacité. Le reporter a son propre
watcher de parent et ne survit pas indéfiniment à la mort de la CLI.

Sous Windows, le guardian rejoint un Job Object avec KILL_ON_JOB_CLOSE avant de
créer le client. L'héritage de job élimine la fenêtre création/affectation ; aucune
permission de breakaway n'est activée. Une incompatibilité de jobs imbriqués
échoue avant le client. Le parent est surveillé par handle et identité de création.
La terminaison du job précède la libération de capacité. Les contrats Win32 sont
testés hors Windows et sur le Windows de développement pour la livraison 1.4.1 ;
les résultats et les limites exactes figurent dans ../VALIDATION.md. Les autres
environnements Windows cibles doivent exécuter ces tests avant qualification.

Un processus POSIX forcé à quitter son groupe, ou un guardian lui-même tué par
SIGKILL, nécessite la supervision OS pour une garantie absolue d'arbre. Les
clients OpenSSH/rsync/SFTP ordinaires sont couverts. Le nettoyage local ne prouve
pas l'arrêt d'une commande déjà lancée sur le serveur ; inspecter son état avant
toute reprise explicite. Aucune opération mutante ambiguë n'est rejouée.

## Filesystem local

Les nouveaux répertoires sensibles sont créés composant par composant avec
dir_fd. Chaque composant est ouvert sans suivi de lien lorsque disponible, puis
comparé par inode/device et validé par fstat. Les alias système POSIX appartenant
à root/au compte sont résolus de manière bornée et leurs cibles revalidées.
Le dernier composant privé ne peut être un alias. Les dossiers partagés non
sticky root sont refusés. Les exports créent leur temporaire avec O_EXCL et
publient relativement au descripteur épinglé, même si un parent est ensuite déplacé.

Windows refuse les reparse points et épingle chaque parent avec un handle sans
FILE_SHARE_DELETE. Les fichiers sensibles sont ouverts avec OPEN_REPARSE_POINT.
Les dossiers privés et les temporaires de rapport reçoivent une DACL protégée
limitée au SID courant et SYSTEM, après contrôle du propriétaire. Les stores
SQLite et les clients natifs continuent d'employer des chemins dans ces dossiers
privés ; aucune VFS SQLite personnalisée n'est ajoutée.

Root, SYSTEM et le compte courant restent des acteurs de confiance. Les contrôles
ne constituent pas une isolation contre un autre programme hostile du même compte.
Les quotas disques et les garanties de fsync du filesystem restent nécessaires.

## Prévisualisation readonly

```sh
swassh push --source ./release/ --destination /srv/app/ -i hosts.txt --dry-run
swassh pull --source /srv/app/ --destination ./collecte/ -i hosts.txt --dry-run
```

Le preview nécessite rsync 3.5.0+ aux deux extrémités, sans repli SFTP. Il reprend
les filtres de sécurité et le profil de synchronisation, ajoute le dry-run natif,
retire uniquement les affichages verbeux/progression et produit une itemisation
fixe sans noms de fichiers. Le parseur compte en streaming, même au-delà du plafond
de capture stdout. Une ligne inconnue ou trop longue fait échouer le preview,
sans présenter un compte partiel comme fiable. Les dossiers et fichiers des deux
côtés ne sont pas modifiés par la synchronisation. Audit, spool et snapshots
locaux restent possibles. Les lectures peuvent changer les atimes du filesystem.

Un pull preview exige le dossier local racine et les dossiers par identité déjà
présents ; il ne les crée pas. Les paramètres de sécurité/canary sont conservés.
Un résultat preview ne promet pas que l'état restera inchangé avant une exécution
future. Les compteurs portent sur les entrées rsync, y compris les métadonnées
de répertoire, liens et suppressions ; ils ne mesurent pas le volume réseau.

## Vérification de fichier

```sh
swassh push --source ./release.tar --destination /srv/release.tar -i hosts.txt --verify-sha256
swassh pull --source /srv/release.tar --destination ./collecte -i hosts.txt --verify-sha256
```

Le mode est opt-in, limité à un fichier et incompatible avec --dry-run. Les
répertoires sont refusés avant transfert. Le snapshot push est partagé par la
flotte, hashé par blocs bornés et rendu privé (0600). Le hash hashlib libère le
GIL pour ces gros blocs ; la lecture est déportée hors de la boucle asyncio.

Le serveur doit exposer un shell POSIX et au moins un outil natif parmi
sha256sum, shasum, openssl dgst ou digest Solaris. Sa présence et sa réponse sont
contrôlées, sans Python distant. Un serveur Windows à shell PowerShell seul
échoue explicitement avant données ; le transfert SFTP normal reste disponible.
Les chemins distants doivent appartenir à un espace fiable du compte SSH, sans
acteur concurrent pouvant remplacer la copie temporaire ou ses parents.

Push écrit d'abord un nom temporaire aléatoire dans le même répertoire distant,
vérifie son empreinte, puis recontrôle celle-ci dans la commande qui publie par
mv. Le fichier vérifié reste 0600. Une réponse de publication perdue est ambiguë,
remontée sans retry et avec le temporaire à inspecter. Un mismatch garde la
cible finale précédente et laisse le temporaire distant signalé dans le receipt.
Aucune tentative automatique de nettoyage distant ne masque son état.

Pull lit l'empreinte distante avant et après le transfert, compare les deux avec
le staging local, puis publie atomiquement. Un changement de source, un outil
non disponible, une sortie tronquée ou un mismatch interdit la publication.
Ces contrôles établissent l'intégrité du contenu dans un espace distant fiable ;
ils n'authentifient pas un serveur hostile qui mentirait sur les données/hashes.
Les opérations de contrôle utilisent les mêmes budgets de connexions et délais.

## Admission adaptative et métriques

```sh
swassh run './deploy.sh --release 42' -i hosts.txt --canary 5 --adaptive --progress
```

Sans --adaptive, les plafonds fixes restent actifs. Avec cette option, chaque
résultat TIMEOUT ou UNREACHABLE divise la limite d'admission par deux, minimum 1,
et réduit le rythme proportionnellement. Après au moins deux succès consécutifs
par slot, la limite remonte d'une unité, sans dépasser le plan ni les plafonds
partagés. `--circuit-threshold` vaut 5 : autant de défaillances réseau consécutives
ouvrent le circuit jusqu'à la fin de cette flotte. Les workers déjà lancés terminent
leur opération ; les nouvelles cibles deviennent skipped avec zéro tentative et
une raison distincte du canary. Aucune sortie stderr distante ne décide un retry.

--progress affiche une seule ligne actualisée sur un terminal, sinon une ligne
par intervalle sur stderr ; --progress-interval vaut 2 s et ne peut être < 1 s.
stdout reste exclusivement le rapport final. Les compteurs n'accumulent pas
les identités des serveurs. L'audit reçoit run_metrics périodiques et finaux :
actifs, terminés, skipped, plafond/admission effective, circuit, réductions,
défaillances réseau, temps d'attente et durées natives. Les actifs correspondent
aux workers admis, y compris ceux attendant le coordinateur. Les sommes de durées
natives sont des temps clients, pas des mesures CPU ; les métriques absentes lors
d'une mort forcée ne sont pas inventées. JSON/CSV finaux conservent leur schéma.

## Références des primitives

- [Python : dir_fd et opérations relatives](https://docs.python.org/3.11/library/os.html)
- [Rsync : dry-run et itemisation](https://download.samba.org/pub/rsync/rsync.1.html)
- [Microsoft : Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Microsoft : jobs imbriqués](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs)
- [Microsoft : CreateFile et partage/suivi de liens](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
