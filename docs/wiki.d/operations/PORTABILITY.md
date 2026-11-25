# Portabilité — SWASSH 2.0.0rc1

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / operations / Portabilité — SWASSH 2.0.0rc1

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Capacités et prérequis](#capacités-et-prérequis)
- [Extensions de la version 2](#extensions-de-la-version-2)
- [Adaptations du moteur](#adaptations-du-moteur)
- [Fuseaux et planification](#fuseaux-et-planification)
- [Solaris : SMF](#solaris--smf)
- [AIX : SRC](#aix--src)
- [Validation et CI](#validation-et-ci)



Le périmètre reste le client de déploiement massif et de transfert SSH.
Le runtime, le build et les tests utilisent Python standard. Les clients
OpenSSH/rsync/SFTP et les superviseurs sont des composants natifs de l'OS.
Il n'y a ni agent sur les serveurs ni bibliothèque Python tierce.

## Capacités et prérequis

Cette matrice décrit les capacités du client SWASSH local. Le shell et les outils
installés sur les serveurs distants déterminent les commandes/scripts exécutables.
Une commande Linux n'est pas rendue portable vers AIX/Windows par SSH.

| Client | run / schedule | Push/pull de fichier | Synchronisation d'arbre rsync | Supervision générée |
| --- | --- | --- | --- | --- |
| Linux | Oui | rsync, repli SFTP | Oui, avec rsync compatible | systemd |
| Solaris | Oui, Python/OpenSSH modernes | rsync, repli SFTP | Oui, avec rsync compatible | SMF : XML + méthode |
| AIX | Oui, Python/OpenSSH modernes | rsync, repli SFTP | Oui, avec rsync compatible | SRC : lanceur foreground |
| macOS | Oui | rsync, repli SFTP | Oui, avec rsync compatible | launchd |
| Windows natif | Oui, boucle Proactor | SFTP | Pas dans le backend natif actuel ; utiliser WSL pour le profil complet | Task Scheduler |
| Windows avec WSL | Comme Linux dans WSL | rsync, repli SFTP | Oui, outils et chemins Linux dans WSL | systemd si activé dans WSL, sinon worker supervisé |

Prévoir CPython 3.11+ 64 bits, avec sqlite3, multiprocessing, asyncio, gzip,
venv/ensurepip pour les probes d'installation, et les modules POSIX du build
pour les Unix. La matrice CI généraliste couvre Python 3.11–3.14 ; les versions
exactes de Solaris/AIX et leurs packages Python doivent être qualifiés sur site.
La compatibilité ne couvre pas le Python ancien fourni par défaut avec certains
OS historiques. Un build CPython privé moderne peut être installé à côté du
Python système, sans le remplacer.

OpenSSH doit accepter la configuration stricte produite, notamment ProxyJump,
les diagnostics -E et les options de clés/agent. SunSSH et les implémentations
SSH propriétaires ne sont pas substituées automatiquement à OpenSSH. La sonde
native vérifie le parsing effectif avec ssh -G, sans connexion réseau.

Le profil -avzPH --numeric-ids --delete exige rsync 3.5.0+ local ET distant.
Les rsync anciens présents par défaut sur certains OS sont refusés. SFTP ne
reconstitue pas ce profil pour les arbres ; un arbre sans rsync compatible
échoue explicitement. Sous Windows natif, les conventions de chemins et
l'environnement d'un port POSIX rsync ne sont pas devinés. Exécuter le client
entier dans WSL pour conserver une seule sémantique de chemins et d'attributs.
Les UID/GID/hard links/permissions restent dépendants du filesystem et des droits.

Les chemins distants de transfert utilisent la syntaxe absolue POSIX exposée
par le serveur SFTP/rsync, sans variables ni .. ; configurer le chemin exposé
par un serveur Windows, pas une expansion locale de C:\\ ou du shell client.
Les chemins locaux suivent pathlib sur l'OS du client. La CLI protège les noms
réservés Windows dans les collectes et sépare les dossiers par identité SSH.

## Extensions de la version 2

Les canaux binaires, tunnels loopback, workflows SQLite et intents sont conçus
pour CPython 3.11+ ; Windows conserve l’exigence Proactor. Les sessions
ControlMaster restent POSIX. Le relais utilise des flux binaires et le même
interpréteur installé ; les métacaractères du chemin de cet interpréteur Windows sont refusés.
Les tests locaux Windows 3.14 et Linux 3.12 ne qualifient pas automatiquement
les clients/serveurs, matériels, macOS, AIX ou Solaris. Les campagnes exactes
sont dans [VALIDATION.md](../../../VALIDATION.md).

## Adaptations du moteur

- Linux seul lit /proc/meminfo et les limites cgroup v2. Une sonde Linux absente
  peut se replier sur sysconf ; une mesure de zéro reste un refus d'admission.
- Sur POSIX, SC_AVPHYS_PAGES × SC_PAGE_SIZE est utilisé si disponible. Un résultat
  absent/indéterminé ne devient pas de la mémoire physique totale présentée comme libre.
- Windows utilise GlobalMemoryStatusEx via ctypes standard, avec une structure
  de 64 octets et des types explicites. Un échec de sonde conserve le budget configuré.
- Le budget --memory-budget-mib reste toujours un plafond d'estimation par invocation.
  L'absence d'une sonde n'autorise pas une concurrence illimitée.
- RLIMIT_NOFILE borne les descripteurs POSIX ; /dev/fd est consulté hors Linux.
  Une liste indisponible réserve une marge supplémentaire ; une limite trop basse
  bloque l'exécution. Sans API resource, le plafond conservateur reste 64 workers,
  également réduit par le budget mémoire et les autres limites.
- O_DIRECTORY et O_NOFOLLOW sont optionnels. Le descripteur ouvert d'un dossier
  est contrôlé par fstat ; la chaîne est désormais parcourue avec dir_fd et
  comparaisons inode/device. Les exports utilisent le dossier épinglé.
- Les groupes de processus POSIX s'appliquent aux quatre Unix. Le descendant
  Windows hérite du Job Object du guardian, créé avant le client. Des tests
  natifs sont fournis ; leur certification sur site reste nécessaire.
- Windows nécessite ProactorEventLoop pour les pipes et subprocesses asyncio.
  La CLI utilise asyncio.run avec sa boucle standard. Une API hébergée dans un
  SelectorEventLoop incompatible échoue sans lancer de client natif ; aucune
  politique de boucle globale de l'application hôte n'est remplacée.

Une DACL privée est appliquée aux dossiers sensibles Windows et aux temporaires
de rapport après contrôle du propriétaire. Le compte et ses dossiers parents
doivent être correctement provisionnés. Les alias
système macOS contrôlés sont conservés ; une jonction Windows dans un chemin
sensible est refusée. Les stocks d'état/audit/spool doivent être locaux et fiables,
avec les permissions/quotas adaptés ; la charge rsync d'un arbre n'est pas un
quota RSS. Le budget commun aux invocations du compte est désormais actif ;
voir [HARDENING-1.4.0.md](../history/hardening/HARDENING-1.4.0.md) pour sa portée et ses limites.
Le preview requiert rsync et reste disponible sur POSIX/WSL. La vérification
SHA-256 peut être pilotée depuis les cinq OS, mais exige un shell POSIX et un
outil de hash supporté côté serveur ; un shell PowerShell seul est refusé.

## Fuseaux et planification

UTC et les offsets explicites fonctionnent sans données IANA supplémentaires.
Les zones nommées comme Europe/Paris utilisent la base zoneinfo du système.
Windows ne la fournit pas forcément : utiliser UTC/+02:00, ou provisionner des
fichiers IANA standards et PYTHONTZPATH. Aucune dépendance tzdata Python n'est ajoutée.
Une zone absente produit une erreur explicite, sans approximation des règles DST.
Les snapshots schedule sont exécutés sur leur client local d'origine : une base
contenant des chemins Unix n'est pas migrée silencieusement vers Windows.
Les bases valides 1.3.0/1.3.1 conservent user_version=1, sans migration destructive.

## Solaris : SMF

Exécuter le générateur sous le compte qui possédera l'état et les fichiers privés.
L'interpréteur courant doit être celui où SWASSH est installé.

```sh
python3 scripts/scheduler_service.py --platform smf --state-dir "$HOME/.local/state/swassh/schedules" --output-dir "$HOME/.local/state/swassh/services"
svccfg validate "$HOME/.local/state/swassh/services/swassh-scheduler-smf.xml"
sudo svccfg import "$HOME/.local/state/swassh/services/swassh-scheduler-smf.xml"
sudo svcadm enable -s svc:/site/swassh-scheduler:default
svcs -xv svc:/site/swassh-scheduler:default
```

Le XML conserve l'instance désactivée jusqu'à l'activation opérateur. La méthode
0700 lance le worker dans le contrat SMF, masque 0077, efface les variables de
contexte SMF et vérifie sa survie initiale. SMF suit le contrat ; la méthode stop
:kill envoie SIGTERM au contrat. La survie initiale n'est pas une preuve de
readiness complète de la base. La définition doit être validée par le DTD natif
et testée sur Solaris. --user peut définir le compte SMF ; par défaut, le UID
effectif est employé sur POSIX, sans faire confiance à USER/LOGNAME.
Si un administrateur génère sous un autre compte, il doit provisionner les droits
d'accès/exécution du compte choisi et l'accès au state/known_hosts/clés.

## AIX : SRC

Le lanceur n'effectue ni fork daemon ni nohup : exec remplace le shell par le
worker pour que SRC supervise ce PID. Le masque 0077 précède Python.

```sh
python3 scripts/scheduler_service.py --platform src --state-dir "$HOME/.local/state/swassh/schedules" --output-dir "$HOME/.local/state/swassh/services"
sudo mkssys -s swassh-scheduler -p "$HOME/.local/state/swassh/services/swassh-scheduler-src.sh" -u "$(id -u)" -S -n 15 -f 9 -R -i /dev/null -o /dev/null -e /dev/null
sudo startsrc -s swassh-scheduler
lssrc -s swassh-scheduler
sudo stopsrc -s swassh-scheduler
```

Le démarrage après reboot doit être intégré à la politique native du site,
par exemple sa configuration inittab administrée ; cette livraison ne la modifie
pas. L'arrêt normal utilise SIGTERM et la fermeture ordonnée du moteur. Un
SIGKILL du parent peut laisser des effets/processus distants ; il ne déclenche
jamais un rejeu de tâche running. Configurer les clés/agent pour le contexte SRC.
Aucun subsystem n'est enregistré ou activé automatiquement.

## Validation et CI

Sonde locale native, sans connexion réseau, avec state/audit/rapport temporaires :

```sh
python3 scripts/platform_gate.py --expected linux
python3 scripts/platform_gate.py --expected solaris --require-rsync
python3 scripts/platform_gate.py --expected aix --require-rsync
python3 scripts/platform_gate.py --expected macos
```

Sur Windows : python scripts/platform_gate.py --expected windows.
La sonde rapporte OS/interpréteur/architecture, clients natifs, plan de ressources,
SQLite/audit fsync et interpréteur de rapport distinct. L'option --require-rsync
certifie la disponibilité locale du profil ; la version distante reste sondée
par chaque transfert. Elle ne constitue pas une intégration SSH authentifiée.

La CI existante Linux/macOS/Windows conserve sa matrice Python 3.11–3.14 et
intègre les nouveaux tests via découverte unittest. Solaris et AIX sont testés
par le workflow manuel .github/workflows/portability.yml, depuis un runner Linux
dédié portant le label swassh-portability, via le même moteur SSH strict.
Les cibles n'ont pas besoin d'un runner GitHub natif.

Configurer l'environnement GitHub native-portability avec sa protection opérateur,
un runner Python 3.11+ / OpenSSH, ses clés ou agent, known_hosts vérifié et ces
variables de dépôt :

| Cible | Identité SSH | Python absolu | Checkout absolu |
| --- | --- | --- | --- |
| Solaris | SWASSH_SOLARIS_HOST | SWASSH_SOLARIS_PYTHON | SWASSH_SOLARIS_CHECKOUT |
| AIX | SWASSH_AIX_HOST | SWASSH_AIX_PYTHON | SWASSH_AIX_CHECKOUT |

Provisionner sur chaque cible le même arbre source extrait de
la livraison (pas seulement le wheel), Python complet avec venv/ensurepip,
OpenSSH et rsync 3.5.0+. Les chemins Python/CHECKOUT sont absolus. Le workflow
n'importe pas de code arbitraire ni de credentials depuis une PR ; il est déclenché
manuellement sur une révision de confiance par l'opérateur.

Le bridge vérifie l'OS natif et les SHA-256 de l'ensemble exact des sources/tests/
scripts/backend avant tout test. Il refuse toute modification ou module supplémentaire,
même sous Python -O. Il exécute la sonde, QA, couverture, build, installations
neuves et packaging ; une étape en erreur bloque les suivantes. Rapports et audit
restent limités et archivés sur le runner ; aucune relance automatique ne réexécute
une campagne ambiguë. Le stdout SSH est borné ; lire les preuves complètes dans
validation/ sur la cible. Le timeout de SSH n'est pas un mécanisme de rollback
ni une garantie d'arrêt du processus de test distant.

Ces définitions et premiers tests de plateforme proviennent du cycle 1.4.0,
exercé sur Linux. Les campagnes de la version 2 ajoutent des essais locaux
Windows et Linux, sans certification native Solaris, AIX ou macOS. VALIDATION.md précise les
preuves locales ; exécuter les campagnes natives avant qualification production.

Références primaires :

- [Python : asyncio par plateforme](https://docs.python.org/3.11/library/asyncio-platforms.html)
- [Solaris : sysconf](https://docs.oracle.com/cd/E88353_01/html/E37843/sysconf-3c.html)
- [Solaris : conventions SMF](https://docs.oracle.com/cd/E36784_01/html/E36883/smf-method-5.html)
- [IBM : mkssys](https://www.ibm.com/docs/en/aix/7.3.0?topic=m-mkssys-command)
- [Windows : GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex)
