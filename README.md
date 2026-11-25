> API Python rc4 (dialogue bidirectionnel asynchrone) : [clients synchrones/asynchrones, flux gérés et erreurs structurées](docs/wiki.d/usage/PYTHON-SDK.md).

> Version 2.0.0 : [procédures réseau et durcissement des sessions](docs/wiki.d/usage/NETWORK.md). La reconnexion après redémarrage est implémentée. Le périmètre de qualification courant couvre Linux et Windows ; les équipements réels, macOS, AIX et Solaris en sont exclus à la demande de l’utilisateur. Voir VALIDATION.md.

Voir aussi le [comparatif fonctionnel avec ssh2-python, Paramiko, Netmiko et Fabric](docs/wiki.d/reference/COMPARISON.md).

Avant une exécution, `swassh run 'uname -r' -i hosts.txt --check` examine les
prérequis locaux sans connexion SSH ni création de tâche. Ajouter `--format json`
pour un diagnostic structuré. Un contrôle local réussi ne garantit pas
l'authentification distante. Les clés explicitement fournies avec `-k` sont
également vérifiées avant une exécution normale ; les erreurs précisent le
numéro de clé et la correction attendue sans divulguer son contenu ni son chemin.

# SWASSH

Version 2.0.0 : idempotence déclarative, workflows persistants avec reprise
sans rejeu, canaux binaires, tunnels loopback et plafond commun des flux SSH.
Vérifier le reçu de qualification locale correspondant au SHA-256 du ZIP et les
contrôles de [VALIDATION.md](VALIDATION.md) avant le déploiement. Le [Wiki](docs/index.md)
regroupe les contrats, procédures et historiques.

**Massively parallel SSH execution, built like a swarm.**

Bibliothèque autonome et commande **`swassh`**, développées en Python **3.11+**
avec **uniquement la bibliothèque standard**. Aucune dépendance Python externe,
y compris pour les tests et la construction des distributions.

SWASSH exécute des commandes depuis un bastion sur des flottes de 10 000 à
100 000 serveurs, avec concurrence bornée, rapports groupés, affichage compact
et logs JSONL avec rotation compressée.

## Organisation DDD

Le code canonique vit dans `src/swassh/domain/`, `application/`,
`infrastructure/` et `interfaces/`. `bootstrap.py` assemble les adaptateurs.
Le domaine porte les identités et résultats immuables ; les cas d’usage dépendent
uniquement des ports injectés. OpenSSH, SQLite, l’audit et les formats de fichiers
restent dans l’infrastructure. Les exports publics `from swassh import ...` restent disponibles ; les modules
plats ont été supprimés au profit des chemins DDD.
Voir [l’architecture détaillée](docs/wiki.d/reference/ARCHITECTURE.md).

## Prérequis et installation

Le client **OpenSSH système (`ssh`)** doit être présent. Python standard ne
fournit pas de client SSH : SWASSH pilote OpenSSH via
`asyncio.create_subprocess_exec`, sans shell Python local. OpenSSH 7.3+ est
requis, notamment pour le saut facultatif via ProxyJump.

```bash
python -m pip install --no-deps dist/swassh-2.0.0-py3-none-any.whl
swassh --version
```

Installation depuis les sources, avec backend de build standard autonome :

```bash
python -m pip install --no-deps .
```

Le wheel n’a aucun `Requires-Dist`. Les commandes distantes doivent être
compatibles avec le shell et les permissions des cibles. Aucun agent SWASSH
n’est installé sur les serveurs.

## Exécution

Provisionner les clés d’hôte vérifiées dans `~/.ssh/known_hosts`, puis utiliser
une clé privée explicite ou l’agent SSH local. Authentification non interactive
par clé/agent par défaut, ou explicitement par mot de passe via un fournisseur
externe, ou Kerberos/GSSAPI. Les clés inconnues ou modifiées sont refusées.

```bash
swassh run 'uname -r' -H srv01 srv02 admin@srv03:2222
swassh run 'df -P' -i examples/hosts.txt -u admin -k ~/.ssh/id_ed25519
swassh run 'uname -r' -i flotte-50000.txt -j 32 --connect-rate 20 --format json -o rapport.json
swassh run 'uptime' -i examples/hosts.csv --format csv -o rapport.csv
swassh run 'hostname' -H srv01 srv02 --jump admin@bastion -u admin
swassh run 'uname -r' -i flotte-50000.txt --plan-only
```

La syntaxe canonique est `swassh run 'commande ou script avec options' -i hosts.txt`.
La commande complète constitue un seul argument : les options contenues dans
les guillemets appartiennent à la commande distante, les options placées après
(`-i`, `-u`, etc.) appartiennent à SWASSH.

```bash
swassh run 'sudo -n /opt/scripts/deploy.sh --env production --workers 4' -i hosts.txt
swassh run 'cd /srv/app && ./maintenance.sh --check && systemctl is-active app' -i hosts.txt
```

Le script doit déjà être présent sur les serveurs. Pour un script local, utiliser
`swassh push` au préalable. Les anciennes options `-c`, `--command` et
`--commande` sont retirées : migrer vers la commande positionnelle de `run`.
Une sous-commande explicite est obligatoire. Les options longues
ne sont pas abrégées ; `--command-timeout` conserve son rôle de délai.

La commande est passée telle quelle au shell **distant** ; ses métacaractères
sont intentionnels. Aucun `sudo` ni PTY n’est généré : passer `sudo -n ...` si
la politique distante le permet. La configuration SSH ambiante n’est pas lue :
un fichier temporaire privé est généré, également utilisé par le saut SSH.

Codes de sortie : `0` toutes les cibles réussissent, `1` au moins une échoue,
`2` entrée/ressource/écriture invalide, `130` après Ctrl+C. Ctrl+C ferme les
clients locaux, sans garantie d’arrêt des processus distants et sans rapport
partiel publié. Un rapport préexistant est préservé si l’export échoue avant
publication. Une erreur de synchronisation du dossier après remplacement peut
laisser le nouveau fichier visible ; inspecter son état avant de relancer.

## États désirés, dépendances et connexions explicites

```sh
swassh converge --action-file examples/desired-state.json -H srv01 --plan-only
swassh workflow --workflow-file examples/workflow.json --plan-only
swassh workflow --workflow-file examples/workflow.json --state-dir ./workflow-state
swassh workflow --state-dir ./workflow-state --worker --once
swassh tunnel -H bastion --local-port 18443 --remote-host service.internal --remote-port 443 --plan-only
```

Les exemples de mutation créent un répertoire de démonstration dans le HOME
distant ; les examiner avant exécution. Une définition DesiredState déclare
check/apply/verify. Le journal bloque tout rejeu d'une action ambiguë. Un workflow
attend toutes ses dépendances et conserve chaque rapport ; sa reprise exige une
postcondition positive et une demande explicite. Les commandes opaques restent
sous responsabilité de l'opérateur.

En Python, `AsyncClient.channel` et `AsyncClient.tunnel` créent des scopes
asynchrones pour un hôte. `SSHChannel`, `SSHTunnel`, `LocalForward`, `DesiredState`,
`ConvergentSwarm`, `Workflow`, `WorkflowStep` et `WorkflowRunner` sont exportés.
Voir les fiches [idempotence](docs/wiki.d/usage/CONVERGENCE.md),
[workflows](docs/wiki.d/usage/WORKFLOWS.md) et [canaux/tunnels](docs/wiki.d/usage/CHANNELS.md).

Les octets chiffrés des connexions du même budget local partagent désormais
`--bastion-bandwidth-kib` dans les deux directions. Le relais n'impose pas une
QoS à la carte réseau ou aux autres logiciels ; voir [son périmètre](docs/wiki.d/operations/BANDWIDTH.md).

## Planifier une commande ou un script

```bash
swassh schedule '/opt/scripts/deploy.sh --env production' -i hosts.txt --at '2026-10-08 02:00' --timezone Europe/Paris --canary 5
swassh schedule --list
swassh schedule --worker
```

L'enregistrement est persistant et rend la main. **Un worker supervisé doit
rester actif** pour exécuter les tâches à l'échéance ; le projet inclut un
générateur de services systemd, launchd et Windows. Chaque tâche garde un
snapshot de son inventaire et de ses options. Une seule flotte est admise à la
fois, avec les mêmes limites de charge et la même barrière canary que `run`.
Les rapports et audits sont privés, séparés par tâche. Une tâche interrompue
n'est jamais relancée automatiquement. La CLI permet de lister, consulter,
annuler et purger les tâches. Les heures locales ambiguës exigent un choix
explicite ; les heures inexistantes sont refusées.
Voir [SCHEDULING.md](docs/wiki.d/usage/SCHEDULING.md) pour les états, fuseaux, retards,
installation des services et récupération après arrêt.

## Transfert de fichiers : push et pull

```bash
swassh push -i flotte.txt --source ./release/ --destination /srv/application/ --format json -o push.json
swassh pull -i flotte.txt --source /var/log/application/ --destination ./collecte/ --format json -o pull.json
```

rsync prioritaire avec **`-avzPH --numeric-ids --delete`** ; SFTP automatique
pour les fichiers simples si rsync est indisponible. **`--delete` supprime les
entrées absentes de la source dans la destination synchronisée.** Le pull isole
chaque serveur dans son propre dossier. SFTP ne reproduit pas les suppressions,
liens physiques et UID/GID : un répertoire sans rsync compatible échoue
explicitement. Concurrence, bande passante et connexions sont bornées ; aucune
relance après le début d’un transfert. Voir [la documentation complète](docs/wiki.d/usage/TRANSFERS.md)
pour les chemins, garanties, limites, budgets et API Python.

## Protection du bastion et GIL

- **asyncio** orchestre la cadence, les workers, les flux et les annulations.
- **32 workers demandés** par défaut ; plafond effectif ajusté au budget mémoire,
  aux descripteurs et à la mémoire disponible lorsque mesurable, avec maximum
  absolu 256. Les sondes Linux/cgroup restent réservées à Linux.
- **20 connexions/s** par défaut, sans rafale d’invocations. Le saut compte deux
  connexions et réduit d’autant la cadence d’invocation.
- Chaque cible utilise un **processus OpenSSH**, dont chiffrement et négociation
  échappent au GIL de Python. Leur nombre reste borné par les workers.
- Un **seul processus Python dédié** sérialise les rapports et écrit SQLite.
  Il a son propre GIL ; les lots transmis sont limités à min(workers, 32).
- File de résultats bornée à la concurrence effective ; capture de **64 Kio par
  flux et cible**. Les flux continuent d’être drainés après troncature.
- La CLI utilise toujours le **mode disque**, avec spool privé, cache SQLite
  limité à 2 Mio, déduplication des réponses et exports par curseurs.

Le nombre de cibles allonge le traitement, sans créer une tâche ou un processus
par serveur simultanément. Les métadonnées d’inventaire restent en O(nombre de
cibles). Le budget est une estimation prudente, **pas une limite RSS imposée**
ni une garantie contre la charge d’autres applications. Inspecter `--plan-only`
puis ajuster sur le bastion réel. Le test local de 50 000 cibles est simulé.

```bash
swassh run 'uptime' -i flotte.txt --memory-budget-mib 128 --max-output-bytes 65536 --max-report-mib 4096 --spool-dir /var/tmp
```

Le spool est borné à 1 Gio par défaut. Un dépassement interrompt la collecte ;
prévoir également l’espace du rapport final pendant l’export atomique. Une
lenteur du processus écrivain applique une contre-pression au moteur.

Les retries portent seulement sur des échecs réseau établis **avant
l’authentification**, d’après les diagnostics privés du client OpenSSH.
Ils sont désynchronisés par temporisation exponentielle et jitter. Une commande
commencée, un code distant `255`, une erreur d’authentification ou de clé d’hôte
ne sont jamais rejoués. La sortie distante ne sert pas à décider une relance.

## Affichage et rapports

Le texte par défaut reste compact : compteurs, une réponse principale par statut,
**3 hôtes exemples maximum**, aperçus de **200 caractères**. Au maximum 8 statuts,
quel que soit le nombre de cibles. Les détails sont conservés en JSON/CSV.

| Statut | Signification |
| --- | --- |
| `success` | Client SSH terminé avec code 0 |
| `failed` | Code de commande distant non nul confirmé par OpenSSH ou échec du transfert natif |
| `unreachable` | Échec réseau identifié avant authentification |
| `auth_failed` | Authentification refusée |
| `host_key_failed` | Clé d’hôte inconnue ou modifiée |
| `timeout` | Délai OpenSSH ou échéance de l’invocation dépassé |
| `interrupted` | Transport interrompu après authentification/lancement |
| `skipped` | Cible non exécutée après échec du canary ; zéro tentative |
| `error` | Erreur client, I/O, extension ou diagnostic incertain |

JSON `schema_version=1` : `run_id`, dates UTC, durée, compteurs, groupes de statuts,
groupes de réponses capturées identiques et résultats par cible. Le rapport disque
suit l’ordre d’achèvement. Les clés comprennent stdout/stderr, code, erreur, durée,
essais et troncature. OpenSSH ne garantit pas l’exposition du nom d’un signal
distant : `exit_signal` peut rester absent. Les groupes comparent le contenu
**capturé**, pas les éventuels suffixes tronqués.

Le CSV neutralise les formules de tableur ; le texte neutralise les caractères
de contrôle. Les exports sont atomiques et privés sur POSIX. Les rapports peuvent
contenir des données sensibles produites par les commandes elles-mêmes.

## Logs et rétention

Logs CLI activés par défaut :
`$XDG_STATE_HOME/swassh/swassh.jsonl`, sinon
`~/.local/state/swassh/swassh.jsonl` sur Unix, et
`%LOCALAPPDATA%/swassh/swassh.jsonl` sur Windows.

```bash
swassh run 'uname -r' -i flotte.txt --log-file /var/log/swassh/swassh.jsonl
```

Rotation à **100 Mio = 104 857 600 octets**, **3 archives gzip** en plus du journal
actif : `.1.gz`, `.2.gz`, `.3.gz`. Chaque archive correspond à un segment de
100 Mio avant compression. Les archives les plus anciennes sont supprimées.

Chaque événement contient date UTC, PID, `run_id`, cible, statut, essais et durée.
Les commandes sont identifiées par SHA-256 ; les logs d’audit ne contiennent ni
commande en clair, ni mot de passe, ni sortie distante. Les diagnostics temporaires
privés d’OpenSSH peuvent contenir la commande et sont supprimés après chaque
invocation ; leur taille est surveillée et leur lecture limitée à 128 Kio.

Les logs sont flushés et fsyncés par lots de 64 au plus, hors de la boucle asyncio.
Les marqueurs canary/flotte sont synchronisés avant l’admission SSH ; la rotation
gzip est aussi terminée et synchronisée avant publication.
La compression gzip native libère le GIL pendant le travail de zlib ; les petites
sérialisations d’événements ne sont pas présentées comme du calcul parallèle.
Un verrou OS refuse plusieurs écrivains sur un même chemin : utiliser un fichier
par processus SWASSH simultané. Une erreur de log interrompt l’exécution.
SIGKILL peut perdre le dernier lot non flushé. Permissions privées POSIX ; ACL
Windows à configurer selon le compte d’exploitation.

## API Python

Mode recommandé pour les grandes flottes, avec un processus écrivain :

```python
from swassh import Options, execute_to_file, load_inventory


def main():
    summary = execute_to_file(
        load_inventory("examples/hosts.yaml"),
        "uname -r",
        "rapport.json",
        Options(username="admin", log_file="logs/swassh.jsonl"),
    )
    print(summary.run_id, summary.counts)


if __name__ == "__main__":
    main()
```

Le garde `if __name__ == "__main__"` est nécessaire pour l’API utilisant le
processus écrivain, comme pour tout programme multiprocessing avec spawn.
Dans une application asyncio : `await Swarm(options).run_to_file(...)`.

`Swarm.iter_results()` fournit les résultats au fil de l’eau. Utiliser
`contextlib.aclosing()` si l’on interrompt l’itération. `Swarm.run()` / `execute()`
restent disponibles pour de petits rapports en mémoire et refusent le dépassement
du budget de collecte. L’ordre de `run()` est celui de l’inventaire. Les API
synchrones refusent une boucle asyncio déjà active.
En bibliothèque, activer l’audit explicitement avec `Options(log_file=...)`.

## Inventaires

TXT : un `[user@]hôte[:port]` par ligne, commentaires `#` et lignes vides acceptés.
IPv6 avec port : `[2001:db8::1]:2222`. CSV : `hostname`, et éventuellement
`port`, `username`, `label`. JSON : liste ou objet contenant seulement `hosts`.

YAML : **sous-ensemble SWASSH strict**, sans bibliothèque externe : liste de chaînes
ou de records, racine `hosts` facultative, champs simples et chaînes citées.
Les ancres, tags, objets Python, tableaux inline et inventaires Ansible/INI sont
refusés. La prise en charge ne constitue pas un parseur YAML général.

```yaml
hosts:
  - srv01
  - hostname: srv02
    port: 2222
    username: admin
    label: production
```

Limites : 10 Mio et 100 000 enregistrements d’entrée, même en cas de doublons. Les doublons identiques sont fusionnés,
les définitions contradictoires refusées. L’utilisateur d’un hôte prime sur
l’utilisateur global. Les identifiants SSH sont limités aux caractères sûrs.

## Tests, construction et CI/CD

La qualification SAST v2 conserve le scan Bandit intégral et son vrai résultat
brut. Chaque avertissement exige une revue individuelle démontrée, liée aux
sources complètes et approuvée par une autorité détachée. Défaut confirmé,
risque ouvert, preuve manquante ou revue périmée restent bloquants. Les attentes
de l'opérateur ne sont jamais calculées depuis la déclaration du candidat.
Voir [SECURITY.md](SECURITY.md) pour les trois paramètres de CI requis, la
frontière de confiance du lanceur et les procédures locales. Le contrôle SAST
ne dispense jamais des tests, des cinq couvertures ≥98 % par module ni des
contrôles d'installation, d'intégrité et de reproductibilité. Les tests du
contrat v1 restent conservés et exécutés sur leur référence versionnée.
Le scan précède les commandes de qualité et de construction dans un arbre
propre de sources maintenues ; caches compilés, membres de racine inconnus et
artefacts préconstruits sont refusés. L'identité et le manifeste d'une archive
complète sont vérifiés avant de préparer cet arbre ; ses distributions et
preuves restent à part, sans suppression des fichiers de travail de l'opérateur.

```bash
python scripts/verify.py
python scripts/coverage.py
python scripts/benchmark.py --hosts 50000 --concurrency 32
python scripts/build.py
python scripts/package.py
```

Tout utilise la bibliothèque standard : unittest, AST, compileall, trace, zipfile,
tarfile. Les tests couvrent domaine, formats, sécurité, annulation, SSH simulé,
client OpenSSH réel, logs/rotation et flotte simulée de 50 000 cibles. Les tests
SSH authentifiés nécessitent un sshd local pouvant effectuer sa séparation de
privilèges ; une indisponibilité est explicitement consignée, pas comptée comme
une validation réussie. Voir `VALIDATION.md`.

CI Linux/macOS/Windows, Python 3.11–3.14, frontières DDD et cycles de dépendances,
contrôles d’imports exclusivement standards,
syntaxe, règles AST de sécurité, tests, cinq couvertures à seuil individuel de 98 %, Wiki, wheel/sdist/ZIP et
installation du wheel sans dépendances. `release.yml` crée la release GitHub et
publie par Trusted Publisher PyPI après validation. Configurer son projet PyPI
et l’environnement `pypi`. Aucune publication externe n’a été effectuée.

Auteur : Alfred TCHONDJO. Copyright © 2026 Alfred TCHONDJO. Licence MIT.

## Durcissement 1.3.1

[Bilan complet de l’audit](docs/wiki.d/history/hardening/HARDENING.md), [politique de sécurité](SECURITY.md)
et [validation exécutée](VALIDATION.md). La syntaxe reste :

```bash
swassh run 'complex-command-or-script-with-options' -i hosts.txt
```

Les alias `-c`, `--command` et `--commande` restent supprimés. Commande opaque
limitée à 16 Kio UTF-8 ; transférer un script plus long avec push puis le lancer
sur la cible. `--report-timeout` borne les opérations du processus de rapport.

Rsync exige **3.5.0+ localement et à distance**. Un rsync ancien entraîne SFTP
pour un fichier simple, un échec explicite pour un répertoire. Le profil
`-avzPH --numeric-ids --delete` reste actif avec des protections supplémentaires :
liens sortants/fichiers spéciaux exclus, bits setuid/setgid retirés, répertoires
de pull privés et allocations rsync plafonnées par `--rsync-max-alloc-mib`.
Les collectes nécessitent toujours un quota disque et une supervision système.

## Canary par défaut

La première vague comporte **1 serveur par défaut**. `--canary` seul conserve
cette valeur ; `--canary 5` choisit les cinq premières identités SSH distinctes
de l’inventaire normalisé. La flotte restante démarre uniquement après le succès
de tous les canaris, avec la concurrence et les budgets habituels. Un échec
bloque la suite : les autres cibles sont `skipped`, avec zéro tentative.

```bash
swassh run 'complex-command-or-script-with-options' -i hosts.txt --canary 5
```

Cette barrière s’applique aussi à push/pull. Le texte compact, JSON/CSV et les
logs distinguent la première vague et les cibles non exécutées. Aucun rollback
ni contrôle de santé supplémentaire n’est implicite ; voir [CANARY.md](docs/wiki.d/usage/CANARY.md).

## Améliorations 1.4.2

Les sept propositions précédentes sont intégrées : budget partagé entre CLI et
workers schedule, nettoyage des descendants Windows par Job Object, chemins
locaux épinglés, preview rsync, vérification SHA-256 avant publication, admission
adaptative et progression agrégée. Python standard reste la seule dépendance.

```bash
swassh run './deploy.sh --release 42' -i hosts.txt --canary 5 --adaptive --progress
swassh push --source ./release/ --destination /srv/app/ -i hosts.txt --dry-run
swassh push --source ./release.tar --destination /srv/release.tar -i hosts.txt --verify-sha256
swassh pull --source /srv/release.tar --destination ./collecte -i hosts.txt --verify-sha256
```

Par défaut, le compte partage 32 slots de connexion, 20 départs/s, 512 MiB de
budgets mémoire réservés et 10 240 KiB/s de plafond commun des flux chiffrés et de limites de transfert. Les options
--bastion-concurrency, --bastion-connect-rate, --bastion-memory-mib et
--bastion-bandwidth-kib configurent cette politique commune. --budget-dir doit
être identique entre invocations concurrentes. Une invocation réserve son budget
mémoire + 64 MiB avant ses helpers ; le plan natif provisionne aussi les guardians.
Ces estimations complètent les quotas OS. Pour plusieurs CLI actives, fournir un
--log-file distinct par invocation ; le verrou exclusif d'audit est conservé.

--dry-run exige rsync compatible, sans repli SFTP. --verify-sha256 couvre un
fichier, utilise un outil de hash natif et un shell POSIX distant, et garde les
fichiers push vérifiés en 0600. Les arbres vérifiés et la combinaison des deux
modes sont refusés. Les compteurs de preview n'affichent aucun nom de fichier.

Voir [les fonctionnalités livrées](docs/wiki.d/history/IMPROVEMENTS.md), leurs [contrats et
conditions](docs/wiki.d/history/hardening/HARDENING-1.4.0.md), la [qualification réseau 1.4.2](docs/wiki.d/history/releases/RELEASE-1.4.2.md)
et la [validation exécutée](VALIDATION.md).

## Portabilité 1.3.2

Le runtime vise Linux, Solaris, AIX, macOS et Windows avec CPython 3.11+ 64 bits
et des clients OpenSSH natifs compatibles. Le profil rsync complet est utilisé
sur POSIX avec rsync 3.5.0+ aux deux extrémités. Sous Windows natif, run/schedule
et les transferts de fichiers SFTP sont disponibles ; la synchronisation
rsync de répertoires est exécutée depuis WSL. Aucun miroir SFTP incomplet
n'est assimilé à --delete/-H/--numeric-ids.

Les sondes mémoire et descripteurs ont des replis conservateurs ; O_DIRECTORY
n'est plus supposé présent. Les services du scheduler peuvent être générés
pour systemd, launchd, Windows Task Scheduler, Solaris SMF et AIX SRC.
Voir [PORTABILITY.md](docs/wiki.d/operations/PORTABILITY.md) pour les capacités exactes,
les prérequis et la campagne de certification native par SSH. La compatibilité
de conception ne remplace pas les tests exécutés sur chaque OS réel.

## Installation et affichage 2.0.0

Le paquet fournit une wheel et une archive source standard, installables par
`python -m pip install dist/swassh-2.0.0-py3-none-any.whl` ou
`python -m pip install .`. Après publication sur votre index, l'installation
directe devient `python -m pip install swassh==2.0.0`.

Pour un déploiement complet via pip avec mise à jour du PATH si nécessaire,
dans un environnement applicatif conservé :

```sh
python3 scripts/install.py --package-version 2.0.0 --venv "$HOME/.local/share/swassh-venv"
```

Cette commande nécessite que la version existe sur l'index configuré dans pip.
L'archive livrée ne vaut pas publication PyPI. En mode hors ligne :

```sh
python3 scripts/install.py dist/swassh-2.0.0-py3-none-any.whl --venv "$HOME/.local/share/swassh-venv"
```

L'installateur appelle pip et sauvegarde les profils modifiés. Il affiche
la commande `export PATH=...` à exécuter dans le shell déjà ouvert. Un processus
Python ou pip ne peut pas modifier l'environnement de son shell parent. Les
prochaines sessions chargent le PATH configuré. Pour une installation pip déjà
réalisée : `python3 -m swassh setup-path`. Avec la 1.4.2, utiliser immédiatement
`export PATH="${PATH:+${PATH}:}/usr/local/bin"`, puis `swassh --version` ; `python3 -m swassh`
fonctionne aussi sans changer le PATH.

Sous Windows :

```powershell
py scripts/install.py --package-version 2.0.0 --venv "$env:LOCALAPPDATA\SWASSH\venv"
```

Le PATH utilisateur Windows est complété sans doublon, avec sauvegarde et
notification des nouvelles sessions. Ouvrir un nouveau terminal après le
déploiement. Les environnements virtuels de développement restent à activer ;
seul `--venv` autorise explicitement la persistance d'un environnement applicatif.
`--skip-path` laisse cette gestion à votre outil de déploiement ; `--user`
sélectionne une installation pip utilisateur, si la politique du Python le permet.
`setup-path` ne modifie jamais le PATH global du système. Les shells POSIX pris en
charge sont bash, sh/dash, ksh et zsh (sans ZDOTDIR personnalisé).
Voir [installation, publication et retour arrière](docs/wiki.d/operations/INSTALLATION.md).

Le format texte affiche la synthèse et les sorties de chaque hôte par défaut.
Avec `--hide-output`, il affiche les réponses exceptionnelles les plus
fréquentes par statut, avec trois hôtes exemples et le nombre de groupes omis.
Les blocs sont structurés par lignes : dix lignes par flux, 240 caractères
par ligne, avertissement explicite de troncature. Les statuts d'erreur existants
restent distingués ; les skipped restent des cibles non exécutées. Les couleurs
sont réservées à stdout interactif ; `NO_COLOR` les désactive. Les fichiers restent
sans couleurs. Les caractères de contrôle distants sont neutralisés en texte.

`Result.changed: bool = False` est un indicateur explicite et optionnel fourni par
un adaptateur, autorisé seulement avec `Status.SUCCESS`. Il apparaît dans JSON,
CSV et les regroupements. Il ne modifie ni les codes de sortie ni les compteurs
success. Le client SSH natif ne peut pas inférer une modification métier d'une
commande opaque, et n'en déclare aucune. Les transferts ne prétendent pas comparer
l'état métier avant/après. Aucun nom de commande ni contenu n'est interprété.

JSON est indenté même dans le processus de rapport, écrit progressivement. CSV
conserve les guillemets, retours internes, protections contre les formules et
ajoute une ligne vide après chaque enregistrement ; `csv.DictReader` ignore ces
lignes. Pour exploiter toutes les réponses sans limite d'affichage, exporter en
JSON/CSV (dans la limite de capture configurée). Voir [la présentation introduite en 1.5.0](docs/wiki.d/history/releases/RELEASE-1.5.0.md).

### Afficher les résultats de commandes de consultation

```sh
swassh run 'ls -la /srv' -i hosts.txt
swassh run 'ip a' -i hosts.txt --output-lines 0
swassh run 'ps -ef' -i hosts.txt --output-lines 30
```

Les sorties sont affichées par défaut, y compris les succès.
`--hide-output` rétablit la synthèse compacte ; `--show-output` reste accepté.
Aucun rôle métier n’est déduit de la commande. Le traitement est identique pour toute commande ou script.
`--output-lines` limite les lignes de chaque flux affiché ; zéro retire cette
limite de lignes. La largeur reste limitée à 240 caractères par ligne avec
indication explicite. JSON/CSV conservent le texte capturé sans cette limite de
présentation. La capture réseau reste bornée par `--max-output-bytes` et toute
troncature de capture est signalée séparément. Pour une flotte volumineuse,
préférer `--output rapport.txt` ou JSON/CSV afin de garder un terminal lisible.
Ces options sont aussi conservées par les tâches schedule et les API Options.

Sur une sortie texte redirigée utilisant un encodage ancien, les caractères non représentables sont échappés explicitement pour éviter une erreur d’affichage ; le rapport UTF-8 écrit dans un fichier conserve ses caractères.


### Contrat de compatibilité OpenSSH

La sonde locale `python scripts/platform_gate.py --expected windows` (ou
`--expected linux`) exige que `ssh -G` confirme les options effectives du profil
strict : vérification des clés, mode non interactif, absence de transferts
implicites, de délégation d'agent et de commandes locales. Un code de sortie nul
avec des options absentes, ambiguës ou dangereuses est refusé. La sonde vérifie
également le stockage local ; elle n'ouvre aucune connexion et ne remplace pas
les recettes d'authentification, de SFTP et de console. Les plateformes non
exécutées restent non qualifiées. Les invariants du runtime sont indépendants
de l'option d'optimisation Python `-O` ou `-OO`.


### Encodage des outils de portabilité

La configuration temporaire de la sonde OpenSSH est écrite en UTF-8, y compris
lorsque Python utilise un encodage local Windows ancien. Les profils et chemins
Unicode restent pris en charge avec le mode UTF-8 Python activé ou désactivé.
Le générateur de définitions de service conserve les noms de fichiers et leur
contenu Unicode ; sur une sortie texte ancienne, les caractères impossibles à
représenter sont affichés avec des échappements explicites. Sur une sortie UTF-8,
le chemin exact est conservé. Une erreur réelle d'écriture reste signalée et
la génération refuse toujours d'écraser une définition existante. Elle ne
déclenche aucune inscription ni activation de service.


### Bornes natives et reconnexion — cycle33

Les canaux et tunnels directs POSIX partagent désormais le relais détenu par le
gardien déjà utilisé pour les commandes et procédures réseau. Le second démarrage
Python du proxy historique disparaît de ce chemin. Windows, les bastions et
GSSAPI conservent leur chemin existant ; confiance, limites, comptabilité et
durées maximales sont conservées. Les canaux préparent leur schéma de comptabilité
avant de pouvoir ouvrir une cible, comme les autres points d'entrée natifs.

Lors d'une reconnexion réseau, le délai de négociation observe le reçu privé
d'admission bornée du gardien, selon le protocole déjà utilisé pour les commandes.
Ce crédit local reste fini. Il ne prolonge ni le délai global de la procédure ni
la fenêtre globale de redémarrage ; un reçu invalide ou un gardien disparu arrête
la procédure. L'activation n'est jamais rejouée.

Les tests de durée native utilisent un enfant natif plutôt qu'un second Python
instrumenté. Les tests de nettoyage Linux attendent la disponibilité par FIFO
privée au lieu d'une boucle active. Les assertions et plafonds existants de
0,5 s, 0,4 s et 5 s sont conservés. Des régressions distinctes vérifient les
durées invalides avant allocation, le démarrage tardif refusé et les cinq états
d'admission. Aucun collecteur, seuil, exclusion ou contrôle CI n'est modifié.
Les résultats de qualification doivent être lus dans les preuves de cette
révision ; ces changements ne constituent pas une qualification du parc réel.


### Frontière du benchmark synthétique — cycle34

Le pair Python du benchmark de canal conserve le gardien natif réel, sa durée,
son admission et les assertions sur les octets. Seules les métadonnées du relais
SSH sont retirées à la frontière de ce faux transport, qui n'est pas OpenSSH.
La régression vérifie la requête réelle du gardien, la durée10s et le contenu
binaire4096octets ; les variantes sans gardien et sans durée sont refusées.
Le benchmark conserve ses opérations, sa concurrence, son plafond90s et ses
limites déclarées. Les99 fichiers du runtime applicatif restent identiques au
candidat précédent. Les mesures antérieures restent historiques ; les cinq
campagnes complètes doivent qualifier ce nouveau package avant actualisation.


### Reçu d'admission Windows — cycle35

Les lecteurs du reçu privé d'admission ouvrent une version complète avec le
partage de suppression Windows. Le gardien utilise ReplaceFileW sans indicateur
d'ignorance d'erreur pour remplacer la version précédente ; seule la première
publication sans destination utilise le déplacement atomique existant. Les
lecteurs déjà ouverts conservent leur instantané complet. Les autres ouvertures
de fichiers gardent leur partage habituel. Les droits de lecture, le refus des
liens de réanalyse et les ACL privées restent contrôlés ; les erreurs réelles de
lecture, allocation, accès ou remplacement sont propagées. Une allocation de
flux échouée libère le descripteur dont elle n'a pas pris possession.

La régression native maintient un lecteur ouvert pendant la publication. Le
scénario CLI original d'une cible inaccessible conserve ses deux tentatives,
ses statuts attendus et tous ses délais ; les variantes retirant le partage ou
le remplacement natif doivent échouer. Ce scénario reproduit une cause possible
de l'erreur observée en qualification Python 3.13 ; la trace de l'incident
initial ne permet pas d'en affirmer rétrospectivement la cause unique.

Aucun schéma, délai, crédit d'admission, seuil, collecteur de couverture,
exclusion ou contrôle CI n'est modifié. Les cinq campagnes complètes sur
l'archive courante restent requises avant toute actualisation locale du package.


### Sélection des adaptateurs d'admission — cycle36

Un test de contrat exerce explicitement les lecteurs et publications POSIX et
Windows sur chaque hôte, avec le même schéma strict et les mêmes appels attendus.
Ce test de sélection complète l'essai natif Windows avec lecteur réellement
maintenu ouvert ; il ne le remplace pas. Les variantes retirant le lecteur ou
le remplacement Windows sont refusées. Aucun code de production, collecteur,
seuil, délai, assertion antérieure ou contrôle CI n'est modifié. Les mesures
partielles du module ne qualifient pas le package ; les cinq campagnes complètes
doivent porter sur la nouvelle archive avant son actualisation locale.


### Scénarios de démarrage lent et observations de reconnexion — cycle37

Les essais de planification gardent une date future pendant le budget de
démarrage de dix secondes déjà accordé à la commande d'enregistrement. Un
scénario supplémentaire injecte 2,25 secondes dans ce même budget ; les plafonds
de dix et quinze secondes, le refus des dates passées et les assertions de
canari et d'absence de rejeu sont conservés.

Les essais réseau distinguent les demandes locales de connexion des sessions
effectivement atteintes par le simulateur distant. Un délai global peut arrêter
une tentative avant l'authentification ; il ne garantit pas une session distante.
Les nombres de demandes restent vérifiés exactement. Les sessions réussies ou
en erreur après dialogue gardent leur décompte exact ; les scénarios TIMEOUT
contrôlent séparément la borne des sessions distantes. Un démarrage local de
0,8 seconde est injecté dans la fenêtre globale existante, sans la prolonger.
Les plafonds natifs de reconnexion sont aussi vérifiés directement. L'activation
reste unique, les vérifications attendues et le plafond global restent contrôlés.

La revue avant/après conserve le refus initial d'un comportement correctement
arrêté par la fenêtre d'une seconde. Elle refuse les variantes avec une tentative
supplémentaire, une fenêtre élargie, un rejeu d'activation ou une date de nouveau
trop courte. Le code de production, les réglages d'authentification, les huit
contrôles figés et les cinq définitions de couverture ne changent pas. Les cinq
campagnes complètes sur la nouvelle archive restent requises avant copie locale.


### Local contention correction awaiting complete qualification

Shared admission polls now return pending without an internal SQLite busy wait. The existing bounded Python retry loop owns initialization/release waiting; its ten-second budget and 0.01-second cadence are retained. Connection timeout settings are restored after every poll. The original ten-process/two-slot test retains its twenty-second child deadline. Focused reviews passed on local Python 3.11–3.14 and Linux 3.12, including Python 3.11 -O/-OO; four unsafe variants were refused. These focused observations do not replace the five complete source-coverage campaigns.


### Native cleanup regression witness

The cleanup integration test now prepares a real guardian and native descendant behind a bounded readiness barrier, then releases the native leader inside the original 0.4-second transfer operation. Its SUCCESS, signal-mask, PID and descendant-destruction checks are retained. Separate unchanged tests still require real cold startup and genuinely running transfers to respect the original 0.4-second deadline. Preparation is bounded to four seconds and remains under parent/child instrumentation. This test-only change does not alter production startup or timeout behavior.


### Native peer admission witness

The relay integration fixture starts its unchanged four-second peer acceptance window after the real native guardian publishes admission. Local preparation remains independently bounded to four seconds; command and connection timeouts remain four and two seconds. All seven previous behavioral assertions, including the real OpenSSH banner and encrypted-byte accounting, remain active, with a real admission assertion added. Controlled delayed preparation fails with the previous fixture and succeeds with this one. This focused correction requires fresh whole-package qualification before source handoff.


### Report batching inside the admitted memory budget

Report batches retain the existing 32-record ceiling and every native worker reservation. Additional report slots use only unused admitted memory, each charged the existing conservative ordinary-worker buffer allowance. Native concurrency, SQLite FULL durability, spool size checks, cancellation and operation deadlines are unchanged. In one paired instrumented 10,001-transfer observation, actual report-worker calls fell from 10,001 to 1,429 and elapsed time from 254.758s to 160.000s; this is a local observation, not a statistical or universal guarantee. Fresh complete qualification remains mandatory.


### Report receiver compatibility

Custom report receivers retain the existing batch bound `min(32, workers)`. Only a receiver advertising `supports_spare_memory_batches = True` explicitly may accept batches funded by unused admitted memory. The native process report writer advertises this capability; worker reservations, the 32-record ceiling, durable SQLite acknowledgements and all timeouts remain unchanged. Absent, false and merely truthy capabilities retain the legacy bound.


### Bounded native connector inspection

The optional native connector is opened without waiting for a FIFO writer before its descriptor type is inspected. Special files remain rejected; owner, write permissions, no-follow protection, bounded help output and subprocess cleanup checks are retained. A real POSIX FIFO regression fails on the prior source and succeeds after this correction. No shell, authentication fallback, deadline extension or new dependency is introduced.
