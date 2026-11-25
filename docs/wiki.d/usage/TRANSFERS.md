# Push et pull — SWASSH 1.3.0

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / usage / Push et pull — SWASSH 1.3.0

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Commandes](#commandes)
- [Options rsync demandées](#options-rsync-demandées)
- [Repli SFTP et limites](#repli-sftp-et-limites)
- [Ressources et traçabilité](#ressources-et-traçabilité)
- [API asyncio](#api-asyncio)
- [Preview et intégrité (1.4.0)](#preview-et-intégrité-140)



## Commandes

```bash
# Fichier simple : nom absolu de destination distante.
swassh push -i flotte.txt --source ./config.ini --destination /etc/application/config.ini -u admin

# Synchronisation des contenus : conserver le slash final de la source.
swassh push -i flotte.txt --source ./release/ --destination /srv/application/ -u admin --format json -o push.json

# Récupération : un dossier distinct par identité SSH, jamais de collision entre serveurs.
swassh pull -i flotte.txt --source /var/log/application/ --destination ./collecte/ -u admin --format json -o pull.json
swassh pull -H srv01 srv02 --source /etc/application/config.ini --destination ./collecte/

# Budget global de 10 Mio/s, cadence et concurrence ajustables ; aucun accès réseau avec plan-only.
swassh push -i flotte.txt --source ./release/ --destination /srv/application/ --transfer-bandwidth-kib 10240 --transfer-timeout 1800 --plan-only
```

`push` ou `pull` doit être le premier argument. Les options SSH, inventaire,
ProxyJump, audit, formats et chemins de rapport sont communes à l’exécution.
Un répertoire distant doit se terminer par `/`. Les chemins distants sont absolus,
sans `..`, contrôles ni expansion de variables. Les glob distants ne sont pas
pris en charge pour les répertoires. Une source locale `release/` copie son
contenu ; `release` copie le dossier lui-même. Les dossiers parents de la
cible distante doivent déjà exister. Le push d’un fichier nomme le fichier
final et n’accepte pas une destination se terminant par `/`.

## Options rsync demandées

L’appel natif utilise exactement le profil `-avzPH --numeric-ids --delete`,
complété par `--protect-args`, `--safe-links`, `--no-devices`, `--no-specials`,
le retrait des bits setuid/setgid, un plafond `--max-alloc`, un plafond `--bwlimit`
et la configuration SSH privée. Les répertoires de pull sont privés au compte.
Ces protections excluent certains objets et attributs du mode archive ; voir
[le bilan du durcissement](../history/hardening/HARDENING.md). Les options de shell local ne sont jamais interprétées par Python.

| Option | Effet |
| --- | --- |
| `-a` | Mode archive : récursion, liens symboliques et attributs POSIX selon les permissions |
| `-v` | Sortie native capturée avec une taille bornée |
| `-z` | Compression dans le processus rsync natif |
| `-P` | Conservation des transferts partiels et progression native capturée |
| `-H` | Conservation des liens physiques ; consommation mémoire liée au nombre de fichiers |
| `--numeric-ids` | Identifiants UID/GID numériques ; changer le propriétaire nécessite les permissions correspondantes |
| `--delete` | Suppression, dans l’arbre de destination synchronisé, des entrées absentes de la source |

**`--delete` est actif.** Un push de répertoire peut donc supprimer des données
sur chaque serveur. Un pull synchronise uniquement le dossier local isolé de
la cible ; ses entrées supplémentaires peuvent être supprimées. Utiliser une
destination exclusivement dédiée à cette synchronisation. Ce n’est pas une
transaction de déploiement : une erreur peut laisser certains fichiers déjà
mis à jour ou supprimés. Un fichier simple n’entraîne pas de suppression de ses
voisins. Le statut de succès dépend du code de sortie du client natif.

## Repli SFTP et limites

Prérequis : OpenSSH `ssh`, `sftp`, et rsync >= 3.5.0 aux deux extrémités pour le
profil complet. Le serveur doit proposer le sous-système SFTP pour le repli.
Le client rsync est testé une fois, puis sa disponibilité distante est sondée
par une commande de lecture `rsync --version`. Sans rsync compatible, un
**fichier simple** utilise automatiquement SFTP. Les chemins de fichier distant
contenant des caractères glob passent aussi par SFTP afin de rester littéraux.
Sous Windows natif, le repli SFTP est utilisé pour les fichiers ; le mode
rsync complet nécessite un environnement POSIX, par exemple Linux ou WSL.

SFTP conserve les permissions et dates via `put/get -p`, mais ne peut pas
reproduire `--numeric-ids`, `-H`, la compression rsync ni `--delete`.
**Un répertoire sans rsync compatible échoue explicitement** : aucun miroir
incomplet n’est présenté comme une synchronisation réussie. Le backend et la
raison du repli figurent dans les rapports. Le fallback ne se produit jamais
après le début d’un transfert rsync, une erreur réseau, un timeout, une erreur
de clé d’hôte ou d’authentification. `--retries` doit rester à zéro.

SFTP pousse d’abord un fichier `.swassh-<identifiant>.part` dans le dossier distant,
puis effectue un renommage. Le remplacement d’un fichier existant dépend de
l’extension de renommage POSIX du serveur. `-f` demande fsync si le serveur
propose l’extension correspondante. Une rupture peut laisser le fichier partiel
distant : `transfer.temporary_path` indique le candidat à nettoyer après
vérification. Une annulation brutale peut empêcher l’écriture de ce reçu.
Un pull de fichier écrit un temporaire privé local puis publie par `os.replace` ;
une erreur laisse le fichier final précédent intact. Les fichiers sources
symboliques sont refusés pour le push simple ; les répertoires rsync suivent
la sémantique archive de rsync. Aucune commande sudo n’est ajoutée.

## Ressources et traçabilité

Le même moteur asyncio utilise une file et un nombre de workers bornés,
un rythme partagé entre sondes SSH et transferts, et un processus Python
séparé pour les rapports. Compression, chiffrement et tables de liens physiques
s’exécutent dans les programmes natifs, en dehors du GIL Python.

`--transfer-bandwidth-kib` est le budget **global par instance**, 10240 Kio/s par
défaut. Chaque worker reçoit la partie entière du budget divisée par le nombre
de workers planifié : le total des limites natives reste inférieur ou égal au
budget. SFTP utilise 4 requêtes de 32 Kio et une limite en Kbit/s correspondante.
La cadence avec ProxyJump tient compte de deux connexions par invocation.
L’estimation mémoire par worker ajoute 24 Mio au coût SSH ; ce n’est pas un
quota RSS. `-H` et les listes d’un grand arbre peuvent dépasser cette estimation :
mesurer sur l’arbre réel et réduire `-j`/augmenter le budget avec prudence.

Le push de fichier crée **une seule copie stable par flotte**, via un thread
I/O, pas une copie par serveur. Taille limitée à `--max-file-mib`, 1024 Mio
par défaut. Les sources modifiées pendant cette copie sont refusées. Cette
copie conserve dates, permissions sans setuid/setgid et UID/GID ; si les droits locaux empêchent
cette conservation, le transfert est refusé. Les autres attributs rsync
non inclus dans `-a` (ACL/xattrs) ne sont pas ajoutés.
Les répertoires sont synchronisés directement : figer leur contenu pendant
le déploiement. Leur taille totale n’est pas limitée par `--max-file-mib` ;
prévoir un **quota disque système** pour les collectes massives.

Le pull de fichier surveille toutes les 100 ms la somme des fichiers réguliers
de son staging privé, y compris les temporaires cachés rsync, puis vérifie la
taille du fichier final avant publication. Ce contrôle peut brièvement dépasser
le seuil ; un quota système reste nécessaire pour un plafond disque strict.
La surveillance ouvre chaque entrée sans suivre de lien dans le dossier épinglé,
puis lit les métadonnées du descripteur et le ferme même en cas d'erreur. Elle
refuse les fichiers spéciaux et les fichiers à plusieurs liens physiques. Cette
lecture évite les métadonnées mises en cache de `DirEntry.stat()`, dont le nombre
de liens vaut zéro sous Windows ([contrat Python](https://docs.python.org/3.14/library/os.html#os.DirEntry.stat)).
`--rsync-max-alloc-mib` limite une allocation rsync individuelle, 16 Mio par
défaut, réduit selon le budget disponible ; ce n’est pas une limite RSS totale. `--max-report-mib` limite uniquement le spool de rapport.

Les résultats réussis sont regroupés sous `transfer complete`, sans imprimer
les milliers de lignes de `-v`/`-P`. Les diagnostics d’échec restent bornés par
`--max-output-bytes`. JSON conserve un reçu `transfer` par cible : direction,
chemins, backend, taille finale du fichier (pas le volume réseau), repli et
partiel distant éventuel. CSV ajoute les colonnes `transfer_*`. Le schéma JSON
version 1 évolue par ajout de ce champ optionnel ; les anciens résultats
incluent `transfer: null`. Les chemins restent confidentiels dans les rapports.
L’audit ne contient pas ces chemins en clair : identifiant SHA-256 du transfert,
backend, statut, durée et taille. Rotation : 100 Mio, 3 archives gzip.

## API asyncio

```python
import asyncio
from swassh import FileSwarm, FileTransfer, TransferDirection, Options, TransferSettings

async def main():
    service = FileSwarm(Options(username="admin", log_file="audit.jsonl"),
                        TransferSettings(bandwidth_kib=10240))
    request = FileTransfer(TransferDirection.PUSH, "./release/", "/srv/application/")
    summary = await service.run_to_file(["srv01", "srv02"], request, "push.json")
    print(summary.counts)

if __name__ == "__main__":
    asyncio.run(main())
```

API synchrones : `push_to_file(hosts, source, destination, rapport, options,
format="json", settings=...)` et `pull_to_file(...)`. Utiliser le garde `main`
avec le processus écrivain. `FileSwarm.iter_results` permet de consommer les
reçus avec `contextlib.aclosing` ; `run` est réservé aux petits rapports.

Références primaires : [manuel rsync](https://download.samba.org/pub/rsync/rsync.1)
, [avis de sécurité rsync](https://rsync.samba.org/security.html)
et [manuel OpenSSH SFTP](https://man.openbsd.org/sftp).

La version 1.3.0 active aussi un canary de 1 cible par défaut, configurable par
`--canary 5`. La flotte est libérée après réussite de toute la première vague ;
sinon les cibles restantes sont skipped. Voir [CANARY.md](CANARY.md) pour la
sélection, les phases de rapport, les limites et les tests.

## Preview et intégrité (1.4.0)

--dry-run inspecte les ajouts/modifications/suppressions rsync en lecture seule,
avec agrégation en streaming et sans repli SFTP. Les dossiers de pull preview
doivent déjà exister. --verify-sha256 vérifie un fichier avant publication,
push ou pull, avec rsync ou SFTP. Le serveur doit fournir un shell POSIX et
sha256sum/shasum/openssl/digest. Un push vérifié reste privé en 0600 ; une erreur
ne rejoue jamais le transfert ni sa publication. Ces modes sont exclusifs et
l'intégrité d'arbre n'est pas implicite. Voir HARDENING-1.4.0.md pour les exemples,
les temporaires à inspecter et la politique de chemins distants fiables.
