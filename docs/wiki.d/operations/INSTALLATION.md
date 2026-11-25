# Installation pip et déploiement

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / operations / Installation pip et déploiement

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Installation directe](#installation-directe)
- [Déploiement en une commande](#déploiement-en-une-commande)
- [PATH et sessions](#path-et-sessions)
- [Publication et retour arrière](#publication-et-retour-arrière)



SWASSH est un paquet Python standard : wheel universelle, archive source PEP 517,
point d'entrée `swassh`, module `python -m swassh`. Il ne dépend d'aucun paquet
Python tiers à l'exécution. L'interpréteur requis est Python 3.11 ou ultérieur.
SSH et les outils de transfert restent des prérequis système distincts.

## Installation directe

```sh
python -m pip install dist/swassh-2.0.0-py3-none-any.whl
python -m swassh --version
python -m swassh setup-path
```

`python -m pip install .` et l'installation du `.tar.gz` utilisent le backend
PEP 517 fourni. Après publication sur l'index choisi :

```sh
python -m pip install swassh==2.0.0
```

Une wheel standard ne possède pas de hook post-installation arbitraire. Pip
installe le point d'entrée mais ne modifie pas les profils shell. Références :
[format wheel](https://packaging.python.org/en/latest/specifications/binary-distribution-format/),
[installation pip](https://pip.pypa.io/en/stable/cli/pip_install/).

## Déploiement en une commande

L'installateur livré orchestre pip puis `setup-path`. Il ne remplace pas pip.
Utiliser un environnement applicatif persistant pour préserver le Python système :

```sh
python3 scripts/install.py --package-version 2.0.0 --venv "$HOME/.local/share/swassh-venv"
```

Sur Windows :

```powershell
py scripts/install.py --package-version 2.0.0 --venv "$env:LOCALAPPDATA\SWASSH\venv"
```

La version doit être publiée sur l'index configuré dans pip. `PIP_INDEX_URL`
ou la configuration habituelle de pip permet un index privé ; conserver TLS
et les secrets hors des commandes partagées. Sans réseau, remplacer
`--package-version 2.0.0` par le chemin de la wheel locale. Les dépendances
de création d'un venv (`venv` et `ensurepip`, ou le paquet système correspondant)
doivent être disponibles. Le script refuse de réutiliser un répertoire existant
qui n'est pas un venv. Ne pas déplacer ni supprimer ce venv après déploiement.

Sans `--venv`, pip utilise le Python courant. `--user` demande le site utilisateur.
Les politiques de Python géré extérieurement sont respectées : aucun
`--break-system-packages` automatique. `--skip-path` est destiné aux déploiements
qui gèrent déjà l'environnement. Un échec pip arrête l'opération avant PATH ;
un échec de configuration PATH renvoie un code non nul, même si pip a réussi.

## PATH et sessions

Si le répertoire des commandes est déjà dans le PATH courant, aucun changement
n'est effectué. Sinon, POSIX sauvegarde puis remplace atomiquement les profils
du compte courant ; Windows sauvegarde puis complète `HKCU\Environment\Path`
en préservant son type. Aucun changement du PATH machine. Les contrôles refusent
les chemins non représentables et les profils dangereux.

Les sessions futures reçoivent la nouvelle configuration. Un processus enfant
ne peut pas remplacer l'environnement de son parent : un terminal déjà ouvert
doit être rouvert, ou utiliser l'export affiché sous POSIX. `python -m swassh`
reste utilisable avec l'interpréteur où le paquet est installé. Pour le venv
applicatif, utiliser son Python si nécessaire. Les services doivent préciser
le chemin absolu de cet interpréteur dans leur configuration.

Si une autre installation de `swassh` précède la nouvelle dans PATH, la
configuration refuse de déclarer le déploiement réussi : résoudre ce conflit
ou utiliser le chemin explicite de l'interpréteur applicatif. Elle ne remplace
pas silencieusement une installation appartenant à un autre environnement.

`setup-path --app-venv` autorise explicitement la persistance du PATH d'un venv
applicatif ; l'installateur l'utilise avec `--venv`. Les venv de développement
restent refusés par défaut pour éviter un PATH durable vers un répertoire jetable.

## Publication et retour arrière

Construire avec `python scripts/build.py`, puis exécuter les contrôles CI,
`python scripts/validate_installation.py` et `python scripts/validate_deployment.py`.
Le workflow de publication existant attend le succès de la matrice CI et vérifie
la correspondance tag/version. Publier les distributions requiert les droits sur
le projet PyPI ou l'index privé. Aucune publication distante n'est effectuée par
la fabrication du ZIP. L’état de qualification de la version 2.0.0 est détaillé dans `VALIDATION.md`.

Pour revenir en arrière, arrêter les invocations et le worker, puis réinstaller
la wheel conservée avec le même Python applicatif. Conserver les bases privées
de planification, de workflows et d’idempotence. rc4 ne lit pas les nouveaux
workflows/intents ; aucune descente destructive ne doit effacer un état ambigu. Pour annuler PATH, restaurer le profil depuis sa sauvegarde
POSIX ; sous Windows, les fichiers privés `.swassh/path-backups/path-*.json`
contiennent l'existence antérieure, la valeur et le type du PATH à restaurer
dans les variables utilisateur. Vérifier les modifications ultérieures avant
restauration pour ne pas les écraser. Retirer l'entrée PATH avant de supprimer
un environnement applicatif.
