# Procédures réseau multiconstructeurs — 1.8.0rc2

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / usage / Procédures réseau multiconstructeurs — 1.8.0rc2

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Périmètre exact](#périmètre-exact)
- [CLI et bibliothèque](#cli-et-bibliothèque)
- [Contrat de procédure](#contrat-de-procédure)
- [Reconnexion explicite après redémarrage firmware](#reconnexion-explicite-après-redémarrage-firmware)
- [Arrêt sûr et limites importantes](#arrêt-sûr-et-limites-importantes)
- [Impact, qualification et retour arrière](#impact-qualification-et-retour-arrière)
- [Durcissement des sessions existantes](#durcissement-des-sessions-existantes)
- [Références constructeur vérifiées](#références-constructeur-vérifiées)



Cette version candidate ajoute un moteur de dialogue réseau à OpenSSH, sans
dépendance Python externe. Il utilise les budgets interprocessus, travailleurs
bornés, canary et rapports de SWASSH. Les commandes historiques restent inchangées.
Ce moteur n'est pas une certification universelle des équipements.

## Périmètre exact

| Profil explicite | Famille de dialogue visée |
| --- | --- |
| `cisco_ios` | Cisco IOS |
| `cisco_iosxe` | Cisco IOS-XE |
| `cisco_nxos` | Cisco NX-OS |
| `juniper_junos` | Juniper Junos |
| `aruba_aoscx` | Aruba AOS-CX |
| `aruba_procurve` | ArubaOS-Switch / ProCurve |
| `aruba_os` | ArubaOS, contrôleurs Wi-Fi |
| `huawei_vrp` | Huawei VRP, invite utilisateur puis vues de configuration |
| `fortinet_fortios` | FortiGate / FortiOS |

Ces profils reconnaissent des familles d'invites et des erreurs CLI. Ils ne
génèrent pas des commandes universelles de configuration, restauration ou mise à
jour. Le banc natif utilise un vrai serveur OpenSSH et des équipements simulés :
il prouve le transport et le protocole testé, pas la compatibilité matérielle.
Les variantes d'invite, modèles, versions, VDOM et contextes non testés doivent
être qualifiés avant exploitation. Pas de détection automatique approximative.

## CLI et bibliothèque

Depuis la racine de la livraison, la commande suivante prépare une revue locale,
sans connexion et sans commande distante :

```sh
swassh network -i hosts.txt --procedure examples/network/cisco-inventory.json
```

La sortie JSON contient les cibles, toutes les commandes et attentes, les bornes
de ressources et `approval_sha256`. Après revue, utiliser la valeur exacte de ce
champ avec `--apply`. Le digest change si la procédure, les utilisateurs/cibles
résolus ou leur ordre changent. Ce mécanisme ne constitue ni une signature ni un
contrôle d'accès ; l'opérateur doit disposer de ses propres droits SSH.

```python
import asyncio
from swassh import NetworkSwarm, Options

async def inspect_plan():
    service = NetworkSwarm.from_file(
        "examples/network/cisco-inventory.json", Options(concurrency=4))
    print(service.plan(["router.lab.example"]))

asyncio.run(inspect_plan())
```

Pour exécuter en bibliothèque, appeler `await service.run(hosts, approval=digest)`
ou `await service.run_to_file(hosts, path, "json", approval=digest)` avec le digest
revu. Le second flux conserve les rapports bornés sur disque pour les grands
inventaires. L'API ne doit pas automatiquement approuver un plan non fiable.
CLI : `--format text|json|csv`, `--output`, `--hide-output`, `--output-lines`,
`--canary`, profils de connexion, bastion et budgets gardent leur rôle habituel.
`--check` vérifie localement le schéma et les prérequis ; il ne certifie pas les
commandes du constructeur. Une procédure est exécutée sur un lot homogène ;
utiliser des procédures et lots séparés pour les autres familles/versions.

Les modes existants `run`, `session`, `shell`, `push`, `pull` et `schedule` restent
disponibles. `schedule` planifie toujours les commandes SSH historiques : il ne
sérialise pas encore les nouvelles procédures réseau. Un ordonnanceur externe
peut invoquer la CLI réseau avec le fichier figé et son digest approuvé.

## Contrat de procédure

Fichier JSON UTF-8 strict, au maximum 1 MiB, sans clés inconnues ni dupliquées.
Champs : `platform`, `operation`, `steps` ; chaque étape possède `stage`,
`command`, `expect` (liste de chaînes littérales) et éventuellement `until`.
Au maximum 1 000 étapes, 4 096 caractères par commande, 16 attentes de 512
caractères par étape. Aucun retour à la ligne ou contrôle terminal dans les
commandes. Aucun code Python ni expression régulière fourni par le plan.

Ordre des étapes : `identify`, `backup`, `prepare`, `transfer`, `checksum`,
`configure`, `activate`, `verify`, `persist`. Plusieurs étapes par stade sont
autorisées. Les stades obligatoires doivent avoir au moins une attente non vide.

| Opération | Stades obligatoires |
| --- | --- |
| `administration` | identify |
| `configuration` | identify, backup, configure, verify |
| `file` | identify, transfer, checksum, verify |
| `firmware` | identify, backup, transfer, checksum, activate, verify |

Le libellé `administration` ne garantit pas qu'une commande soit en lecture
seule. Toute procédure nécessite la même revue avant exécution. L'utilisateur
doit définir une sauvegarde réellement restaurable, les conditions de succès,
les vérifications métier et, si nécessaire, la persistance de configuration.
Les commandes de fichiers sont celles de l'équipement (par exemple récupération
depuis un dépôt autorisé) ; ce flux ne transforme pas automatiquement `push/pull`
en SCP propriétaire. Les transferts historiques restent utilisables lorsque la
cible prend en charge leurs protocoles et exigences.

Pour `file` et `firmware`, `image_sha256` est obligatoire et doit être attendu
dans le stade `checksum`. Le moteur vérifie un digest hexadécimal complet dans
la réponse, indépendamment de la casse, après retrait de l'écho de commande.
Si `exact_lines: true` est choisi pour cette étape, la ligne entière et sa casse
doivent correspondre exactement, comme pour les autres attentes de ce mode.
Cela atteste la réponse du CLI authentifié, pas la signature du fournisseur ni
la compatibilité de l'image. La vérification locale des sources et signatures
constructeur reste un prérequis de la procédure d'exploitation.

Pour `firmware`, `model`, `current_version`, `target_version` et `recovery` sont
obligatoires. Les étapes `identify` doivent vérifier les chaînes de modèle et
version actuelle ; `verify` doit vérifier la version cible distincte. `recovery`
documente la reprise hors bande : le moteur ne l'exécute pas automatiquement.

`until` désigne une question exacte de confirmation, sans expression régulière.
L'étape suivante contient la réponse explicitement revue ; une chaîne vide est
admise uniquement après une telle question. La dernière étape doit revenir à
une invite d'équipement. Aucun mot de passe enable n'est injecté : utiliser un
compte avec les privilèges nécessaires. Aucun secret ne doit figurer dans la
procédure ; l'authentification utilise les clés, le fournisseur externe de mot
de passe ou GSSAPI déjà disponibles selon la cible.

## Reconnexion explicite après redémarrage firmware

Une procédure firmware peut déclarer `reconnect` avec exactement les trois
champs `attempts` (entier 1 à 60), `timeout` (1 à 3 600 secondes) et `interval`
(0,1 à 60 secondes). Une seule étape `activate` porte alors `reboot: true` et
une attente non vide attestant l'acceptation. Elle attend ensuite la fermeture
SSH, même si une invite revient temporairement. Une coupure sans cette preuve
échoue. Sans ces champs, le comportement de rc1 et son digest restent inchangés.

Les étapes suivantes sont exclusivement `verify`, sans question interactive.
Le modèle et la version actuelle dans `identify`, puis le modèle et la version
cible dans `verify`, doivent être attendus avec `exact_lines: true`. Les champs
de modèle/version contiennent alors les lignes complètes attendues dans la
sortie réelle, hors écho de commande. Une sous-chaîne ne suffit pas.

L'activation n'est jamais rejouée. Seule une connexion encore dépourvue de
commande de vérification peut être retentée lorsque le serveur est injoignable
ou que son invite tarde à arriver. Clé hôte inconnue/modifiée, authentification
refusée, sortie invalide et erreur de vérification bloquent immédiatement.
Les échecs SSH avant la première commande sont classés à partir du diagnostic
privé du client, notamment `timeout` ou `interrupted`, plutôt qu'un échec
générique. Une sortie distante ne peut pas autoriser le rejeu d'une commande.
Après l'envoi de la première commande de vérification, aucune nouvelle tentative
n'est permise, même si la connexion se coupe. Le libellé `verify` ne garantit pas
qu'une commande opaque soit en lecture seule : sa revue reste obligatoire.

`--command-timeout` borne toute la procédure ; `reconnect.timeout` borne la
reconnexion et la vérification ; `--connect-timeout` borne chaque nouvelle
attente d'invite. Avant chaque tentative, une temporisation exponentielle
utilise `interval`, un multiplicateur plafonné à 8 et une dispersion aléatoire
de 0 à 25 %, avec un délai maximum de 60 secondes. Les délais globaux prévalent.
Le gardien précédent est fermé avant toute nouvelle réservation du budget
partagé. Le plafond de sortie est commun à toutes les connexions et l'identité
d'invite reste celle du premier dialogue. Le compteur de tentatives de procédure
reste à 1 ; les attentes de reconnexion apparaissent dans la sortie du rapport.

Le simulateur et ses procédures exécutables sont dans `tests/network_fixture.py`
et `tests/test_network_reboot.py`. Ils ne sont pas des recettes constructeur.
La reconnexion est implémentée ; la qualification des mises à jour firmware sur
chaque modèle/version réel reste **NON TERMINÉE**. Pas de rotation automatique
de clé hôte, de persistance après reboot ni de restauration universelle.

## Arrêt sûr et limites importantes

- Une session interactive neuve par hôte, avec reconnexion uniquement selon le
  contrat firmware explicite ci-dessus. Pas de pool entre invocations.
- Délai global `--command-timeout`, également imposé au client natif par le
  gardien indépendant. Écho des commandes exigé ; un écho ne vaut jamais preuve
  de réussite. Invites liées à l'identité initiale, sans changement de hostname.
- Toute erreur reconnue, réponse manquante, pagination, sortie hors budget,
  encodage invalide ou contrôle terminal non pris en charge arrête la procédure.
  Les questions ne sont jamais confirmées par défaut. Préparer explicitement
  la pagination avec les commandes adaptées au système.
- Aucun retry de commande. Le canary bloque la flotte s'il échoue. Après le
  canary, plusieurs hôtes peuvent déjà être en cours lorsqu'un autre échoue :
  il ne s'agit pas d'une transaction distribuée ni d'un rollback global.
- Les sorties terminées et les erreurs de commande capturées sont conservées
  dans les rapports ; le budget réseau est agrégé sur la procédure. Les flux
  distants PTY sont fusionnés. Les commandes et frappes ne sont pas ajoutées
  au journal d'audit ; celui-ci reçoit le digest de procédure. Des sorties de
  configuration peuvent contenir des secrets : protéger rapports et sauvegardes.
- Une coupure non prévue ou une vérification post-redémarrage incomplète produit
  un état distant inconnu et un échec, jamais un succès supposé.
- Pas de rollback universel : ne pas appliquer de commandes inverses après une
  rupture ambiguë. Utiliser la console hors bande et la procédure constructeur.
- SSH uniquement ; aucun ajout de Telnet, SNMP, NETCONF, RESTCONF, API constructeur
  ou émulation d'algorithmes SSH obsolètes. Aucun contrôle de clé hôte affaibli.

## Impact, qualification et retour arrière

| Domaine | Changement / invariant |
| --- | --- |
| Contrats | Sous-commande et API nouvelles ; contrats historiques conservés |
| Architecture | Modèles immuables domaine, adaptateur OpenSSH, façade d'orchestration |
| Ressources | Budgets partagés et gardiens existants ; tâches et buffers bornés |
| Sécurité | Plan figé, validation stricte, preuve sans écho, arrêt sans rejeu |
| Résilience | Session fermée et descendants arrêtés avant libération des ressources |
| Dépendances | Bibliothèque standard uniquement ; OpenSSH natif inchangé |
| CI | Découverte des nouveaux tests, porte native SSH incluant le simulateur |
| Compatibilité | Aucun matériel constructeur ni firmware réel certifié localement |

Avant exploitation : exécuter chaque procédure en laboratoire sur le modèle et
la version exacts, vérifier les sauvegardes et leur restauration, injecter
refus de commande, perte réseau, saturation et coupure, puis canary et lots
bornés. Comparer les configurations avant/après et les contrôles métier.
Les contrôles locaux et leurs exclusions sont consignés dans `VALIDATION.md`.

Pour revenir à rc1, arrêter les invocations, vérifier leur état distant puis
réinstaller la wheel 1.8.0rc1 conservée. Les procédures avec les nouveaux champs
sont refusées par rc1 ; ne pas retirer ces champs pour tenter une reprise.
Pour revenir à 1.7.0 : arrêter les invocations réseau, vérifier leur état distant,
puis réinstaller la wheel 1.7.0 conservée. Les procédures réseau sont nouvelles
et ne s'exécutent pas avec cette ancienne version. Une réinstallation du client
ne restaure ni une configuration distante ni un firmware. Le durcissement de
fermeture des sessions décrit ci-dessous n'est pas présent en 1.7.0.

## Durcissement des sessions existantes

La sortie de contexte `Session` annule et attend la commande active, interdit
aux appels en attente d'ouvrir un nouveau canal, puis libère les réservations.
Seule la tâche ayant ouvert le contexte peut le fermer. La fermeture du maître
est partagée par les appels concurrents et protégée des annulations répétées.
Les tests vérifient l'ordre réel des événements et la propagation d'annulation.

## Références constructeur vérifiées

- [Cisco IOS-XE, fichiers de configuration](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/system-management/system-management/m_cm-config-files-0.html).
- [Cisco NX-OS, checkpoints et restrictions du rollback](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus6000/sw/system_management/7x/b_6k_System_Mgmt_Config_7x/configuring_rollback.html).
- [Junos, commit et confirmation](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/commit.html).
- [Huawei, sauvegarde de configuration](https://info.support.huawei.com/hedex/api/pages/EDOC1000053358/YEF0907R/25/resources/en-us_task_0141547205.html).
- [Fortinet, différences entre inspection et sauvegarde restaurable](https://community.fortinet.com/fortigate-3/technical-tip-configuration-differences-through-gui-or-security-fabric-automation-and-show-command-207000).

Ces références expliquent des différences de sémantique ; elles ne constituent
pas une validation de toutes les versions ou de commandes firmware absentes.
