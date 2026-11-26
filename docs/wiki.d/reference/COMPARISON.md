# Comparatif fonctionnel — 23 octobre 2026

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / reference / Comparatif fonctionnel — 23 octobre 2026

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Lecture pour le projet](#lecture-pour-le-projet)

Cette comparaison conserve son état historique rc4 et ses sources datées. La
version 2 ajoute depuis [idempotence](../usage/CONVERGENCE.md),
[workflows](../usage/WORKFLOWS.md), [canaux/tunnels](../usage/CHANNELS.md) et
[plafond chiffré](../operations/BANDWIDTH.md). Les colonnes concurrentes ci-dessous
ne constituent pas une nouvelle vérification de leurs versions actuelles.



Comparaison des périmètres documentés, sans benchmark de vitesse entre produits.
Une bibliothèque de transport n’a pas le même rôle qu’un orchestrateur de flotte.
Les caractéristiques SWASSH correspondent aux sources 1.8.0rc4 ; les limites de
qualification restent celles de VALIDATION.md.

| Critère | SWASSH 1.8.0rc4 | ssh2-python | Paramiko | Netmiko | Fabric |
| --- | --- | --- | --- | --- | --- |
| Usage principal | Exécution et transferts sur flottes de serveurs depuis un bastion | API bas niveau autour de libssh2 | Bibliothèque SSH Python généraliste | Automatisation des CLI d’équipements réseau | Tâches d’administration et déploiement en Python |
| Transport | Clients OpenSSH système | libssh2 natif | Implémentation SSH Python, composants cryptographiques externes | Principalement Paramiko pour SSH | Paramiko pour SSH |
| Parallélisme | Travailleurs bornés, cadence, admission adaptative plafonnée | Mode non bloquant ; orchestration à construire | Orchestration multi-hôtes à construire | Orchestration à apporter par le programme ou un outil tiers | SerialGroup et ThreadingGroup |
| Protection commune à plusieurs invocations | Budget interprocessus partagé du bastion | À ajouter autour du transport | À ajouter autour du transport | À ajouter à l’orchestrateur | À ajouter aux groupes/tâches |
| Déploiement progressif | Canary intégré, flotte bloquée en cas d’échec | À programmer | À programmer | À programmer ou déléguer à l’orchestrateur | À programmer dans les tâches |
| Commande distante | CLI run et API | Channel.execute | exec_command | send_command, commandes de configuration | Connection.run et tâches fab |
| Inventaire et paramètres par hôte | Liste/fichier et profils JSON stricts | Objets à construire | Paramètres par SSHClient | Paramètres par équipement | Connections, configuration et listes d’hôtes |
| Saut par bastion | ProxyJump avec identité distincte | Canaux TCP à orchestrer | Canaux/socket ou ProxyCommand | Configuration SSH/proxy selon intégration | gateway et configuration SSH |
| Entrée standard | Fichier binaire borné ou réponses asynchrones par hôte via interact | Écriture dans le canal | Flux stdin retourné par exec_command | Écriture de canal, dialogue de CLI | in_stream du moteur Invoke |
| Encodage des sorties | Codec global ou par profil | Décodage des octets par l’application | Décodage des octets par l’application | Paramètre encoding | Paramètre encoding du moteur d’exécution |
| Planification persistante | Sous-commande schedule, état des tâches | Planificateur externe | Planificateur externe | Planificateur externe | Planificateur externe pour lancer les tâches |
| Prévisualisation des suppressions | Intégrée au flux rsync --delete | À construire | À construire | Selon équipement/opération, pas un équivalent générique | À construire dans la tâche |
| Rapport consolidé JSON/CSV | Intégré, statuts et regroupement des réponses | À construire | À construire | À construire à partir des résultats | GroupResult ; export métier à construire |
| Réutilisation de session | Contexte Session et CLI session, un hôte, POSIX, durée bornée ; run reste sans multiplexage par défaut | Plusieurs canaux par session | Plusieurs canaux par transport | Connexion d’équipement réutilisable | Connection réutilisable |
| Clé/agent, mot de passe | Oui ; fournisseur externe pour mot de passe | API dédiées | Oui | Oui | Oui via configuration/Paramiko |
| Kerberos/GSSAPI | Mode explicite, client compatible et ticket requis ; sans délégation | Non exposé dans l’API Session consultée ; ne pas confondre avec ssh-python/libssh | Retiré depuis Paramiko 5.0 ; disponible en 4.x | Pas une capacité générale à déduire de Paramiko ; dépend de l’intégration | Dépend de Paramiko ; absent avec Paramiko 5.x |
| Transferts | push/pull, rsync ou SFTP selon le cas, vérification SHA-256 et prévisualisation des suppressions rsync | Primitives SFTP/SCP | SFTP | Transferts et vérifications dépendant des plateformes | get/put via SFTP |
| Sorties | Rapport groupé, JSON/CSV, capture bornée, affichage final par défaut ; JSONL progressif facultatif | Lecture des canaux à gérer | Flux/canaux à traiter | Gestion des invites et nettoyage des sorties réseau, intégration de parseurs | Résultats par connexion, diffusion et masquage configurables |
| Résilience de flotte | Délais, annulation, canary, reprise limitée aux cas sûrs, tâches persistantes | Primitives d’erreur et de délai ; politique à construire | Exceptions et délais ; politique à construire | Délais et logique propre aux CLI ; politique de flotte à construire | Exceptions et résultats groupés ; politique métier à écrire |
| Dialogue interactif/équipements réseau | shell/PTY et profils de dialogue réseau avec procédures explicites ; reconnexion après redémarrage bornée ; qualification matérielle incomplète | Canaux bas niveau | Shell/PTY programmables | Point fort : modes de configuration et particularités constructeurs | Shell/PTY et tâches interactives selon configuration |
| Coût d’intégration | Client/AsyncClient, flux gérés, erreurs typées ; clients natifs à installer | Faible niveau, intégration plus importante | Bon contrôle en Python, orchestration à développer | Très adapté au réseau multi-constructeurs | Très adapté aux workflows applicatifs personnalisés |

« À ajouter » signifie que la capacité ne fait pas partie de l’interface
documentée examinée, pas qu’elle serait impossible à développer.

## Lecture pour le projet

Pour le besoin actuel, conserver SWASSH comme orchestrateur évite de reconstruire
les budgets partagés, canary, rapports et planification. Son coût est celui des
processus OpenSSH et de leur encadrement ; il faut le mesurer sur le parc réel.
Netmiko conserve une couverture de particularités constructeurs plus étendue ;
les profils réseau SWASSH exigent des procédures explicites et une qualification
par modèle/version (docs/wiki.d/usage/NETWORK.md). Fabric est intéressant pour des recettes Python complexes ; Paramiko
pour intégrer finement SSH dans une application ; ssh2-python pour construire un
moteur de transport natif non bloquant avec une orchestration maîtrisée.

Le scénario SWASSH de 50 000 hôtes simulés ne permet de conclure ni à une
supériorité de débit ni à une supériorité de fiabilité sur ces bibliothèques.
Un comparatif de performances exigerait les mêmes machines, versions, algorithmes,
authentifications, concurrence, volumes de sortie, fautes injectées et répétitions.

Sources primaires consultées :

- [ssh2-python : conception et API](https://ssh2-python.readthedocs.io/en/latest/), [Session](https://ssh2-python.readthedocs.io/en/stable/session.html).
- [Paramiko : SSHClient, authentification, canaux et SFTP](https://docs.paramiko.org/en/4.0/api/client.html).
- [Netmiko : projet officiel](https://github.com/ktbyers/netmiko), [API](https://ktbyers.github.io/netmiko/docs/netmiko/index.html).
- [Fabric : groupes et résultats](https://docs.fabfile.org/en/stable/api/group.html), [authentification](https://docs.fabfile.org/en/stable/concepts/authentication.html).
- [Fabric : connexions et passerelles](https://docs.fabfile.org/en/stable/api/connection.html), [ssh2-python : canaux](https://ssh2-python.readthedocs.io/en/latest/channel.html), [Netmiko : connexions](https://ktbyers.github.io/netmiko/docs/netmiko/base_connection.html).
- [Invoke : flux, encodage et résultats utilisés par Fabric](https://docs.pyinvoke.org/en/stable/api/runners.html).

La version rc3 ajoute Client/AsyncClient pour intégrer le SSH parallèle en quelques lignes,
avec transports distincts, erreurs structurées et fermeture des flux. Voir [SDK](../usage/PYTHON-SDK.md).
Les canaux binaires publics et tunnels ne sont pas encore exposés ; ne pas présenter
le SDK comme un remplacement complet de toutes les primitives Paramiko.
Correction documentaire GSSAPI : [historique Paramiko](https://www.paramiko.org/changelog.html).

La rc4 ajoute interact/interact_stream : fragments de sortie en direct et
réponses stdin bornées par hôte, sans paquet Python tiers. Il ne s’agit pas
d’une API de canaux SSH bruts ni de tunnels. Les comparaisons de vitesse restent
NON EXÉCUTÉES ; les résultats de simulation interne ne constituent pas un
benchmark contre Paramiko ou Parallel-SSH.
