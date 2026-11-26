# Critères d'acceptation : SSH parallèle et intégration applicative

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / reference / Critères d'acceptation : SSH parallèle et intégration applicative

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Dépendance explicite entre deux opérations](#dépendance-explicite-entre-deux-opérations)
- [Procédures de qualification restantes](#procédures-de-qualification-restantes)
- [Intégration applicative et préoccupations liées à Paramiko](#intégration-applicative-et-préoccupations-liées-à-paramiko)
- [Impact et retour arrière de rc3](#impact-et-retour-arrière-de-rc3)
- [Extension rc4](#extension-rc4)



Cette matrice traduit les risques fournis par l'utilisateur en exigences SWASSH.
Elle n'attribue pas indistinctement ces défauts à la CLI PSSH, à la bibliothèque
parallel-ssh ou à toutes leurs versions. Les contrôles réellement exécutés et
leurs exclusions sont consignés dans VALIDATION.md.

| Risque | Contrat SWASSH | État et limite |
| --- | --- | --- |
| CPU/mémoire du bastion saturés | Nombre borné de travailleurs, estimation mémoire conservatrice, budget interprocessus, capture bornée et export sur disque | Implémenté ; ce n'est ni un quota CPU du système ni une preuve de capacité du parc réel |
| Trop de descripteurs et sockets | Plan tenant compte des descripteurs disponibles, plafond de connexions partagé et cadence d'ouverture | Implémenté selon capacités OS ; les autres programmes du bastion peuvent encore consommer des ressources |
| Réseau du bastion saturé | Concurrence/cadence bornées, plafond des transferts, dimensionnement et mesures | Relais chiffré commun émission/réception implémenté ; [portée exacte](../operations/BANDWIDTH.md). QoS physique, autres programmes et répartition entre bastions restent externes, sans qualification de parc |
| Action répétée sans tenir compte de l'état | Contrôle métier explicite avant mutation, puis vérification ; pas de rejeu d'une commande ambiguë | [DesiredState](../usage/CONVERGENCE.md) implémenté : contrôles déclarés, intent durable et vérification sans rejeu ; vérité métier à qualifier |
| B exécuté malgré un échec de A | En Python, attendre A avec check=True avant de lancer B ; échec/canary bloque la suite | [WorkflowRunner](../usage/WORKFLOWS.md) implémenté : DAG, checkpoints, branches bloquées et reprise explicitement vérifiée |
| Interaction manuelle bloquée sur une grande flotte | Délais bornés, modes non interactifs, PTY explicite, dialogues réseau revus et aucune réponse automatique inconnue | MFA humain par cible non automatisé ; un agent ou fournisseur externe doit préparer les authentifications compatibles |
| Sorties illisibles pendant une panne | Rapport groupé, statuts distincts, détails JSON/CSV, flux de résultats et erreurs typées | Implémenté ; les sorties contenant des secrets doivent rester protégées |
| Coupure au milieu d'une mutation | État inconnu explicite, pas de rejeu aveugle ; retries pré-authentification, reconnexion firmware bornée | Pas de reprise universelle au milieu d'un script ; exige un protocole applicatif de checkpoints/idempotence |
| Authentifications hétérogènes | HostProfile pour identité, clés, known_hosts, délais, encodage et méthode ; fournisseur externe de mot de passe, GSSAPI/OpenSSH | Implémenté selon le client/serveur ; rotation automatique de certificats et parcours MFA arbitraires non fournis |

## Dépendance explicite entre deux opérations

```python
import asyncio
from swassh import AsyncClient

async def inspect_in_order():
    client = AsyncClient("serveur-a")
    first = await client.run("uname -r", check=True)
    second = await client.on("serveur-b").run("uname -r", check=True)
    return first, second

asyncio.run(inspect_in_order())
```

La deuxième opération n'est appelée qu'après réussite de la première. Ce code
n'est pas un ordonnanceur durable : après crash, il ne doit pas être relancé
aveuglément avec des commandes de mutation. Un contrôle métier doit déterminer
l'état réel. Un code de sortie zéro d'un script ne prouve pas à lui seul que
son effet est idempotent ou que le changement est restaurable.

## Procédures de qualification restantes

- Charge réelle : sur un parc autorisé, augmenter les lots après canary ; mesurer
  CPU, RSS cumulée, descripteurs, sockets, débits, latences et erreurs. Vérifier
  les plafonds avec plusieurs invocations concurrentes et une charge extérieure.
  Attendu : backpressure ou refus explicite, aucune croissance non bornée.
- Reprise métier : fournir un état observable, un contrôle sans effet de bord,
  une action et une vérification. Injecter une coupure avant/après chaque effet.
  Attendu : aucun doublon de mutation ; tout état ambigu reste bloqué.
- Authentification : tester les profils réellement utilisés avec leurs versions
  OpenSSH, agents, fournisseurs et tickets. Simuler clé inconnue, changement de
  clé, ticket expiré et fournisseur indisponible. Attendu : erreur distincte,
  aucun fallback qui affaiblit l'authentification.

Prérequis : parc/laboratoire autorisé, accès hors bande, mesures système et
procédures restaurables. Ces essais ne peuvent pas être remplacés par la
simulation de 50 000 hôtes. Aucune affirmation « tous les manquements corrigés »
n'est justifiée tant que les éléments NON TERMINÉ ci-dessus subsistent.

## Intégration applicative et préoccupations liées à Paramiko

Ces critères décrivent les choix de SWASSH, sans attribuer à toutes les versions
concurrentes les mêmes limites. Paramiko fournit déjà des gestionnaires de
contexte, des canaux et des paramètres SFTP ; leur présence ne remplace pas
une orchestration de flotte ou un pilote de dialogue réseau.

| Préoccupation | Réponse intégrée | Preuve ou limite |
| --- | --- | --- |
| Gestion SSH et chiffrement en Python | Transport par processus OpenSSH système, aucune dépendance Python tierce | Les coûts de processus existent ; aucune supériorité mesurée sur Paramiko ou ssh2-python |
| Complexité du premier appel multi-hôtes | Client, inventaire, run, rapport commun et erreurs typées | Tests SDK et installation des exports publics |
| Intégration asyncio | AsyncClient, flux asynchrone géré, annulation et nettoyage attendus | Tests d'annulation répétée et de fermeture ; les appels utilisateur doivent rester non bloquants |
| Lecture manuelle des flux et fuite de ressources | Moteur de capture borné et contexte de flux explicite | Callbacks et [SSHChannel](../usage/CHANNELS.md) implémentés ; qualification SSH authentifiée et matérielle distincte |
| Commandes réseau sans code de sortie standard | Profils, dialogue, preuves et procédures spécifiques | Simulation SSH native ; qualification sur matériels réels : NON EXÉCUTÉ |
| Débit SFTP et transferts volumineux | Outils système, limites, intégrité et rsync selon capacités | Aucun benchmark comparatif ; dimensionnement réseau/serveur nécessaire |
| Intégration bas niveau dans une application | Options par opération/hôte, transport injecté, Session explicite | Callbacks, SSHChannel et SSHTunnel intégrés ; loopback et cycle de vie bornés, limites de qualification explicites |

## Impact et retour arrière de rc3

| Domaine | Changement / invariant | Vérification |
| --- | --- | --- |
| CLI et formats | Aucun remplacement des commandes ni des schémas de rapports | Suite historique CLI/rapports |
| API Python | Exports ajoutés ; Swarm existant conservé | Tests SDK, architecture et installation |
| Concurrence | Réservation propre à chaque opération SDK, file supplémentaire bornée | Régression d'héritage de réservation et backpressure |
| Erreurs et données | Exceptions à message sans sortie sensible, résultat attaché | Tests de décodage et d'échec ; protéger les rapports attachés |
| Cycle de vie | Arrêt attend le nettoyage, échec de fermeture visible | Régression avant/après et annulations répétées |
| Packaging | Aucun paquet Python ajouté, construction standard uniquement | Contrôle des imports et installations hors ligne |

Retour arrière : arrêter les opérations en cours, contrôler l'état distant,
puis réinstaller la wheel rc2 conservée. Une application utilisant les nouveaux
exports doit revenir à sa version compatible rc2. Aucune migration des données
persistantes n'est introduite. Un retour arrière local n'annule pas les effets
des commandes déjà exécutées sur les cibles.

## Extension rc4

interact et interact_stream ajoutent des callbacks par hôte sur fragments en
direct, avec stdin borné. Les gardiens, canary et rapports existants sont
conservés. Une erreur de callback, un dépassement de sortie ou un délai ne
peuvent pas produire un succès. Aucun rejeu n’est permis dans ce mode.
Revenir à rc3 nécessite de retirer les appels interact/interact_stream du
programme applicatif ; aucun schéma persistant ne change.
