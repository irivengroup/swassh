# Intégration Python — 2.0.0rc1

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / usage / Intégration Python — 2.0.0rc1

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Démarrage en quelques lignes](#démarrage-en-quelques-lignes)
- [Applications asynchrones](#applications-asynchrones)
- [Résultats progressifs et mémoire](#résultats-progressifs-et-mémoire)
- [Contrôle fin sans mutation partagée](#contrôle-fin-sans-mutation-partagée)
- [Traitement des données et erreurs](#traitement-des-données-et-erreurs)
- [Adaptateurs et tests applicatifs](#adaptateurs-et-tests-applicatifs)
- [Écarts suivis et qualification](#écarts-suivis-et-qualification)
- [Dialogue bidirectionnel asynchrone — rc4](#dialogue-bidirectionnel-asynchrone--rc4)



SWASSH expose deux clients explicites : `Client` pour les scripts synchrones,
`AsyncClient` pour les applications asyncio et notebooks. Ils utilisent le même
moteur que `Swarm` : canary obligatoire, concurrence et sorties bornées, budgets
du bastion, audit, profils, authentification et rapports. La construction d'un
client ne crée aucune connexion. Python 3.11+ et OpenSSH sont requis pour SSH.

Pour une intégration applicative, privilégier `AsyncClient`. Une invocation
sur 100 hôtes utilise les travailleurs concurrents du moteur ; elle ne lance
pas 100 appels bloquants l'un après l'autre. Le canary reste une phase préalable
volontaire et les plafonds de ressources peuvent réduire la concurrence effective.
Un hôte lent occupe un travailleur, sans bloquer les autres ni la boucle asyncio.
`run` attend le rapport complet ; `stream` permet de consommer les hôtes terminés.

`Client` est conservé pour la compatibilité des scripts : il bloque son appelant,
mais son moteur multi-hôtes demeure parallèle. Une Session persistante unique
sérialise actuellement ses commandes ; elle ne constitue pas le moteur de flotte.
Les fonctions utilisateur appelées dans asyncio doivent elles-mêmes éviter les
attentes bloquantes. Le dialogue bidirectionnel de `interact` réagit aux fragments pendant
la commande ; `stream` conserve son contrat de résultats d'hôtes terminés.

## Démarrage en quelques lignes

```python
from swassh import Client

report = Client(["srv1", "srv2"], concurrency=8).run("uname -r")
for result in report.results:
    print(result.host.target, result.status, result.stdout)
```

Les noms représentent des machines de votre inventaire, accessibles avec vos
clés et votre fichier known_hosts. Le client ne demande aucun mot de passe
interactif et ne fait pas confiance automatiquement aux clés inconnues.
Une chaîne unique représente un seul hôte, jamais un iterable de caractères.
`Client.from_inventory("hosts.txt")` charge les formats d'inventaire existants.

## Applications asynchrones

```python
import asyncio
from swassh import AsyncClient, ExecutionError

async def main():
    client = AsyncClient(["srv1", "srv2"], concurrency=8)
    try:
        report = await client.run("uname -r", check=True, command_timeout=15)
    except ExecutionError as error:
        report = error.report
    print(report.counts)

asyncio.run(main())
```

Dans une boucle déjà active, appeler `await main()` sans `asyncio.run`.
Un appel `Client` bloquant dans une boucle est refusé avant de créer une coroutine.
Il n'y a pas de changement implicite du type de retour selon l'environnement.

`run` renvoie toujours un `Report`, même pour un seul hôte, dans l'ordre de
l'inventaire résolu. Par défaut, les échecs distants restent des résultats.
`check=True` attend le rapport complet puis lève `ExecutionError` s'il contient
un échec ou un hôte ignoré. Cela ne désactive pas le canary. Les erreurs locales
de configuration restent des `ValueError`/`TypeError`, et l'annulation asyncio
reste une `CancelledError`.

## Résultats progressifs et mémoire

```python
from swassh import Client

client = Client.from_inventory("hosts.txt", concurrency=16)
with client.stream("uname -r") as results:
    for result in results:
        print(result.host.target, result.stdout)
```

L'équivalent asynchrone utilise `async with client.stream(...)` et `async for`.
Le flux livre chaque résultat d'hôte terminé, dans l'ordre de terminaison après
la phase canary. Ce n'est pas un flux d'octets en direct d'une commande active.
La file supplémentaire contient au maximum un résultat ; les travailleurs et
la file du moteur restent bornés par le plan de ressources. L'inventaire est
normalisé en mémoire ; seul le stockage des résultats est progressif.

Un `break`, une exception ou une annulation ferme le producteur, annule les
travailleurs restants et attend leur nettoyage. Une opération distante déjà
envoyée n'est pas annulée rétroactivement. `check=True` sur un flux lève
`CommandError` au premier résultat non réussi ; sortir du contexte interrompt
alors le travail restant. Un flux est à usage unique, un seul lecteur à la fois.
Le flux synchrone appartient au thread entrant ; l'asynchrone à sa boucle.

En mode synchrone, la boucle privée avance pendant les appels d'itération : un
traitement bloquant entre deux résultats peut retarder le drainage des sorties.
Les gardiens natifs continuent d'imposer les délais. Dans une application qui
traite longtemps chaque résultat, préférer AsyncClient et ne pas bloquer sa boucle.

Pour exporter sans conserver les sorties de toute la flotte en mémoire :
`client.run_to_file("uname -r", "report.json")`, ou sa version awaitable.
Le résumé retourné conserve les compteurs ; JSON et CSV gardent leur format.

## Contrôle fin sans mutation partagée

Tous les paramètres nommés supplémentaires sont des champs validés d'`Options`.
Les noms inconnus sont refusés. Priorité : valeurs par défaut, objet `options`,
paramètres du constructeur, paramètres de l'opération. Les profils d'hôte
continuent d'appliquer leurs règles existantes ; un profil explicite peut donc
surcharger un délai global de l'opération.

- `client.with_options(command_timeout=20)` crée un autre client.
- `client.on("autre-hote")` crée un client pour cet ensemble de cibles explicite.
- `host_profiles`, `stdin_file`, encodage, bastion, mot de passe externe, GSSAPI,
  limites mémoire/sorties, cadence et audit utilisent les contrats existants.
- Les appels simultanés d'un `AsyncClient` possèdent leurs transports propres.
  Ils ne constituent pas un pool persistant partagé entre invocations.

Pour réutiliser une connexion sur un hôte :

```python
import asyncio
from swassh import AsyncClient

async def inspect():
    async with AsyncClient("srv1").session(lifetime=120) as session:
        system = await session.run("uname -s")
        kernel = await session.run("uname -r")
        print(system.to_text(), kernel.to_text())

asyncio.run(inspect())
```

Ce mode reprend les limites de `Session` : POSIX, un hôte, commandes sérialisées,
canal neuf par commande, aucun répertoire/environnement shell persistant.
Il n'est pas exposé comme une session synchrone. `shell`/PTY reste disponible
dans les interfaces historiques. Le SDK fournit des callbacks bidirectionnels
via interact. Les scopes SSHChannel/SSHTunnel exposent aussi les octets binaires
et le forwarding loopback ; voir [canaux et tunnels](CHANNELS.md).

Le mode interactif local exige un terminal POSIX ou une console Windows native.
Une plateforme de terminal inconnue est refusée avant l'exécution, sans mode
de remplacement implicite. Les attributs du terminal sont restaurés à la sortie,
y compris après une erreur ou une annulation.

## Traitement des données et erreurs

`result.ok` indique un succès. `result.raise_for_status()` retourne le même
résultat ou lève `CommandError` avec `.result`. `report.raise_for_status()`
retourne le rapport ou lève `ExecutionError` avec `.report`.
`result.json()` exige un succès, une sortie complète et un JSON strict ; les
propriétés dupliquées, constantes NaN/Infinity et sorties tronquées sont refusées
par `OutputDecodeError`, qui conserve `.result`. Aucun contenu distant n'est
ajouté au message de ces exceptions. Le résultat attaché peut contenir des
données sensibles : ne pas le journaliser aveuglément.

Les formats de rapport historiques ne changent pas : ces méthodes et propriétés
ne deviennent pas de nouveaux champs sérialisés.

## Adaptateurs et tests applicatifs

`Transport` est exporté comme protocole public. `Client`, `AsyncClient` et
`Swarm` acceptent `transport_factory`, une fonction recevant `Options` et créant
un adaptateur distinct par opération. L'adaptateur fournit
`async execute(host, command) -> Result` et peut fournir `async aclose()`.
Le moteur appelle cette fermeture à la fin ou lors d'une interruption.
`Swarm(transport=...)` reste compatible ; fournir les deux formes est refusé.
Une factory ne doit pas lancer de travail autonome hors du cycle de son adaptateur.

L'injection est une frontière de confiance pour tests et extensions : les
gardiens OpenSSH ne peuvent pas protéger automatiquement du code tiers qui
lance ses propres processus ou connexions. Les garanties natives portent sur
le transport par défaut. Ne pas utiliser cette injection pour contourner les
budgets du bastion. Le mode Session refuse une factory personnalisée.

## Écarts suivis et qualification

Chaque opération SDK réserve sa propre capacité, même si elle est appelée
depuis une Session déjà ouverte. Elle ne réutilise pas implicitement le budget
de cette session ; un budget disponible insuffisant peut donc la mettre en
attente. Le contexte de réservation de l'appelant est restauré à la sortie.

SWASSH utilise uniquement la bibliothèque standard Python, y compris pour
ces clients et leur construction. OpenSSH, SFTP et rsync sont des outils
système externes requis selon les opérations, pas des dépendances Python.

| Besoin / risque | Réponse actuelle | Limite restante |
| --- | --- | --- |
| Beaucoup de code avant le premier SSH parallèle | Clients liés à un inventaire, appel run unique | Authentification et confiance SSH restent à préparer |
| API différente entre scripts et applications asyncio | Méthodes parallèles explicites, rapports communs | Pas de changement automatique sync/async |
| Résultats accumulés sans limite | Flux géré, files bornées, export sur disque | Inventaire en mémoire, limites par résultat conservées |
| Fuite après break ou annulation répétée | Fermeture attendue et testée | Aucune restauration distante automatique |
| Erreurs non exploitables | Exceptions typées et résultats attachés | Politique métier à définir par l'application |
| Options partagées modifiées en cours de travail | Copies d'Options immuables et transports distincts | Code tiers injecté sous responsabilité de l'intégrateur |
| Intégration fine bas niveau comparable à Paramiko | Paramètres par hôte, sessions, ports d'adaptation | Callbacks et scopes binaires/tunnels implémentés ; voir [contrats et qualification](CHANNELS.md) |
| Réseau multiconstructeur | Profils et procédures explicites, reprise firmware bornée | Qualification matérielle, parseurs métier et recettes propres aux modèles : NON TERMINÉ |
| Supériorité de performances sur les concurrents | Contrôles de charge internes | Benchmark comparatif réel : NON EXÉCUTÉ |

Ces écarts ne sont pas tous des défauts des concurrents : plusieurs correspondent
à des choix de périmètre. L'objectif de référence se juge sur des preuves, pas
sur une promesse d'exhaustivité. Les chiffres et procédures manquantes figurent
dans VALIDATION.md. CI : découverte des tests SDK, portes SSH natives et tests
d'installation des exports publics. Aucun nouveau paquet Python requis.

Retour arrière : arrêter les opérations, vérifier l'état distant, puis réinstaller
la wheel rc3 conservée. Les anciens points d'entrée restent utilisables ; les
applications utilisant Client/AsyncClient nécessitent rc3 ; interact et interact_stream nécessitent rc4. Le scheduler conserve son schéma. La version 2 ajoute des bases séparées pour
les workflows et intents, non lisibles par rc4 ; les sauvegarder avant retour arrière.
Voir [idempotence](CONVERGENCE.md) et [workflows](WORKFLOWS.md).

## Dialogue bidirectionnel asynchrone — rc4

`await client.interact(command, handler_factory)` conserve les rapports et le
canary. La factory reçoit chaque Host et retourne un callback asynchrone
`handler(event, input)`. Le callback reçoit les fragments dès leur lecture,
y compris une invite sans saut de ligne, et peut répondre sans attendre la fin
publique de la commande. Il est propre à l'hôte ; aucune réponse n'est diffusée
implicitement aux autres cibles.

```python
import asyncio
from swassh import AsyncClient


def dialogue(host):
    pending = bytearray()
    answered = False

    async def react(event, input):
        nonlocal answered
        if event.stream != "stdout" or answered:
            return
        pending.extend(event.data)
        if len(pending) > 128:
            raise ValueError("unexpected prompt")
        if pending == b"READY?":
            await input.send(b"continue\n")
            input.close()
            answered = True

    return react


async def main():
    client = AsyncClient.from_inventory("hosts.txt", concurrency=16)
    report = await client.interact(
        'printf "READY?"; IFS= read -r reply; printf "%s" "$reply"',
        dialogue,
        check=True,
    )
    print(report.counts)


asyncio.run(main())
```

Pour combiner réactions en direct et résultats progressifs, utiliser
`async with client.interact_stream(command, dialogue) as results`, puis
`async for result in results`. Les callbacks reçoivent les fragments ;
l'itérateur reçoit les résultats complets, avec la même fermeture garantie que
`stream`. Aucun point d'entrée interactif bloquant n'est ajouté à Client.

Contrats et limites :

- `OutputEvent.stream` vaut start, stdout ou stderr. start est délivré avant les
  sorties ; il signale le lancement local, pas une authentification réussie.
  `data` contient au plus 4096 octets ; `eof` marque la fin du flux.
  Les fragments ne sont ni des lignes ni nécessairement des caractères UTF-8
  complets. Un analyseur de lignes doit borner son accumulation et utiliser un
  décodeur incrémental. stdout et stderr n'ont pas d'ordre chronologique commun.
- Les callbacks sont sérialisés par hôte et concurrents entre hôtes. Aucune file
  d'événements sans limite n'est créée. Un callback lent applique une pression
  en retour à cet hôte ; les autres travailleurs restent indépendants.
- `input.send(bytes)` accepte au plus 16384 octets par appel, attend le drainage
  et respecte `max_stdin_bytes` cumulé par hôte. `input.close()` ferme stdin.
  Le canal n'est utilisable que pendant son callback, dans la même tâche ;
  le conserver pour une tâche de fond est refusé.
- `stdin_file` et `retries > 0` sont refusés. Aucune réponse ni commande n'est
  rejouée. Le délai command_timeout couvre lancement, callbacks et fermeture
  normale ; les gardiens natifs restent actifs. Un callback en erreur produit
  ERROR sans inclure son message potentiellement sensible dans le rapport.
- Dépasser max_output_bytes sur l'un des flux interrompt l'interaction avec
  ERROR et une indication de troncature. Les commandes ordinaires conservent
  leur comportement historique de capture tronquée.
- Une factory et ses callbacks sont du code applicatif de confiance : pas de
  blocage synchrone de la boucle, pas d'accumulation illimitée, pas de tâche de
  fond conservant le canal. Le SDK ne peut pas contrôler la mémoire ou les
  effets arbitraires de ce code. La factory elle-même doit être courte.
- Le canary attend la fin des hôtes pilotes avant d'ouvrir la flotte. Un callback
  pilote ne doit donc pas attendre une réponse d'un hôte non encore admis.
- PTY reste explicite ; les sorties distantes peuvent alors être fusionnées et
  transformées par le terminal. SSHChannel et SSHTunnel sont des scopes séparés,
  sans PTY. Les profils réseau existants conservent leurs procédures.
- Après interruption, l'état distant peut être inconnu : aucune annulation
  rétroactive des effets distants ni restauration automatique n'est promise.
