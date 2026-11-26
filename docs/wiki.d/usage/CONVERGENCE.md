# Idempotence déclarative

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / usage / Idempotence déclarative

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Contrat check, apply, verify](#contrat-check-apply-verify)
- [CLI](#cli)
- [API Python](#api-python)
- [Persistance et interruption](#persistance-et-interruption)
- [Reprise, retour arrière et limites](#reprise-retour-arrière-et-limites)



`DesiredState` déclare un contrôle sans effet de bord, une action et une
postcondition. SWASSH ne devine jamais l'effet d'une commande shell opaque.
Les commandes sont du code de confiance fourni par l'opérateur ; aucune clé,
aucun mot de passe ni jeton ne doit y être placé.

## Contrat check, apply, verify

| Phase | Résultat | Comportement |
| --- | --- | --- |
| check | code 0 confirmé | État désiré, aucune action, changed=false |
| check | échec confirmé, code 1 | Intent durable, puis action |
| check | autre code, timeout ou erreur | Arrêt sans action |
| apply | code 0 confirmé | Vérification obligatoire |
| apply | autre issue | État ambigu conservé, aucun rejeu automatique |
| verify | code 0 confirmé | Succès avec changed=true pour cette invocation |
| verify | autre issue | État ambigu conservé, aucun succès déclaré |

Sans `verify`, le contrôle `check` sert aussi de postcondition. Chaque commande
est limitée à 16 Kio UTF-8. `retries=0`, absence de stdin_file et de PTY sont
obligatoires. Les délais natifs s'appliquent à chaque phase, pas à une promesse
de durée globale identique à celle d'une seule commande.

## CLI

Exemple POSIX : créer un répertoire de démonstration privé dans le HOME distant.
Le fichier `examples/desired-state.json` contient une spécification complète.

```sh
swassh converge --action-file examples/desired-state.json -H srv01 --plan-only
swassh converge --action-file examples/desired-state.json -H srv01 --check
swassh converge --action-file examples/desired-state.json -H srv01 --format json --output convergence.json
```

`--plan-only` ne contacte aucun hôte et ne crée pas de journal. `--check` examine
les prérequis locaux, sans exécuter le contrôle distant. L'exécution normale
conserve le canary, les limites et le rapport du moteur de flotte.

## API Python

```python
import asyncio
from swassh import AsyncClient, DesiredState, Options

async def main():
    state = DesiredState(
        "demo-directory",
        'test -d "$HOME/swassh-demo"',
        'umask 077; mkdir "$HOME/swassh-demo"',
    )
    client = AsyncClient("srv01", options=Options(log_file="audit/converge.jsonl"))
    report = await client.converge(state, check=True)
    print(report.counts)

if __name__ == "__main__":
    asyncio.run(main())
```

`Client.converge` est l'équivalent synchrone. `ConvergentSwarm` fournit aussi
`run`, `run_to_file`, `iter_results`, `verify` et `verify_to_file`. Les deux
méthodes de vérification n'exécutent jamais l'action, même si l'état est absent.
L'itérateur doit être fermé avec `contextlib.aclosing` lors d'une sortie anticipée.

## Persistance et interruption

Le journal privé est sous la racine du budget local, dans `convergence/`.
Un verrou OS sérialise chaque identité hôte/action. L'intent est synchronisé
avant l'action ; après interruption, seule la postcondition peut être exécutée.
Une postcondition négative reste bloquante et n'autorise aucun nouvel apply.
Une vérification positive clôt l'intent sans prétendre avoir muté pendant cette
nouvelle invocation. Un contrôle de vérification neuf et négatif ne crée pas
artificiellement un intent de mutation.

L'identité lie le nom et toutes les commandes par SHA-256. Modifier cette
définition crée une autre identité : ne jamais le faire pour contourner un
intent ambigu. Examiner l'état distant et conserver la définition initiale.
Une modification par une autre application reste possible après le contrôle.
Le verrou local ne remplace pas un verrou métier sur le serveur distant.

Le journal conserve au plus 100000 identités et 32 Mio de base SQLite. Les
marqueurs de verrou restent sur disque pour éviter une course de remplacement.
Ne pas les supprimer pendant une opération. Le mode SQLite EXTRA renforce les
synchronisations du journal ; il dépend toujours du stockage et de son respect
des écritures durables. Les bases doivent rester sur un disque local fiable.

## Reprise, retour arrière et limites

Pour une commande opaque, un code de sortie ne prouve pas la vérité du contrôle.
L'opérateur doit vérifier que check et verify sont complets et sans effet de
bord. L'action peut avoir été partiellement exécutée sur le serveur après une
coupure ; SWASSH ne peut ni l'annuler ni inventer sa compensation.

Arrêter les invocations avant de changer de version. Sauvegarder les bases et
définitions privées. Le schéma v1 possède une descente qui refuse une base non
vide ; aucun effacement de preuves n'est utilisé pour revenir à rc4. Réinstaller
rc4 exige de retirer les nouveaux appels ; cette version ne lit pas ces bases.
Pour annuler la démonstration, supprimer manuellement le répertoire distant
uniquement s'il est encore vide et appartient bien à cette démonstration.

Les tests de contrats, de mort d'un processus, de verrous, de canary et
d'annulation figurent dans [test_convergence.py](../../../tests/test_convergence.py).
Ils ne remplacent pas la recette métier sur les cibles réelles.
