# Workflows persistants avec dépendances

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / usage / Workflows persistants avec dépendances

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Définition et enregistrement](#définition-et-enregistrement)
- [API Python](#api-python)
- [Claims, audit et états](#claims-audit-et-états)
- [Réconciliation et reprise explicites](#réconciliation-et-reprise-explicites)
- [Stockage, limites et exploitation](#stockage-limites-et-exploitation)
- [Migration et retour arrière](#migration-et-retour-arrière)



Un `Workflow` est un graphe acyclique de `WorkflowStep`. Chaque étape porte son
inventaire et soit une commande opaque, soit un `DesiredState`. Elle attend la
réussite de toutes ses dépendances. Un échec bloque ses descendants ; les
branches indépendantes restent exécutables. Un seul moteur de flotte s'exécute
à la fois par répertoire d'état, avec son canary et ses budgets habituels.

## Définition et enregistrement

Le fichier complet `examples/workflow.json` illustre une consultation POSIX,
puis la création du répertoire de démonstration décrit dans
[l'idempotence déclarative](CONVERGENCE.md).

```sh
swassh workflow --workflow-file examples/workflow.json --plan-only
swassh workflow --workflow-file examples/workflow.json --check
swassh workflow --workflow-file examples/workflow.json --state-dir ./workflow-state
swassh workflow --state-dir ./workflow-state --list
swassh workflow --state-dir ./workflow-state --worker --once
```

L'enregistrement ne lance aucune commande distante. Il fige les cibles résolues,
options, chemins d'exécutables et références de clés/confiance ; les mots de
passe et tickets restent externes. Le worker doit tourner sous le compte et
dans l'environnement capables d'utiliser ces références. Ne déplacer aucune
base entre Windows et Unix en supposant ses chemins portables.

Le plan est local, sans ouverture de base, recherche d'exécutable ou accès
réseau. Le contrôle `--check` inspecte les prérequis locaux. La CLI utilise
JSON pour les métadonnées ; les rapports d'étapes sont des JSON séparés. Les
options d'exécution ne sont pas acceptées avec une action de gestion : elles
ne remplacent pas silencieusement le snapshot déjà enregistré.

## API Python

```python
import asyncio
from swassh import WorkflowRunner, Options

async def main():
    definition = WorkflowRunner.load("examples/workflow.json")
    print(WorkflowRunner.plan(definition))
    with WorkflowRunner("workflow-state") as runner:
        info = runner.register(definition, Options())
        print(info.id)
        await runner.serve(once=True)
        print(runner.store.get(info.id).to_dict())

if __name__ == "__main__":
    asyncio.run(main())
```

La construction, le chargement et l'enregistrement effectuent des opérations
locales synchrones. Les effectuer pendant l'initialisation ou dans un thread
si une application doit maintenir une boucle sans attente disque. Le worker
déplace ses transactions et écritures d'audit hors de la boucle asyncio.

## Claims, audit et états

Le worker possède un verrou OS pendant toute sa vie. Chaque claim et son
événement d'outbox sont commis avant l'exécution ; l'audit est synchronisé avant
l'admission suivante. L'outbox n'est acquittée qu'après fermeture durable du
journal. Une panne de stockage ou d'audit interdit l'effet suivant.

| État d'étape | Sens |
| --- | --- |
| pending | Attend l'admission et ses dépendances |
| running | Claim durable, commande éventuellement commencée |
| succeeded | Résumé complet réussi ou postcondition explicitement vérifiée |
| failed | Échec d'exécution ou de rapport |
| blocked | Dépendance non réussie |
| interrupted | Claim retrouvé après perte ou arrêt du worker |
| cancelled | Annulation explicite avant admission |

Une étape running n'est jamais remise automatiquement à pending. Après crash,
elle devient interrupted. Les étapes réussies restent terminales. Un arrêt
attend le nettoyage natif avant de libérer les réservations. Cela ne prouve
pas que le processus distant a été arrêté.

## Réconciliation et reprise explicites

`--reconcile ID --step NOM` exécute seulement une postcondition déclarée :
verify/check pour `DesiredState`, ou `reconcile_check` séparé pour une commande
opaque. Aucun code ne permet de rejouer automatiquement la commande interrompue.
Sans vérificateur déclaré, la reprise de cette étape est refusée.

Une vérification positive est une preuve d'état fournie par le contrôle métier,
pas une preuve rétrospective que chaque instruction a été exécutée. Le contrat
du contrôle doit donc couvrir l'effet attendu. Une vérification négative reste
bloquante. La fonction `await runner.reconcile(id, step)` est l'équivalent API.

Chaque vérification écrit `reconcile-N.json`, avec au plus 16 tentatives. Son
identifiant, ses compteurs et son chemin restent séparés du rapport et des
compteurs initiaux. Aucun rapport d'échec n'est écrasé. `--resume ID` ou
`runner.resume(id)` n'admettent le workflow qu'après vérification de toutes les
étapes failed/interrupted. Les descendants blocked reviennent alors à pending ;
les étapes réussies ne sont pas rejouées.

## Stockage, limites et exploitation

Par défaut, le stockage est dans le dossier d'état utilisateur, sous
`swassh/workflows`. Les rapports sont sous `runs/ID/ETAPE/report.json`. Utiliser
`--state-dir` pour une destination locale dédiée et privée. Les définitions
contiennent les commandes en clair : aucun secret ne doit être incorporé dans
une commande, un inventaire ou un fichier de plan. Le stockage privé n'est pas
un chiffrement au repos ni une sauvegarde.

Limites : 256 étapes, 4096 arêtes, 100000 enregistrements cible/étape au total,
snapshot 10 Mio, 1000 workflows conservés et base 128 Mio. Les cibles répétées
dans des étapes différentes comptent plusieurs fois. Les rapports ont leur
propre budget ; prévoir aussi leur rétention et des quotas de volume.
`--purge ID` supprime explicitement une métadonnée terminale, conserve rapports
et événements d'audit, et n'annule aucun effet distant. `--cancel ID` concerne
uniquement un workflow encore pending. Il n'existe aucune suppression globale
automatique des journaux ou des intents ambigus.

Le worker reste au premier plan : le faire superviser par l'outil d'exploitation
du site. Les générateurs de service de `schedule` restent destinés à schedule.
Cette implémentation ne crée ni cluster de workers distribués ni coordinateur
sur plusieurs bastions. SQLite ne doit pas être placé sur un partage réseau
pour essayer de produire cette garantie.

## Migration et retour arrière

Les workflows ont leur base et leur schéma v1 distincts du scheduler existant.
Les migrations Up/Down sont transactionnelles ; Down refuse travail ou outbox
non vides. Arrêter le worker, sauvegarder base et rapports, vérifier l'état
distant, puis installer la version précédente si nécessaire. rc4 ne prend pas
en charge les nouveaux workflows ; conserver leurs preuves hors de son usage.
Un retour arrière local ne restaure pas les serveurs.

Sous Linux, après arrêt du worker, la commande installée
`swassh-clean-restore` retire un répertoire de restauration partielle qui
contient uniquement `workflows.sqlite`. L'administrateur utilise le compte
propriétaire du répertoire et l'empreinte SHA-256 attendue tirée du manifeste
de sauvegarde. Le répertoire parent doit être privé et sur un disque local.

```sh
swassh-clean-restore /var/lib/swassh/restored --sha256 "$EXPECTED_SHA256"
```

Pour restaurer, garder le worker arrêté et utiliser le même compte. Préparer
une sauvegarde SQLite autonome avec l'API SQLite de sauvegarde, et joindre
les rapports sous `runs/` ainsi que `workflow.jsonl` lorsqu'ils existent.
Passer un manifeste JSON de confiance conservé hors du dossier de sauvegarde.
Chaque clé est le chemin relatif d'un fichier et chaque valeur son SHA-256.
Les répertoires de sauvegarde doivent être privés. La commande accepte au
maximum 1 Mio de manifeste, 128 Mio de SQLite, 512 Mio de données au total et
16 384 répertoires. Elle conserve les dossiers de rapports vides des étapes
en attente.

```sh
swassh-restore-workflows /var/lib/swassh/backup /var/lib/swassh/restored --manifest /var/lib/swassh/backup.json
```

Les deux commandes prennent le même verrou par destination avant de toucher
au dossier. Le concurrent reçoit le code 75 et « volume verrouillé ». Le
verrou reste dans le parent après l'opération pour conserver la même identité
après retrait du dossier. Le code 2 signale une erreur d'entrée ou de stockage.
La restauration vérifie l'inventaire, les empreintes et SQLite dans un dossier
de préparation privé. Elle publie la copie complète dans une destination
neuve. À l'issue de la copie, rétablir le chemin d'état logique qui figure dans
les checkpoints avant de redémarrer le worker.

Pour une étape interrompue, vérifier son effet avec `--reconcile` avant
`--resume`. Après un arrêt brutal, vérifier que les deux commandes et le worker
sont arrêtés. Un répertoire de préparation abandonné, nommé
`.swassh-restore-*`, peut subsister. Contrôler sa nature et retirer uniquement
la préparation identifiée ou la réservation vide. Conserver le fichier de
verrou qui se termine par `.lock`.

Les scénarios reproductibles sont dans
[test_workflows.py](../../../tests/test_workflows.py) : graphe, admission,
verrous, crash/reprise, annulation répétée, audit indisponible, corruption et
conservation des rapports. La qualification sur le parc reste distincte.
