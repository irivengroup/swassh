# Canary — première vague avant la flotte

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / usage / Canary — première vague avant la flotte

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Sortie et traçabilité](#sortie-et-traçabilité)
- [API asyncio](#api-asyncio)



```bash
# Par défaut : un canari, même sans option.
swassh run 'complex-command-or-script-with-options' -i hosts.txt

# Option seule : toujours un canari.
swassh run 'sudo -n /opt/deploy.sh --env production' -i hosts.txt --canary

# Cinq canaris, puis libération automatique de la flotte si tous réussissent.
swassh run 'sudo -n /opt/deploy.sh --env production' -i hosts.txt --canary 5

# La même barrière s’applique aux transferts.
swassh push --source ./release/ --destination /srv/application/ -i hosts.txt --canary 5
swassh pull --source /etc/application/config.ini --destination ./collecte/ -i hosts.txt --canary 5
```

`--canary` accepte un entier de 1 à 100 000, avec valeur implicite et défaut 1.
Les N premières identités SSH distinctes de l’inventaire normalisé sont choisies,
après application de l’utilisateur par défaut et déduplication. L’ordre est
celui de l’inventaire, sans tirage aléatoire. Si N dépasse le nombre de cibles,
toutes sont des canaris et aucune vague supplémentaire ne reste à lancer.

La première vague respecte les mêmes limites de workers, cadence, mémoire,
bande passante, timeouts et vérification des clés d’hôte. N est une taille de
vague, pas une nouvelle limite de concurrence. Tous les canaris sélectionnés
sont évalués ; le moteur attend leur fin avant toute opération sur les autres
cibles. Les canaris réussis ne sont pas exécutés une seconde fois.

La flotte restante démarre uniquement si **chaque canari a le statut success**.
Une erreur, un timeout, un échec d’authentification/clé, une interruption ou un
code distant non nul bloque la suite. Chaque cible non exécutée apparaît comme
`skipped`, `phase: fleet`, `attempts: 0`, sans code de sortie ni reçu de transfert.
Le rapport conserve donc le total de l’inventaire, avec distinction entre
réussites, échecs et cibles non exécutées. La CLI retourne 1 si le canary échoue.
Une annulation externe interrompt l’opération sans libérer la flotte et conserve
la politique de publication des rapports déjà documentée.

La réussite est celle de l’opération demandée, pas un contrôle de santé ajouté
implicitement. Pour vérifier le service après déploiement, inclure ce contrôle
et un code de sortie approprié dans la commande ou le script distant. Le succès
d’un transfert signifie que le client natif a réussi ; il ne prouve pas la santé
de l’application. Il n’y a ni validation interactive ni rollback automatique :
les modifications effectuées sur les canaris restent en place en cas d’échec.
Le canary couvre **une invocation** ; un push suivi d’un run reste deux invocations
avec deux barrières indépendantes, pas une transaction de déploiement commune.

## Sortie et traçabilité

Le texte compact affiche une seule ligne `Canary: N hosts — passed` ou
`failed; fleet blocked`, puis les compteurs de statuts et aperçus habituels.
Le nombre de lignes ne croît pas avec le nombre de cibles.

JSON ajoute `canary: {requested, selected, passed}` et `phase` par résultat.
CSV ajoute la colonne `phase` ; `skipped` est un nouveau statut. Le schéma JSON
reste 1 avec ces ajouts : les consommateurs qui valident strictement les statuts
et colonnes doivent accepter cette extension. Les regroupements de réponses
restent indépendants de la phase, pour conserver une sortie lisible.

L’audit émet `canary_started`, puis `canary_passed` ou `canary_failed`, et
`fleet_started` uniquement lorsque la barrière est franchie. Chaque `host_result`
indique la phase. Le bilan distingue `executed` et `skipped` ; en cas d’annulation
avant la fin de la première vague, `canary_passed` reste null. Les limites de
rotation, compression et confidentialité des logs sont conservées.

`--plan-only` affiche `canary_requested` et `canary_count`, avec le plan de
ressources, sans ouvrir de connexion. Il ne simule pas un succès du canary.

## API asyncio

```python
service = Swarm(Options(canary=5, concurrency=32))
summary = await service.run_to_file(hosts, command, "report.json")
print(summary.canary_count, summary.canary_passed, summary.counts["skipped"])
```

La même option `Options(canary=5)` est utilisée avec FileSwarm. La sélection et
la barrière appartiennent au cas d’usage application/swarm.py, sans dépendance
vers un adaptateur natif. L’API iter_results émet d’abord la première vague,
puis la flotte ou ses résultats skipped, avec backpressure et workers bornés.
