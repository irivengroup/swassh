# SWASSH 1.5.2 — sorties affichées par défaut

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / releases / SWASSH 1.5.2 — sorties affichées par défaut

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->


La CLI et les API affichent désormais les sorties de tous les hôtes par défaut,
y compris les succès, pour toute commande. `--show-output` reste compatible ;
`--hide-output` rétablit la synthèse compacte des réponses exceptionnelles.
Dans l’API, utiliser `Options(show_output=False)` pour ce même comportement.
La limite par défaut reste de dix lignes par flux et 240 caractères par ligne ;
`--output-lines 0` retire seulement la limite de lignes. JSON/CSV conservent leurs
formats et leurs données. Les limites de capture réseau restent inchangées.

Les nouvelles tâches planifiées enregistrent le nouveau défaut. Une tâche déjà
persistée conserve son option explicite, sans migration ni modification silencieuse.
Les plafonds des budgets, les transferts et les règles de sécurité sont conservés.
La qualification a révélé un verrou SQLite temporaire au démarrage concurrent.
L’initialisation et l’acquisition des transactions de création/libération des
réservations reprennent seulement SQLITE_BUSY dans un budget de dix
secondes, avec attentes SQLite courtes ; les autres erreurs remontent. Aucun
rejeu de commande distante n’est ajouté.
Le volume de texte affiché peut augmenter ; utiliser `--output` pour écrire un
rapport ou `--hide-output` pour conserver une console compacte.

Voir `VALIDATION.md` pour les contrôles exécutés sur cette modification. Les
preuves de 1.5.1 sont historiques et ne constituent pas une nouvelle qualification.
Pour revenir à 1.5.1, arrêter les invocations et le worker puis réinstaller sa
wheel conservée avec le même Python ; aucune migration de base n’est nécessaire.

Le banc de transport synchronise la sortie partielle avec un marqueur du
processus de test, puis applique le délai de 100 ms. Un scénario séparé vérifie
que le délai réel inclut un lancement lent ; le comportement de production
des délais n’est pas modifié.
