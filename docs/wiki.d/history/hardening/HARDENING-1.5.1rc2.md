# Durcissement 1.5.1rc2 — erreurs de stockage et annulations

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / hardening / Durcissement 1.5.1rc2 — erreurs de stockage et annulations

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Défauts reproduits et corrections](#défauts-reproduits-et-corrections)
- [Impact, risques et exploitation](#impact-risques-et-exploitation)



Cette candidate prolonge 1.5.1rc1 sans modifier la CLI, les formats de rapports,
les plafonds de concurrence ou les schémas persistants. La qualification globale
reste NON TERMINÉE : voir `VALIDATION.md` et les preuves de cette campagne.

## Défauts reproduits et corrections

Les cinq tests de `tests/test_budget_cleanup.py` échouent sur l'archive 1.5.1rc1
conservée, puis réussissent avec les corrections :

| Déclencheur | Ancien effet | Correction |
| --- | --- | --- |
| Erreur de libération d'une réservation | Connexion SQLite non fermée | Fermeture dans un `finally` indépendant |
| Deux annulations pendant une réservation | Retour avant la fin du nettoyage en thread | Attente protégée du nettoyage jusqu'à son achèvement |
| Échec de fermeture du journal | Verrou du journal non libéré | Libération indépendante du verrou |
| Échec du déverrouillage explicite | Descripteur de verrou non fermé | Fermeture tentée dans tous les cas, erreur conservée |
| Échec de suppression d'un temporaire | Répertoire sécurisé maintenu ouvert | Fermeture indépendante des handles du répertoire |

Les erreurs restent propagées. Un temporaire impossible à supprimer peut rester
sur disque ; la correction ne prétend pas réparer un stockage défaillant.
Une annulation attend la fin des opérations SQLite en cours : le délai de
contention est borné par SQLite, mais un système de fichiers bloqué dans le noyau
ne peut pas être interrompu de manière portable par un thread Python.

## Impact, risques et exploitation

| Domaine | Impact et garantie |
| --- | --- |
| Concurrence | Aucune capacité supplémentaire ; mêmes verrous, quotas et ordre d'admission |
| Résilience | Moins de ressources conservées après panne ; aucun rejeu de commande ajouté |
| Sécurité | Résolution des chemins, droits privés, Job Objects Windows et contrôle SSH préservés |
| Données | Aucun changement de schéma ni migration ; publication atomique inchangée |
| Performances | Pas de changement d'algorithme nominal ; benchmark simulé de 50 000 hôtes et seuil mémoire existant conservés |
| Compatibilité | Python >= 3.11 ; validation native Windows/Linux, autres systèmes à qualifier |
| CLI et installation | `run`, `push`, `pull`, `schedule`, canary, sorties, pip et configuration PATH conservés |
| CI | Découverte automatique des nouveaux tests par `scripts/verify.py` et `scripts/coverage.py` ; seuil 90 % inchangé |

Pour qualifier sur un hôte : `python scripts/verify.py`, puis
`python scripts/coverage.py`. Pour les transports réels, utiliser
`python scripts/native_network_gate.py` avec OpenSSH serveur/client et rsync
pris en charge, dans un laboratoire isolé. Les résultats du benchmark simulent
le transport ; ils ne prédisent pas le débit d'un parc SSH réel.

En cas d'erreur disque, vérifier espace, droits, santé du volume et événements
d'audit. Ne pas supprimer une base ou un verrou utilisé par une invocation.
Arrêter et attendre les invocations et le worker avant une maintenance.

Retour arrière : après arrêt des invocations, réinstaller la wheel précédente
conservée avec le même interpréteur. Garder les bases de planification et les
rapports ; aucune conversion de données n'est nécessaire. La régression connue
de nettoyage réapparaît avec l'ancienne version.

L'incident historique isolé de planification ne dispose toujours pas de preuve
de cause ; ces corrections ne sont pas présentées comme sa résolution. Les
succès de tests ultérieurs ne remplacent pas cette preuve. Aucune promesse
d'absence de défaut ni de gain de débit réseau n'est faite.
