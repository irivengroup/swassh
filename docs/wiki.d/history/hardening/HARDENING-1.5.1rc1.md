# Durcissement 1.5.1rc1

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / hardening / Durcissement 1.5.1rc1

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Corrections et impacts](#corrections-et-impacts)
- [Stockage, migration et retour arrière](#stockage-migration-et-retour-arrière)
- [Menaces et limites](#menaces-et-limites)



Cette version candidate corrige six défauts confirmés. Elle ne constitue pas
une garantie d'absence de bugs. L'incident intermittent de planification de la
campagne 1.5.0 reste ouvert : son état et sa cause n'avaient pas été conservés.
Quarante nouvelles planifications réelles ont réussi sans rejeu ; cette série
ne démontre pas la résolution de l'incident historique.

## Corrections et impacts

| Domaine | Défaut corrigé | Garantie et contrôle |
| --- | --- | --- |
| Admission adaptative | Un réveil anticipé permettait une admission avant le créneau réservé | Revérification de l'horloge ; test déterministe de réveil anticipé et maintien du plafond |
| Installation PATH | PATH vide introduisait le répertoire courant ; PATH absent échouait sous `set -u` ; deux-points non représentable | Expansion conditionnelle POSIX, refus des deux-points, tests avec un vrai shell ; sauvegarde et remplacement du bloc ancien reconnu ; bloc modifié refusé explicitement |
| Verrous | Fermer un descripteur non propriétaire effaçait le suivi du propriétaire | Seul le propriétaire libère son marqueur ; test de deux descripteurs |
| Débit partagé | Un délai légitime supérieur à 120 secondes était pris pour un redémarrage | Échantillon persistant de l'horloge monotone ; délais longs et changement de politique conservés |
| Contention | Une transaction SQLite occupée faisait échouer l'admission | SQLITE_BUSY avant la transaction signifie attente ; les autres erreurs restent explicites ; transaction concurrente réelle et dix processus |

La CLI, les rapports, canary, schedule, push/pull, SHA-256 et la prévisualisation
des suppressions restent disponibles. Aucun paquet Python supplémentaire.
Le test du rapport canary lit explicitement son encodage UTF-8 : l'assertion
fonctionnelle est conservée, sans dépendance au mode UTF-8 global du runtime.

Les archives ZIP et source excluent aussi automatiquement `validation/installation.json`,
qui contient la sortie brute des contrôles locaux. Un test vérifie les deux formats.

## Stockage, migration et retour arrière

Le coordinateur ajoute une table `clock` dans sa transaction d'initialisation.
Une ancienne base migre sans effacer ses réservations ni sa politique. En
l'absence d'échantillon historique, la borne déduite du plus grand délai légal
reste conservatrice : après un redémarrage, une base ancienne peut imposer une
attente jusqu'au délai restant. Une régression d'horloge avec réservations
actives provoque un refus explicite ; aucune capacité supplémentaire n'est admise.

Arrêter les invocations et le worker avant une mise à niveau ou un retour
arrière ; éviter le mélange de versions du coordinateur. Conserver les bases
privées de planification et les sauvegardes des profils. La 1.5.0 ignore la table
supplémentaire, mais son retour réintroduit les défauts corrigés. Ne jamais
supprimer une base de budget tant que des invocations ou descendants sont actifs.
Les profils sont restaurables depuis les sauvegardes créées par `setup-path`.

## Menaces et limites

Les contrôles protègent le plafond partagé, la propriété des verrous et la
recherche de commandes par PATH. Le budget reste local au compte et à sa racine
commune : ce n'est pas un coordinateur entre plusieurs machines ou comptes.
Une saturation du stockage reste une panne explicite ; seule la contention
SQLite d'admission est traitée comme une attente. Le maximum de débit n'est pas
une garantie de latence ni de disponibilité du bastion.

Les résultats de la campagne et les contrôles non exécutés sont décrits dans
`VALIDATION.md`. Les plateformes sans exécution native ne sont pas certifiées.
