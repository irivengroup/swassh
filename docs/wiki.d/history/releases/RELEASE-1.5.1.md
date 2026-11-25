# SWASSH 1.5.1 — critères de stabilité et exploitation

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / releases / SWASSH 1.5.1 — critères de stabilité et exploitation

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Critères de promotion](#critères-de-promotion)
- [Corrections de planification](#corrections-de-planification)
- [Incident historique et décision de livraison](#incident-historique-et-décision-de-livraison)
- [Vérification et retour arrière](#vérification-et-retour-arrière)



Cette livraison conserve `swassh run 'commande' -i hosts.txt`, push/pull,
schedule, canary, sorties, budgets partagés, prévisualisation, SHA-256 et pip/PATH.
Elle ne change pas le schéma des bases ni la politique de non-rejeu.

## Critères de promotion

La promotion nécessite zéro échec inattendu dans les suites complètes Windows
Python 3.11 à 3.14 disponibles et Linux Python 3.12, une couverture Linux d'au
moins 90 % sans exclusion nouvelle, les onze essais réseau natifs sans ignorés,
50 jobs planifiés concurrents avec des invocations manuelles, des résultats et
comptages exacts sans rejeu, puis l'installation réelle des distributions finales
et leur reconstruction reproductible avec le même environnement de construction.
Les résultats observés et le périmètre exact sont consignés dans `VALIDATION.md`.

Une version stable ne signifie pas absence mathématique de bugs. macOS, Solaris
et AIX conservent leurs implémentations et procédures de qualification ; aucune
certification native sur ces systèmes n'est déduite des résultats Windows/Linux.
La qualification de toutes les plateformes reste distincte de cette promotion.

| Domaine | Impact et contrôle |
| --- | --- |
| CLI et API | Arguments et codes de raison conservés ; une erreur de persistance auparavant masquée remonte désormais comme erreur au caller/superviseur |
| Données | Champ de diagnostic ajouté à l'événement d'échec ; aucune table ni migration nouvelle, écriture atomique avec l'état |
| Concurrence | Plafonds et politique de non-rejeu inchangés ; campagne avec worker redémarré et invocations manuelles partageant le budget |
| Sécurité | Liste autorisée de catégories/types et errno borné ; aucun message d'exception ou secret dans le diagnostic durable |
| Performance | Aucun appel disque supplémentaire sur le chemin nominal ; benchmark et plafonds existants conservés, aucun gain de débit revendiqué |
| CI et exploitation | Nouvelle campagne Linux de 50 jobs ; conservation locale des preuves privées en cas d'échec d'installation |
| Compatibilité et rollback | Tests des anciens adapters et snapshots ; réinstallation de la wheel précédente après arrêt, sans conversion des bases |

## Corrections de planification

Une erreur d'enregistrement du résultat final pouvait être interceptée comme
une erreur d'exécution, puis transformée en état `failed`. Désormais, cette erreur
remonte au superviseur. Si la transaction avait réussi avant l'erreur, l'état
terminal est conservé. Sinon, le claim est interrompu lors de la récupération,
sans relancer la commande. Il peut donc exister un rapport réussi avec un job
`interrupted` lorsque la confirmation durable est indisponible : inspecter le
rapport et la cible avant de décider manuellement d'une nouvelle opération.

Le code `reason=execution_or_report_error` est conservé pour la compatibilité.
L'événement durable `schedule_failed` possède en plus un objet `diagnostic` :
`category`, `error_type`, `errno`. Ses valeurs sont issues d'une liste autorisée ;
les messages d'exception, chemins et commandes ne sont pas enregistrés. Les
catégories sont timeout, permission, missing_file, io, invalid_input,
invalid_summary, runtime et unexpected. Cet objet et l'état terminal sont écrits
dans la même transaction, puis exportés par l'outbox existante. Les adapters
injectés sans cette capacité facultative gardent le comportement compatible.

Le banc d'installation conserve désormais son répertoire privé en cas d'échec,
avec `failure.json`, base et journaux, et imprime son emplacement. Ces preuves
brutes ne doivent pas être publiées ni ajoutées à une distribution. Nettoyer
uniquement le répertoire indiqué après diagnostic et sauvegarde utile. Le banc
revérifie l'échéance UTC après chaque réveil pour ne pas démarrer le worker avant
la date attendue ; l'attente est bornée en cas de dérive d'horloge.

## Incident historique et décision de livraison

L'échec isolé de qualification 1.5.0 reste de cause indéterminée : les preuves
initiales ont été supprimées par l'ancien banc. Les défauts reproduits ci-dessus
ne sont pas présentés comme sa cause démontrée. La décision de promotion repose
sur les critères explicites de cette campagne, la conservation des diagnostics
futurs et les tests de panne, et non sur l'affirmation d'une correction historique
impossible à prouver. Un nouvel échec inattendu bloque la promotion et doit être
diagnostiqué ; un succès ultérieur ne l'efface pas.

## Vérification et retour arrière

Exécuter `python scripts/verify.py`, `python scripts/coverage.py`, puis sous Linux
`PYTHONPATH=src python scripts/qualify_schedule.py --iterations 50` et
`python scripts/native_network_gate.py` avec les prérequis SSH/rsync du projet.
La campagne utilise des processus de transport simulés, pas un parc distant ;
les essais réseau natifs restent un contrôle séparé. Les cinq échecs de canary
prévus dans cinquante jobs ne sont pas des échecs du contrôle : les états, les
hôtes ignorés et les comptages attendus sont vérifiés.

Construire puis installer les paquets avec les procédures de `INSTALLATION.md`.
Arrêter les invocations et le worker avant mise à niveau ou retour à la wheel
précédente. Garder les bases privées et rapports ; aucune migration n'est requise.
Les claims interrompus ne sont jamais rejoués automatiquement. Le suffixe stable
ne constitue pas une publication PyPI : cette publication est une opération
distincte, conditionnée par la CI et les autorisations de l'index.
