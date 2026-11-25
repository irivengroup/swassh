# Audit et durcissement — SWASSH 1.3.0

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / hardening / Audit et durcissement — SWASSH 1.3.0

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Constats et corrections](#constats-et-corrections)
- [Politique rsync](#politique-rsync)
- [Contrat de sécurité et limites](#contrat-de-sécurité-et-limites)
- [Vérification et maintenance](#vérification-et-maintenance)
- [Planification persistante (1.3.0)](#planification-persistante-130)
- [Corrections 1.3.1](#corrections-131)



Périmètre : code livré, couches DDD, CLI/API, inventaires, processus SSH et
transferts, budgets, rapports, logs, construction et workflows. Base : archive
utilisateur `swassh-1.0.2.zip`, puis changements documentés jusqu’à 1.1.1.
Les résultats réellement exécutés et leurs limites figurent dans `VALIDATION.md`.
Cette revue de code avec tests adverses ne constitue pas un pentest externe
ni une certification d’un bastion de production.

## Constats et corrections

| Risque | Priorité | Correction et preuve reproductible |
| --- | --- | --- |
| rsync ancien accepté dès 3.0, malgré les avis de sécurité amont | Haute | Seuil 3.5.0 aux deux extrémités, sans contournement ; `test_rsync_security_floor`, `test_local_old_version`, `test_fallback_export_and_publish_edges` |
| Un client natif terminé pouvait laisser un descendant tenant les pipes ouverts | Haute | Nettoyage du groupe POSIX, TERM puis KILL, même si son leader a été récolté ; `test_reaped_native_leader_cannot_leave_pipe_child` |
| Une seconde annulation pouvait interrompre le nettoyage avant la fin d’un thread ou processus | Haute | Attente protégée des tâches de nettoyage ; `test_cleanup_survives_repeated_cancellation`, tests d’annulation SSH/transfert/rapport |
| Rapports sans échéance : un écrivain bloqué immobilisait la flotte | Haute | RPC sérialisés, `--report-timeout` 60 s par opération, arrêt forcé puis nettoyage ; `test_report_deadline_kills_stopped_worker` suspend réellement le processus |
| Logs existants : liens physiques, fichiers spéciaux ou staging partagé | Haute | Ouverture sans suivi de lien et sans blocage FIFO, contrôle du type/propriétaire/nlink, refus des dossiers directement partagés en écriture ; tests `LocalFilesHardeningTests` |
| Réception locale exposée aux métadonnées distantes et temporaires cachés | Haute | Staging privé par fichier ; somme des fichiers temporaires surveillée ; contrôle final du type, taille, nlink ; retrait setuid/setgid ; dossiers de pull privés ; `test_hidden_native_download_counts_toward_budget`, tests rsync/SFTP natifs |
| Répertoires rsync : liens sortants et fichiers spéciaux acceptés par `-a` | Haute | `--safe-links --no-devices --no-specials` ; test rsync local avec symlink sortant, FIFO, hard links et `--delete` |
| Champs JSON/CSV ambigus ou profondeur JSON excessive | Moyenne | Doublons/constantes non finies/champs inconnus/lignes CSV incomplètes refusés ; erreurs converties en `InventoryError` ; `test_ambiguous_inventories_are_rejected` |
| Inventaire FIFO ou générateur de doublons sans borne | Moyenne | Lecture régulière non bloquante, plafond de 100 000 enregistrements d’entrée même dédupliqués ; tests FIFO/itérateur |
| Macros OpenSSH dans les chemins et noms non littéraux | Moyenne | DNS/IPv6 validés et normalisés pour dédupliquer leurs variantes, IDNA normalisé, `%` littéral échappé, `${...}` et contrôles refusés dans les chemins ; tests des hôtes et de la configuration |
| Commandes énormes et résultats invalides provenant d’un adaptateur | Moyenne | Commande limitée à 16 Kio UTF-8, objets de résultat/reçu validés ; la commande valide reste opaque ; tests CLI et domaine |
| Annulation interne d’un worker : attente d’un résultat qui n’arriverait jamais | Moyenne | Annulation spontanée du transport devient `error` ; worker effectivement annulé déclenche une erreur bornée ; tests d’annulation interne |
| Plan recalculé en cours d’exécution et limites cgroup imbriquées ignorées | Moyenne | Plan fixé pour toute la collecte ; minimum des plafonds cgroup v2 lisibles ; tests de plan et de cgroup |
| Spool : compteurs non restaurés après échec d’un lot, budget uniquement estimé | Moyenne | Transaction et compteurs restaurés ensemble ; `max_page_count` impose aussi une limite SQLite physique ; cleanup d’initialisation ; tests transactionnels |
| Sortie console falsifiable avec Unicode bidi/séparateurs et cellules CSV actives | Moyenne | Contrôles neutralisés dans l’aperçu, apostrophe avant les formules après contrôles/espaces invisibles ; `test_unicode_console_and_csv_spoofing` |
| Métadonnées d’audit écrasables par les valeurs fournies | Moyenne | Champs `timestamp`, `run_id`, `pid`, `event` réservés ; `test_audit_metadata_cannot_be_forged` |
| Archives pouvant inclure des liens externes ou des fichiers racine accidentels | Moyenne | Liens refusés, liste des racines et fichiers livrables, manifeste SHA-256 vérifié ; tests builders et packaging |
| Actions CI référencées par tags mobiles, credentials conservés après checkout | Moyenne | Actions épinglées sur SHA complets, checkout sans credentials persistés, permissions minimales, échéance des jobs, mises à jour Dependabot hebdomadaires ; `WorkflowHardeningTests` |

Le canary apporte une barrière supplémentaire contre la propagation d’un
échec : 10 tests dédiés couvrent la sélection, les budgets, les erreurs,
l’annulation, les rapports et les transferts. La réussite ne vaut pas contrôle
de santé implicite et les modifications de première vague ne sont pas annulées.

## Politique rsync

L’avis amont daté du 13 août 2026 décrit 33 problèmes affectant rsync 3.4.4 et
antérieur, corrigés en 3.5.0. La politique conservatrice de SWASSH exige donc
3.5.0 minimum **localement et sur chaque cible**. Le texte de version ne prouve
pas les correctifs rétroportés d’une distribution : ils ne sont pas acceptés
automatiquement. Un wrapper qui ment sur la version n’est pas une solution.
Installer une version maintenue depuis une source de confiance.

Un rsync incompatible entraîne SFTP pour un fichier simple, avant toute copie.
Pour un répertoire, l’opération échoue : le repli ne saurait reproduire `-H`,
`--numeric-ids` et `--delete`. Aucun repli après le début d’une copie rsync.
Le profil demandé reste `-avzPH --numeric-ids --delete`, complété par les
protections suivantes :

- `--protect-args`, configuration SSH privée et limites de débit ;
- `--safe-links`, exclusion devices/specials et retrait setuid/setgid ;
- `--max-alloc`, 16 Mio par allocation par défaut, réduit selon le budget ;
- pour le pull, suppression des droits groupe/autres sur les répertoires locaux.

Ces filtres changent volontairement la reproduction des attributs dangereux :
un symlink sortant ou FIFO peut être ignoré même si rsync termine avec succès.
La limite d’allocation n’est ni une limite de RSS totale ni un quota distant.
Un grand arbre `-H` peut nécessiter davantage de mémoire ; un échec ne provoque
pas de repli masquant une synchronisation partielle.

## Contrat de sécurité et limites

Les clés d’hôte sont strictement vérifiées et doivent être provisionnées hors
bande. Aucun mot de passe interactif, agent forwarding, TTY, commande locale
OpenSSH, multiplexage global ou configuration utilisateur implicite n’est
activé. Les programmes natifs et la configuration de leur environnement sont
administrés et de confiance. Cette isolation n’empêche pas un administrateur,
un processus du même UID, une bibliothèque native modifiée ou un serveur
compromis de mentir ou d’accéder aux données autorisées.

Les chemins configurés, leurs ancêtres et le volume temporaire doivent être
contrôlés par le compte exécutant SWASSH. Les protections de dernier composant
et dossiers dédiés ne remplacent pas un confinement système du filesystem.
Sous Windows, `chmod` ne configure pas les ACL et l’arrêt du client ne fournit
pas le même confinement de groupe que POSIX : utiliser des ACL, des quotas et
un superviseur adaptés. La matrice CI est fournie ; seul l’environnement
explicitement indiqué dans VALIDATION a été exécuté pendant cette livraison.

Un timeout local ne prouve pas l’arrêt de la commande distante. `--delete` peut
supprimer une partie d’un arbre avant un échec ; les copies de répertoires ne
sont pas transactionnelles. Les sources répertoire doivent être figées pendant
le déploiement. La publication atomique de fichier et de rapport protège le
fichier final précédent avant le renommage, mais ne garantit pas la durabilité
en cas de coupure électrique du répertoire parent. Annuler après un renommage
peut laisser une opération déjà publiée.

La taille de fichier est surveillée toutes les 100 ms et revérifiée avant
publication ; une brève surconsommation reste possible. Le spool SQLite est
borné, mais son journal, le rapport exporté et la somme des collectes nécessitent
leur propre espace/quota. Le budget mémoire est une estimation conservatrice,
pas un contrôle RSS de tous les processus. Plusieurs instances additionnent
leurs consommations. Les benchmarks simulent les transports et n’établissent
aucune garantie sur 10 000 serveurs réseau réels.

Les rapports complets contiennent la commande, les sorties et les chemins.
L’audit conserve des métadonnées et empreintes, pas ces secrets en clair ; les
empreintes ne cachent pas un secret à faible entropie à quelqu’un qui peut le
deviner. Les logs locaux rotatifs ne sont pas une preuve inviolable : un compte
compromis peut les modifier. SIGKILL/crash peut perdre le lot non encore écrit.
Les exportations JSON gardent les sorties brutes ; leurs consommateurs doivent
traiter ces chaînes comme des données. L’aperçu console est neutralisé et borné.

L’écrivain de rapports s’exécute dans un processus distinct pour isoler son GIL.
Sur CPython 3.11–3.13, l’arrêt forcé utilise des attributs privés du pool, faute
d’API publique ; les régressions de cycle de vie doivent être validées à chaque
montée de Python. Les opérations lentes de filesystem impossibles à interrompre
au niveau OS nécessitent toujours un superviseur externe.

## Vérification et maintenance

```bash
python scripts/verify.py
python scripts/coverage.py
python scripts/build.py
python scripts/package.py
```

Le contrôle AST impose des imports standards, interdit `eval`, `exec` et
`shell=True`, puis vérifie compilation et structure DDD. Il ne remplace pas un
analyseur de vulnérabilités complet. Les workflows release sont préparés ; aucun
push Git, tag, publication GitHub ou PyPI n’est effectué ici. Configurer les
protections du dépôt et l’environnement PyPI avant utilisation.

Références primaires consultées le 6 octobre 2026 :
[avis rsync](https://rsync.samba.org/security.html),
[manuel rsync](https://download.samba.org/pub/rsync/rsync.1),
[tokens OpenSSH](https://man.openbsd.org/ssh_config).

La version 1.3.0 active aussi un canary de 1 cible par défaut, configurable par
`--canary 5`. La flotte est libérée après réussite de toute la première vague ;
sinon les cibles restantes sont skipped. Voir [CANARY.md](../../usage/CANARY.md) pour la
sélection, les phases de rapport, les limites et les tests.

## Planification persistante (1.3.0)

Voir [SCHEDULING.md](../../usage/SCHEDULING.md) pour le worker supervisé, le claim durable sans relance automatique,
les retards d’échéance, la copie des inventaires, les droits du stockage et
les journaux par tâche. Les fichiers contenant les commandes restent privés
mais ne sont pas chiffrés. Une seule flotte planifiée est admise par répertoire
d’état. Depuis 1.4.0, les invocations manuelles et les workers du même compte
partagent aussi le budget local lorsqu'ils utilisent la même racine de coordination.

## Corrections 1.3.1

Voir [HARDENING-1.3.1.md](HARDENING-1.3.1.md) : parents des chemins, source/staging, synchronisation
des publications et de l’audit, checkpoints avant admission, configuration SSH
et invariants du scheduler. Les ports injectés restent compatibles ; les
capacités optionnelles prepare/flush des adapters système renforcent les
frontières sans ajouter de dépendance à une couche extérieure au cœur.
