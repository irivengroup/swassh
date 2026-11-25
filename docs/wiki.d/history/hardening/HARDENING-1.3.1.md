# Durcissement ciblé — SWASSH 1.3.1

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / hardening / Durcissement ciblé — SWASSH 1.3.1

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Faiblesses constatées et corrections intégrées](#faiblesses-constatées-et-corrections-intégrées)
- [Compatibilité et exploitation](#compatibilité-et-exploitation)
- [Garanties et limites pratiques](#garanties-et-limites-pratiques)
- [Vérification](#vérification)



Document historique : les extensions ultérieures sont livrées dans
[HARDENING-1.4.0.md](HARDENING-1.4.0.md), dont budget partagé, Job Object et chemins épinglés.

Cette version conserve l'objectif : exécuter et transférer par SSH sur des
flottes massives, avec asyncio, des ressources bornées et des clients natifs.
Le runtime, les tests et le build utilisent uniquement Python standard.

## Faiblesses constatées et corrections intégrées

| Frontière | État précédent | Correction |
| --- | --- | --- |
| Répertoires locaux | Seul le dernier dossier privé était vérifié ; un parent partagé restait accepté | Vérification des parents avant toute création, du chemin original et de ses parents résolus |
| Liens de parents | Résolution implicite sans vérification du propriétaire et des permissions | Sur POSIX : parents appartenant au compte ou à root, sans écriture groupe/autres ; exception pour les dossiers sticky de root, comme /tmp |
| Compatibilité des chemins | Les alias système doivent rester utilisables | Alias POSIX appartenant au compte/root acceptés seulement si leur contenant et leur cible ont des parents fiables ; les liens du dernier dossier privé restent refusés |
| Windows | Protection de reparse points limitée au dernier composant | Refus des reparse points dans les parents des sorties sensibles ; ACL toujours à provisionner par l'exploitation |
| Rapports/spools | Une sortie non fiable pouvait être découverte après l'exécution si un spool distinct était fourni | Spool vérifié avant création ; destination finale préparée par le writer système avant l'admission SSH ; nouvelle vérification à l'export |
| Publication | Données de fichier fsyncées, renommage non synchronisé | Synchronisation des entrées du dossier après publication du rapport et d'un pull de fichier, sur POSIX lorsque supportée |
| Source push | Identité/taille contrôlées avant copie ; changement préalable de même taille pas distingué | Comparaison aussi de mtime_ns et ctime_ns entre lstat initial et le descripteur ouvert, puis à la fin de copie |
| Staging pull | Budget des fichiers réguliers surveillé ; autres entrées ignorées | Liens, entrées spéciales et liens physiques multiples refusés pendant la surveillance du staging d'un fichier |
| Journal actif | Flush vers le système, sans fsync | fsync par lot de 64 au plus, dans le thread I/O ; création/rotation du dossier synchronisée lorsque supportée |
| Rotation gzip | Fermeture gzip, puis publication sans synchronisation du fichier compressé | Trailer gzip terminé, fichier flushé/fsyncé avant remplacement et suppression du segment source |
| Admission auditable | Les marqueurs initiaux pouvaient rester en buffer pendant les premiers SSH | Checkpoints avant le canary et avant la flotte ; échec de synchronisation bloque les nouvelles admissions à cette frontière |
| Outbox schedule | Acquittement après flush du journal | Acquittement après synchronisation du journal ; panne d'écriture/fsync laisse les événements dans SQLite |
| Identités SSH | Quelques paramètres reposaient sur les valeurs natives par défaut | UpdateHostKeys, VerifyHostKeyDNS, AddKeysToAgent et Tunnel explicitement désactivés ; EscapeChar none |
| Paramètres numériques | Taux minuscule accepté alors que son inverse était infini | Refus des intervalles non représentables, y compris après division par deux pour ProxyJump ; dépassement numérique API converti en ValueError |
| Base schedule | En-tête/version vérifiés sans contrôle des tables/objets | Colonnes contrôlées, triggers/views refusés ; changement de schéma/version détecté pendant l'ouverture ; trusted_schema désactivé lorsque la bibliothèque SQLite le supporte |
| Métadonnées schedule | Invariants partiels sur dates/compteurs | UTC canonique, ordre création/échéance/grâce, SHA-256, dates optionnelles, run_id et compteurs validés ; snapshot du saut strict |

## Compatibilité et exploitation

La syntaxe run/push/pull/schedule, les exports Python, le canary et le profil
`-avzPH --numeric-ids --delete` sont conservés. Le repli SFTP reste limité aux
fichiers ; aucune opération de données ambiguë n'est rejouée. La base schedule
reste en schema user_version=1 : les enregistrements valides 1.3.0 rouvrent sans
migration destructive ni réécriture de leur état. Arrêter le worker pendant le
remplacement du package pour éviter un mélange de versions en exploitation.

Un emplacement partagé sans sticky de root, ou contrôlé par un autre UID, peut
être refusé là où il était auparavant accepté. Utiliser un dossier local fiable,
appartenant au compte d'exploitation. Les ACL Windows doivent limiter l'accès à
ce compte. Une jonction Windows dans un chemin sensible est désormais refusée ;
utiliser le chemin réel. Aucun dossier utilisateur n'est supprimé automatiquement.

Les adapters système appliquent les checkpoints et la préparation de sortie.
Les ports d'audit/reporting injectés existants restent compatibles : les
capacités async flush/prepare sont optionnelles. Un port tiers sans ces méthodes
ne bénéficie pas des garanties de checkpoint/préparation du port système.

## Garanties et limites pratiques

fsync demande au système la synchronisation du fichier ; ce n'est pas une
certification de la batterie/cache du contrôleur, du disque ou du filesystem.
Le dossier est synchronisé sur POSIX quand l'OS/filesystem le permet ; EINVAL,
ENOTSUP/EOPNOTSUPP sont distingués des erreurs de stockage réelles, qui remontent.
Windows conserve le fsync du fichier via l'implémentation Python, sans nouvelle
garantie de synchronisation des entrées de dossier. Utiliser des disques locaux
fiables pour état, audit et spool.

Les événements de résultat restent bornés en lots : un arrêt brutal peut perdre
le dernier lot pas encore émis, et l'outbox peut répéter un event_id après une
coupure entre publication et acquittement. Aucune promesse exactly-once distante.
Après le remplacement atomique d'un fichier, une erreur de synchronisation du
dossier peut être remontée alors que le nouveau fichier est déjà visible.
Inspecter l'état et le rapport avant une nouvelle action ; il n'y a pas de rollback
ni de relance automatique. Les opérations encore actives peuvent avoir eu des
effets distants lorsqu'un journal échoue au milieu d'une flotte.

Les propriétaires du compte et root restent de confiance. Les contrôles de
parents refusent les ancêtres non fiables au moment de leur vérification ; ils
ne constituent pas une résolution atomique de tous les composants du chemin.
Préprovisionner les parents privés dans les dossiers sticky : la création
concurrente d'un parent manquant dans /tmp reste une frontière à renforcer par
des descripteurs de répertoires. Le compte d'exploitation lui-même reste de
confiance. Le digest des snapshots détecte les corruptions, pas les modifications
intentionnelles du compte qui détient la base.

Les limites mémoire et de cadence restent par invocation. Plusieurs invocations
manuelles ou plusieurs répertoires de worker peuvent cumuler leurs charges.
Les arbres rsync et tables de hard links coûtent une mémoire dépendant des fichiers ;
max-alloc borne une allocation, pas la RSS totale. La limite de taille surveillée
concerne les transferts de fichiers simples, pas tout un arbre de répertoires.
Dans cette validation historique 1.3.1, le nettoyage des descendants ProxyJump
Windows restait à qualifier. Pour les contrôles natifs de la livraison actuelle,
consulter [VALIDATION.md](../../../../VALIDATION.md).
Ces points prioritaires sont détaillés dans [IMPROVEMENTS.md](../IMPROVEMENTS.md).

## Vérification

Les 22 tests supplémentaires de tests/test_hardening_massive.py exercent les
parents partagés/alias/propriétaires, la conservation des sorties précédentes,
le refus avant SSH malgré un spool sûr, le parsing OpenSSH natif, les changements
de source, les liens de staging, les fsync et la publication gzip, le caractère
borné/hors boucle des batches, l'outbox et les bases existantes/corrompues.
Les tests complets précédents sont conservés. Les preuves finales sont dans
VALIDATION.md et validation/, avec les limites des intégrations exécutées.

Références : [Python os.fsync](https://docs.python.org/3/library/os.html#os.fsync),
[SQLite PRAGMA trusted_schema](https://www.sqlite.org/pragma.html#pragma_trusted_schema),
[OpenSSH ssh_config](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
