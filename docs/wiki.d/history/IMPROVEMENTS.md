# Améliorations livrées — 1.4.2

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / Améliorations livrées — 1.4.2

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->


Les sept propositions de la version 1.3.2 sont implémentées. Le périmètre reste
le déploiement massif et les transferts SSH, avec asyncio, Python standard et
les clients natifs OpenSSH/rsync/SFTP. Aucun agent distant n'est ajouté.

| Proposition | Implémentation | Vérification disponible |
| --- | --- | --- |
| Budget partagé du bastion | SQLite local, files FIFO, leases protégées par verrous OS, connexions/rythme/mémoire/débit communs | Dix processus indépendants sous deux slots ; mémoire retenue après mort du parent ; pacing ProxyJump et récupération sans replay |
| Descendants Windows | Guardian placé dans un Job Object avant création du client ; héritage natif, kill-on-close et aucun breakaway | Contrats ctypes testés ; tests natifs de descendants inclus dans la CI Windows |
| Chemins locaux épinglés | Traversée POSIX par dir_fd ; export relatif et atomique ; handles Windows sans FILE_SHARE_DELETE | Échange d'un parent pendant l'export ; course mkdir/lien ; refus des reparse points ; contrats DACL |
| Prévisualisation rsync | --dry-run, itemisation sans noms de fichiers, compteurs ajout/modification/suppression | Rsync local réel : les données et mtimes de destination restent identiques ; 10 000 records agrégés |
| Intégrité opt-in | --verify-sha256 pour un fichier, comparaison avant publication | Push/pull SFTP natifs avec SHA-256 ; corruption et publication ambiguë refusées sans replay |
| Admission adaptative | --adaptive, baisse multiplicative, remontée progressive et coupe-circuit persistant pour la flotte | Plafonds respectés, timeouts/unreachable seuls, skipped avec zéro tentative, stderr sans influence |
| Progression et mesures | --progress sur stderr, métriques d'audit constantes en mémoire | Affichage sans lignes par serveur, cadence >= 1 s, schéma JSON/CSV final conservé |

Les détails et les conditions d'exploitation sont dans
[HARDENING-1.4.0.md](hardening/HARDENING-1.4.0.md). Les résultats réellement exécutés sont
consignés dans [VALIDATION.md](../../../VALIDATION.md). Les correctifs de cette livraison
sont décrits dans [RELEASE-1.4.1.md](releases/RELEASE-1.4.1.md), complétés par la
[qualification réseau 1.4.2](releases/RELEASE-1.4.2.md). La présence d'une matrice
CI ne constitue pas une preuve de son exécution distante.
