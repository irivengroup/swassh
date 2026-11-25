# SWASSH 1.5.0 — installation et rapports

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / releases / SWASSH 1.5.0 — installation et rapports

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Impact et décisions](#impact-et-décisions)
- [Exploitation et rollback](#exploitation-et-rollback)
- [Qualification](#qualification)



Demande utilisateur du 10 octobre 2026. La 1.4.2 reste intacte et restaurable.

## Impact et décisions

| Domaine | Changement et risque traité |
| --- | --- |
| Installation | Installateur hors ligne puis setup-path explicite POSIX ; profils sauvegardés, symlinks et fichiers spéciaux refusés. Le shell courant doit exécuter l'export affiché. |
| CLI | run, push, pull, schedule et canary conservés ; setup-path ajouté. |
| Données | changed booléen optionnel ajouté aux résultats, JSON et colonne CSV. SUCCESS reste le statut pour les modifications explicitement déclarées. |
| Texte | Sorties des succès masquées par défaut ; --show-output affiche chaque hôte ; --output-lines 0 montre toutes les lignes capturées ; dix lignes par flux exceptionnel et 240 caractères par ligne ; groupes représentatifs et omissions annoncées. |
| JSON/CSV | Indentation progressive sans liste de flotte en mémoire ; CSV séparé par lignes vides, données multiligne conservées. |
| Sécurité | Contrôles terminal neutralisés en texte, couleurs seulement interactives, NO_COLOR ; protections CSV existantes préservées. |
| Asynchrone/processus | File et propriétaire unique du spool inchangés ; sérialisation de changed et groupement dans le processus enfant testés. |
| Débit | Échéance du pacer revérifiée après réveil anticipé, observé sous Windows Python 3.11. Test déterministe ajouté. |
| Tests | Horloge simulée pour FIFO/bande passante ; reset TCP attendu accepté uniquement au nettoyage du test SSH après assertions. |

## Exploitation et rollback

Utiliser `python3 scripts/install.py dist/swassh-1.5.0-py3-none-any.whl` depuis
l'archive extraite. L'installateur ne résout aucune dépendance réseau. Il annonce
les sauvegardes privées des profils et la commande pour le shell courant. Un
échec de setup-path laisse le paquet installé et renvoie un échec explicite.
Windows et environnements virtuels : `--skip-path` et activation/configuration
native. Ne pas ajouter durablement le bin d'un environnement virtuel aux profils.

Pour revenir au moteur précédent : installer la wheel 1.4.2 archivée, puis
restaurer uniquement les profils modifiés depuis leurs sauvegardes, après
comparaison avec leurs éventuelles modifications ultérieures. Aucun état de
schedule ni budget partagé n'est migré. Le spool de rapport reste temporaire.
Les consommateurs CSV qui fixent strictement les colonnes doivent accepter la
colonne additive changed et ignorer les lignes vides. JSON garde schema_version 1
avec champ additif. Les sorties capturées restent limitées par max_output_bytes.

Aucune règle ne peut déterminer universellement CHANGED à partir d'une commande
opaque. L'adaptateur doit le déclarer ; les clients natifs ne l'inventent pas.
Les couleurs des exports ne dépendent jamais du TTY du processus enfant.

## Qualification

Les résultats réellement exécutés et les limites figurent dans VALIDATION.md.
Les preuves 1.4.2 ne sont pas réattribuées à cette version.

Statut : candidat de qualification. Une instabilité du contrôle d’installation Linux reste non expliquée ; voir VALIDATION.md.
