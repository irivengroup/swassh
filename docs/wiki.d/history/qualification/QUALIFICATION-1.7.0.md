# Qualification SWASSH 1.7.0

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / qualification / Qualification SWASSH 1.7.0

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Limites restantes](#limites-restantes)



Périmètre : sessions réutilisables POSIX, shell interactif mono-hôte, PTY
facultatif, restauration/redimensionnement du terminal, garde des ressources
et absence de reconnexion/rejeu automatique. Les preuves history-* restent
historiques et ne sont pas comptées comme contrôles actuels.

| Contrôle | Statut | Résultat observé |
| --- | --- | --- |
| Windows Python 3.14, suite et contrôles statiques | EXÉCUTÉ | 380 tests recensés, 67 ignorés, zéro échec ; 200.715 s |
| Linux Python 3.12, couverture avec prérequis SSH/Kerberos natifs | EXÉCUTÉ | 379 tests recensés, 6 ignorés, zéro échec ; 172.829 s |
| Couverture de lignes | EXÉCUTÉ | 90.74 %, seuil 90 % inchangé |
| Porte SSH native Linux | EXÉCUTÉ | 17 tests, zéro exclusion, zéro échec |
| Authentification mot de passe/SFTP et Kerberos | EXÉCUTÉ | 2 tests sans exclusion ; répétés via le banc autonome de CI |
| Porte Linux/rsync | EXÉCUTÉ | Code de sortie 0 |
| 50 000 hôtes simulés | EXÉCUTÉ | 83.71 s, 14 travailleurs maximum, 11399770 octets Python maximum dans le parent |

Les tests natifs prouvent une même connexion SSH pour deux commandes,
la conservation du code de sortie distant, le refus après perte du socket ou
du maître, l’expiration, l’annulation, l’allocation PTY facultative, le shell
dans un terminal réel de test, le redimensionnement et la restauration locale.
Les tests existants de rapports, affichage par défaut, canary, planification,
budgets interprocessus et transferts sont conservés.

La première passe sans serveur SSH disponible n’atteignait pas le seuil de
couverture. La qualification finale utilise les prérequis natifs de la CI,
sans abaisser le seuil ni exclure les nouveaux modules. Les premiers essais
ont également corrigé le classement des codes de sortie multiplexés, la
compatibilité du point d’injection du transport et les hypothèses de fins de
ligne du terminal. Les assertions portent sur les comportements observables.
Le protocole du gardien a été étendu en conservant la lecture des requêtes
antérieures ; le test d’échéance vérifie un démarrage natif réel avant l’arrêt.
Une passe Windows pendant les modifications a mélangé des modules de deux
révisions ; les preuves finales proviennent d’une copie figée dont les
empreintes Python sont comparées aux sources livrées.

Le scénario de 50 000 hôtes est simulé, pas un parc SSH réel. La mesure 1.6.0
était 70,70 s, 14 travailleurs et 11 413 309 octets Python. Ces mesures
ponctuelles sur machine partagée ne démontrent pas un gain/perte de débit ;
les bornes de concurrence et mémoire Python sont contrôlées. Elles ne couvrent
pas la RSS cumulée de tous les processus ni le trafic d’un parc réel.

Les fichiers validation/installation-review-windows.json et
installation-review-linux.json ajoutés après construction décrivent les
installations hors ligne du wheel et du sdist exacts dans des environnements
neufs. Le justificatif dist/release-verification-1.7.0.json livré à côté du ZIP
donne les empreintes et la reconstruction reproductible avec le même runtime.
Les journaux bruts privés sont exclus de la livraison.

## Limites restantes

**Qualification complète de toutes les plateformes : NON TERMINÉE.**
Aucune garantie d’absence totale de défaut. La couverture de lignes ne couvre
pas toutes les branches ni automatiquement tous les processus enfants.

| Contrôle | Statut | Raison, procédure, prérequis et risque restant |
| --- | --- | --- |
| Session réutilisable Windows | NON APPLICABLE | Mode explicitement non pris en charge, refus avant connexion ; les fonctions historiques restent disponibles. |
| Shell/PTY natifs Windows | NON EXÉCUTÉ | Console interactive et serveur de test Windows non mobilisés ; avec OpenSSH et serveur autorisé lancer shell, run --pty, resize, interruption et vérifier les modes de console avant/après. Attendu : sortie correcte et restauration. Risque : particularités du client/terminal. |
| macOS, Solaris, AIX et autres runtimes | NON EXÉCUTÉ | Machines indisponibles ; lancer verify.py et les portes natives sur chaque plateforme équipée, puis deux commandes Session et un shell/resize/annulation. Attendu : zéro échec applicable et connexion conservée. Risque : multiplexage et terminaux propres aux versions système. |
| CI distante et publication publique | NON EXÉCUTÉ | Runner/publication non mobilisés ; exécuter les workflows avant publication avec leurs dépendances natives. Attendu : toutes les portes réussissent. Risque : différences de runner/index. |
| Charge sur parc réel | NON EXÉCUTÉ | Parc autorisé indisponible ; canary puis lots croissants avec métriques CPU/RSS/connexions/latence/erreurs. Attendu : budgets respectés et aucun rejeu ambigu. Risque : saturation réseau et comportement du serveur. |
| Audit sécurité externe | NON EXÉCUTÉ | Auditeur externe indisponible ; examiner archive et clients système dans l’environnement cible. Attendu : aucun défaut bloquant non résolu. Risque : vulnérabilités non détectées localement. |

Le PTY fusionne les flux distants et peut modifier écho/fins de ligne : c’est
un effet explicite du nouveau mode, pas le comportement de run par défaut.
Le shell direct affiche les séquences terminales distantes sans journaliser
les frappes. Les coups d’arrêt non interceptables et les effets distants
inconnus restent des limites documentées. Les sessions sont mono-hôte et
ne constituent pas un pool persistant entre invocations.

Installation, menaces, contrats et retour arrière : docs/wiki.d/history/releases/RELEASE-1.7.0.md,
docs/wiki.d/operations/INSTALLATION.md et SECURITY.md. Les tâches anciennes restent lisibles ;
terminer/annuler les nouvelles tâches avant retour à 1.6.0 (champ PTY nouveau).
Les artefacts 1.6.0 sont conservés séparément.
