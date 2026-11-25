# Protocole et historique de validation SWASSH 2.0.1

## Correctif CI et portabilité 2.0.1 — conditions d'admission

Cette candidate conserve les douze cases Python 3.11–3.14 de la CI et les cinq
seuils à 98 % par module/composant. Le checkout désactive la conversion automatique
des fins de ligne ; les empreintes des oracles v1 restent inchangées. Le lanceur
QA configure uniquement le propriétaire par défaut des nouveaux objets du
processus Windows. Il ne modifie ni les privilèges, ni les groupes, ni les DACL ou
propriétaires existants ; le refus des répertoires étrangers reste inchangé.
Les erreurs des commandes natives PowerShell et des pipelines bash restent bloquantes.

Le contrôle TCP_NODELAY accepte le booléen natif non nul (1 sous Linux, 4 sous
Darwin) et refuse toujours zéro, une remise de descripteur invalide ou un helper
en échec. Le test du terminal compare tous les attributs à un aller-retour natif
sur un second PTY : aucun bit n'est masqué et aucune entrée utilisateur n'est vidée.
La reprise après SIGKILL exige à la fois la disparition du client et la capacité
libérée dans le même budget de récupération de 2,5 secondes, sans rejeu.

Le nettoyage du groupe natif conserve son délai de grâce de 0,35 seconde.
Un refus de signal peut déclencher des observations avec le signal zéro : seul
ESRCH, constaté avant l'expiration du délai initial, établit la disparition du
groupe. Un groupe encore présent, inaccessible ou observé trop tard reste un
échec ; aucune commande n'est rejouée. Les contrats portables vérifient aussi
l'enveloppe littérale produite par le relais TCP et la limite UTF-8 de sa
configuration, indépendamment des fixtures SSH propres à chaque plateforme.

La création d'un fichier partagé sous Darwin utilise une création exclusive,
puis une ouverture sans création uniquement après EEXIST. Le descripteur du
parent, les protections contre les liens, les permissions et les vérifications
de propriétaire/type/nombre de liens restent inchangés. Une entrée supprimée
entre ces deux opérations est refusée ; aucune temporisation, répétition ou
ouverture par chemin absolu ne masque l'erreur. Les ouvertures explicitement
exclusives, sans création et sur les autres systèmes conservent leur parcours.
La régression reproduit l'ENOENT observé sur la référence conservée et vérifie
les refus de liens, fichiers spéciaux, permissions et erreurs de stockage.
Le benchmark conserve ses opérations, sa concurrence et tous ses délais.

La sonde de déploiement résout strictement son propre répertoire temporaire
avant de construire les chemins attendus. Cela préserve la comparaison exacte
du lanceur et du profil installés lorsque le système utilise un alias /var.
La recette conserve toutes ses assertions d'installation, d'idempotence et
de refus ; sa régression utilise un véritable alias de dossier privé.

macOS reçoit la même source rsync 3.5.2, avec SHA-256 et signature vérifiés ; le
binaire système est conservé. Les essais de cette CI sur runners macOS ne valent
pas recette sur un équipement réel ou sur un bastion macOS d'entreprise.

Les recettes et couvertures historiques ci-dessous restent rattachées à leurs
révisions d'origine. La livraison 2.0.1 exige de nouvelles preuves locales, une
revue SAST détachée de ses octets exacts et la réussite de toute la CI avant
publication. L'approbation C139 ne qualifie pas automatiquement ces modifications.

## Correctifs de reproduction de la CI Linux

Le job Linux compile la distribution source rsync **3.5.2** publiée par le
projet amont. Le script vérifie le SHA-256 et la signature détachée avec la
clé dont l’empreinte primaire est épinglée avant toute extraction. Les
bibliothèques de compilation et OpenSSH proviennent des dépôts Ubuntu signés.
L’installation du binaire de recette conserve la copie de la distribution par
diversion dpkg et vérifie la version installée. Voir
[les distributions officielles et la clé de signature](https://rsync.samba.org/download).

Le benchmark crée le dossier du rapport demandé, y compris sur une extraction
neuve. La campagne de planification transmet le chemin absolu du checkout
aux CLI lancées depuis son espace de travail temporaire. Le test PTY vérifie
la taille distante sur un enregistrement préfixé par un marqueur que la
commande recopiée ne contient pas, puis contrôle la restauration de l’état
du terminal local. Il fonctionne avec une invite interactive normale.

## Qualification SAST v2 et maintien des contrôles

Le contrat v2, autorisé sous condition de vérification, sépare le résultat brut
du scanner de la revue de chaque signal. La politique et la frontière de
confiance actuelles figurent dans `SECURITY.md`. Les mentions du contrat brut
v1 dans l'historique ci-dessous décrivent leurs révisions d'origine ; elles ne
constituent ni une approbation des alertes ni une dérogation aux contrôles v2.

Les cas d'acceptation portent sur l'encodeur pur B404, sans enfant natif, et sur
un shell dangereux analysé sans être exécuté. Ils vérifient aussi l'autorité
détachée, les empreintes, appelants, preuves, refus de caches compilés et hooks
d'import, rapport absent, timeout et inventaire de scan incomplet. Les quatre
oracles v1 sont conservés dans leur référence versionnée et restent exécutés.
La réussite de ces cas n'est pas une qualification collective des signaux du
projet et ne suffit pas à publier un paquet.

L'examen préalable à l'adoption inclut aussi les entrées hors inventaire :
fichier Python à la racine, cache compilé applicatif, manifeste auto-déclaré et
distribution préconstruite. L'inventaire d'une ancienne revue ne doit pas rester
valide en présence de ces entrées. Le scan reçoit donc un arbre propre de
sources maintenues après vérification indépendante de l'archive complète ; les
artefacts et preuves externes ne sont ni exécutés ni effacés par cette préparation.
Les attributs réels de lien/reparse sont inspectés jusqu'à la frontière du
répertoire détenu : un alias Windows court/long ordinaire n'est pas un lien.
Le contrôle doit conserver le refus d'une véritable jonction et identifier
correctement les hooks ou caches derrière un chemin ordinaire. L'empreinte du
rapport est calculée sur les octets mêmes qui ont été analysés, sans seconde
lecture pouvant désigner un remplacement. La CI vérifie aussi la source et le
verrou QA détachés avant d'installer ses dépendances ; chaque test de fraîcheur
est une commande distincte pour conserver le refus sous les règles bash de CI.

Chaque recette de livraison doit repartir de l'archive extraite identifiée,
conserver le JSON Bandit original, son code réel, les décisions individuelles,
le reçu externe du lanceur et les cinq mesures source indépendantes. Les
compteurs Python bruts restent séparés. Aucun collecteur de couverture, seuil,
module requis, assertion métier ou budget de recette n'est modifié par v2.

La revue du vérificateur inclut les alias de casse réels de Windows. Un témoin
inoffensif a confirmé qu'un cache `.PYC` sous `__PYCACHE__` pouvait être chargé
alors que les sources originales de l'outil restaient inchangées. Les contrôles
de cache et de hook examinent donc ces variantes de casse avant lancement.
Une autre recette ajoute une déclaration de plugin à une distribution existante
sans changer ses fichiers originaux : cette entrée supplémentaire doit aussi
être refusée. L'inventaire complet des fichiers installés complète la comparaison
des membres des wheels. Les objets non réguliers du scanner et des sources sont
refusés ; ils ne sont ni lus de façon bloquante ni omis du catalogue. Les témoins
antérieurs et leurs résultats restent conservés, et les nouveaux refus ne
remplacent aucun des tests précédents. Les six régressions supplémentaires
portent sur ces causes, avec un refus des modifications non revues et une
installation d'origine toujours admise.

## Nettoyage des sondes de connecteur natif

Chaque sonde d'aide ou de descripteur est lancée dans sa propre session POSIX.
Le nettoyage conserve l'arrêt et l'attente bornée du processus principal, puis
arrête son groupe même si le principal est déjà sorti. Cela couvre les enfants
ordinaires d'un wrapper qui retiennent un tube ou le socket de contrôle. Les
contrôles de confiance, limites de sortie, délais 1/2 secondes et refus de repli
après sélection restent inchangés. Les programmes qui se détachent volontairement
du groupe restent hors de cette garantie ; les wrappers sont de confiance.
Les régressions utilisent seulement des exécutables temporaires privés et un
échange fdpass loopback, sans cible SSH. Les erreurs de nettoyage restent visibles.
Le signal Bandit générique sur les deux lancements reste conservé.

## Périmètre actif — décision utilisateur du 7 novembre 2026

La qualification courante couvre les cinq environnements locaux : Windows avec Python 3.11, 3.12, 3.13 et 3.14 ; Linux avec Python 3.12. Les tests sur équipements réels, macOS, AIX et Solaris sont désormais hors périmètre et NON APPLICABLES à cette livraison, à la demande explicite de l’utilisateur. Aucune qualification de ces cibles n’est revendiquée. Leurs anciens statuts NON EXÉCUTÉ restent conservés comme historique, sans constituer un blocage du périmètre courant.

Les suites locales, les contrôles existants et les cinq couvertures indépendantes >=98% globalement, par composant et par module restent obligatoires et inchangés. La CI distante reste à exécuter lorsqu’un dépôt autorisé sera disponible. Les alertes Bandit brutes sont conservées ; aucune règle, suppression, baseline ou exclusion supplémentaire n’est autorisée pour faire accepter une livraison.

### Correction de l’inspection du connecteur natif

La revue du contexte de B603 dans relay_connect.py a confirmé un blocage avant lancement du programme : ouvrir un tube nommé en lecture attendait un écrivain avant la vérification fstat du type de fichier. L’ouverture non bloquante permet de refuser ce fichier spécial immédiatement. Le test réel reproduit le blocage antérieur et vérifie le refus, l’absence de sous-processus et la fermeture du thread de contrôle après correction. Les contrôles de propriétaire, permissions, no-follow, sortie d’aide et délais 1/2 secondes sont conservés. Le signal Bandit générique sur l’appel subprocess reste visible ; sa présence n’est pas assimilée à la persistance du blocage corrigé.



### Fournisseur de mot de passe de la fixture Linux

Le helper askpass temporaire cite le chemin du fichier comme un argument shell littéral et utilise /bin/cat sans recherche dans PATH. Les espaces, apostrophes et substitutions de commande dans un nom de répertoire ne deviennent pas du code. Les modes 0700 du helper et 0600 du fichier restent inchangés ; un fichier absent provoque un échec. Les tests exécutent le helper réel dans des fichiers privés et interceptent les mutations de comptes ; la recette d’authentification complète conserve ses espaces de noms privés. Ce contrat du helper ne revendique pas la prise en charge de tous les noms possibles par les formats de configuration Kerberos ou les options de montage.


### Erreur de fermeture des réservations partagées

Une erreur de fermeture reste propagée. Si le flux est effectivement fermé, le marqueur local de propriété est libéré : la récupération normale peut alors reprendre la capacité après rollback SQLite. Si le flux reste ouvert, la réservation est conservée. Trois régressions utilisent des fichiers et verrous réels, SQLite et un processus indépendant ; les quotas, le débit et la file FIFO sont inchangés.


### Résolution des outils de qualification d’authentification

Le gate choisit mount, ip et unshare uniquement dans /usr/sbin, /usr/bin, /sbin et /bin. Le PATH de l’appelant ne remplace plus le programme qui établit l’isolation, ni les montages et le réseau de sa fixture. Un prérequis absent provoque un échec explicite. Les six nouvelles régressions exécutent des substituts inoffensifs dans des répertoires temporaires privés ; elles interceptent le provisionnement des comptes. Le PATH des processus enfants et des outils de provisionnement est explicitement limité aux répertoires système ; le KDC est résolu dans ces mêmes répertoires et son absence est fatale. Les flags d’isolation, vérifications root/PID, délais et recettes natives complètes sont conservés.

## Contrat adopté des lignes source — schéma 6, 4 novembre 2026

Après l’examen en lecture seule cycle8f, l’utilisateur adopte la distinction des
corps `typing.Protocol` sans implémentation et demande sa correction vérifiée.
Cette adoption ne transforme pas les refus historiques du schéma 5 en succès.
Les cinq seuils de 98 %, globalement, par composant et par fichier avant arrondi,
restent inchangés. Les signatures ne sont ni reformatées ni appelées artificiellement.

Les lignes source sont l’union des tables de lignes des objets de code conservés
comme implémentations. Seuls les corps vérifiés d’une méthode de Protocol ne
contenant, après docstring éventuelle, que `pass` ou `...` sont distingués. Les
fonctions ordinaires vides, méthodes par défaut, levées d’exception, création de
classes/fonctions, décorateurs, valeurs par défaut et helpers d’annotations restent
inventoriés. Une ligne partagée avec du code exécutable reste dans le dénominateur.
Un alias ambigu n’autorise aucune exclusion. Seuls des événements réels créditent
les lignes ; aucune exécution d’un corps n’est déduite de sa déclaration.

Le schéma source 6 contient un inventaire reconstructible : source exacte encodée
en base64, empreinte du module, lignes d’implémentation, corps et lignes exclusivement
déclaratifs. Le gate compile sans l’exécuter cette source vérifiée, sur le même
interpréteur de mesure, et recalcule inventaire, projection des observations et
agrégats. Toute altération de source, exclusion non prouvée, observation absente,
agrégat incohérent, runtime incompatible ou couverture insuffisante reste refusée.
La source de chaque module est bornée à 2 Mio ; un dépassement refuse la mesure,
il n’exclut pas le module. Les données encodées restent du code, jamais des secrets.

Les compteurs Python bruts du schéma 4 sont conservés intégralement et séparément,
avec leurs dénominateurs, événements manquants et refus. Leur instrumentateur et
le protocole des enfants ne changent pas. Le gate garde la compatibilité de lecture
du schéma 5 et son égalité stricte des lignes source/brutes ; les nouvelles campagnes
génèrent le schéma 6. Les premières réparations et preuves décrites plus bas restent
historiques, liées à leurs anciennes archives. Les projections de la revue ne sont
pas des mesures de la correction : la nouvelle archive doit être requalifiée.


## Admission locale de la version 2.0.0

La version 2.0.0 reprend 2.0.0rc3 avec les métadonnées de la version stable.
Le passage à la version stable ne modifie ni les interfaces, ni les schémas
SQLite, ni les contrôles de sécurité et de qualification.

Toute preuve obligatoire absente, échouée ou liée à une autre archive impose
**Statut final : 🔴 NON TERMINÉ — NE PAS DÉPLOYER.**

Les campagnes intermédiaires ci-dessous ne qualifient pas l'archive finale.
Le document rc4 est conservé intégralement dans
[QUALIFICATION-1.8.0rc4.md](docs/wiki.d/history/qualification/QUALIFICATION-1.8.0rc4.md).
Ses anciens résultats ne sont pas des mesures de cette révision.
Ce fichier est figé avant la campagne d'extraction. Le reçu de qualification
et le rapport livrés à côté du ZIP portent son SHA-256 exact, les résultats
finaux et les cinq matrices par composant. Ils évitent une référence circulaire
où l'ajout du reçu modifierait l'empreinte de l'archive qu'il qualifie.

## Périmètre et contrats

Le besoin couvre complétude, robustesse et sécurité de SWASSH, avec idempotence
déclarative, dépendances durables, canaux binaires et tunnels. La matrice accessible
est [ACCEPTANCE-SCALE.md](docs/wiki.d/reference/ACCEPTANCE-SCALE.md). Aucun CDC
formalisé distinct, identifiant, version ou date de CDC n'a été fourni.
Le [Wiki](docs/index.md) expose les contrats et les limites. Python standard,
OpenSSH strict et les formats de rapport sont conservés. Les nouvelles bases
SQLite sont séparées du scheduler. Aucune publication externe n'a été effectuée.

## Contrôles de recette permanents

Les contrôles d’acceptation de benchmark.py, qualify_schedule.py,
validate_deployment.py et validate_installation.py sont des gardes explicites.
Ils vérifient les mêmes 62 prédicats et messages qu’auparavant, y compris
lorsque Python est lancé avec -O. Les résultats invalides provoquent toujours
AssertionError ; les seuils, délais, fixtures et cas de refus sont conservés.
La non-régression refuse un benchmark échoué, incomplet ou surengagé sous
Python optimisé et fige séparément chacun des contrôles d’origine.
Cette correction ne modifie ni le contrat des cinq couvertures, ni leur
instrumentation, ni les sources runtime. La qualification de l’archive
courante et ses résultats restent dans les reçus externes liés à son SHA-256.

### Fermeture des canaux avec sortie non lue

Une fermeture explicite ou une erreur libère les files bornées puis
maintient les lecteurs jusqu’à la fin des pipes pendant l’arrêt natif.
Les octets suivants sont jetés sans agrandir les captures et sans
annoncer de réussite. Les tâches de lecture sont annulées et jointes
après cette frontière ; le nettoyage possédé est partagé et attendu
malgré les annulations répétées. Le délai de recette natif de huit
secondes reste inchangé. Les garde-fous de capture, de stockage,
d’authentification et les cinq couvertures restent obligatoires.

### Initialisation et démarrage immédiat des tâches

Le canal initialise son état de fermeture, de capture et de nettoyage avant de
créer ses lecteurs. Une fabrique de tâches peut exécuter leur coroutine pendant
la construction : des sorties déjà reçues ou un EOF immédiat doivent rester
lisibles, sans erreur d'attribut ni tâche abandonnée. Le test utilise la fabrique
standard `asyncio.eager_task_factory` sur Python 3.12 et suivants ; cette API
n'existe pas sous Python 3.11, où ce seul nouveau cas est NON APPLICABLE.
Les autres tests de canaux, délais et plafonds restent obligatoires.

### Valeurs JSON et export borné

Les séparateurs Unicode NEL, LS et PS sont des caractères licites dans une
chaîne JSON : ils ne doivent pas devenir des retours à la ligne non échappés.
Seuls les LF structurels du rendu indenté reçoivent un préfixe d'indentation.
Chaque valeur déjà bornée est écrite d'un bloc ; le tableau complet reste
produit par itération, avec le même contrôle d'annulation par enregistrement.
Les validations des modèles et du spool, les transactions SQLite, l'écriture
atomique et la propagation des erreurs d'écriture restent inchangées.
Le scénario de 10 001 résultats et le délai d'export de 60 secondes restent
intacts. Une mesure ciblée ne remplace pas les cinq collectes complètes ni
l'admission de l'archive reconstruite depuis une extraction isolée.

### I/O durable et fin d'étape

Le propriétaire attend directement le futur de l'exécuteur natif avec une copie
du contexte appelant et les mêmes arguments. L'annulation de l'appelant n'est
pas transmise au futur : chaque opération déjà soumise reste possédée et jointe,
y compris après des annulations répétées ; son erreur reste visible. Le futur
de drainage possède aussi directement sa jointure, sans tâche intermédiaire.

Pendant serve, le workflow garde un propriétaire natif unique sur un
exécuteur privé borné à un thread et une seule commande admise à la fois. Le
pool partagé reste disponible, même avec un seul thread. Chaque commande garde
sa propre copie du contexte appelant. Une commande concurrente est refusée ;
aucune file non bornée ni répétition automatique n'est ajoutée.

Le propriétaire survit aux erreurs d'une commande et reste possédé jusqu'à la
fermeture du scope. L'annulation rejoint la commande admise, puis le travailleur
et son thread avant libération du verrou du stockage. Une sortie prématurée du
travailleur rend l'erreur visible et interdit toute nouvelle commande. Les
autres usages de l'I/O durable gardent leur soumission ponctuelle habituelle.

La fin d'une étape et la première lecture de son outbox partagent un passage
natif. Le surveillant d'arrêt est joint avant la livraison des événements.
La fermeture durable de l'audit précède son acquittement dans une transaction
distincte. Après le dernier acquittement et une outbox vide, la définition est
lue dans ce même passage natif, dans le contexte appelant. Les lots apparus
entre-temps sont livrés avant cette lecture. Une absence de run ne lit aucune
définition ; une erreur de lecture ou d'audit reste visible sans répétition ni
requalification d'une persistance terminale.

Les arguments, validations, ordre des opérations de stockage, transactions,
mode SQLite DELETE/synchronous=EXTRA et délai historique de trois secondes
restent obligatoires. Les comparaisons de contention comptent toute soumission
à l'exécuteur natif, qu'elle utilise to_thread ou directement run_in_executor.

## Campagnes intermédiaires

### Horloges et canaux Windows — reprise du 4 novembre 2026

La qualification de l'archive intermédiaire cycle8b conserve son refus Windows :
le test de cadence échoue et les lignes d'attente inactive du scheduler restent
à 97/99, soit 97,97979797979798 %. Le reçu Linux de cette même archive réussit
ses onze contrôles locaux ; il ne qualifie pas les changements suivants.

Un témoin indépendant sans import SWASSH observe seize intervalles réels de
plus de 10 ms que l'horloge Windows `GetTickCount64` affiche sous 8 ms. Un autre
témoin constate aussi une admission réellement trop précoce dans l'ancien
limiteur. Le limiteur mesure maintenant l'intervalle avec le compteur monotone
haute résolution `perf_counter`, en revérifiant après chaque réveil. Le test
d'origine conserve son seuil, sa concurrence et ses assertions ; seule son
observation utilise également ce compteur. Le test de réveil anticipé garde
ses deux attentes et leurs durées exactes. La nouvelle régression reproduit
l'échec avant correction. Trente séries locales après correction n'observent
aucune admission prématurée ; cela ne constitue pas la qualification finale.

Un test supplémentaire du scheduler utilise un véritable timeout et un arrêt
par événement en mémoire. Il observe les deux lignes manquantes sans dépendre
du délai d'accès SQLite. Tous les anciens tests restent identiques. Une mutation
qui laisse échapper ce timeout est refusée sous les cinq interpréteurs contrôlés.

Le vrai client OpenSSH Windows réussit les commandes, la séparation des sorties
et les refus de clés contre un serveur Linux privé sur loopback. Il refuse en
revanche la lecture de son journal `-E` pendant un canal persistant, y compris
avec les modes de partage Win32 usuels. Le témoin de canal nommé ne fournit
aucun diagnostic et n'est pas retenu. Les preuves de ces refus sont conservées.

Sur Windows, les scopes utilisent désormais une confirmation locale privée,
aléatoire et atomique, produite par l'option OpenSSH `LocalCommand` après
authentification et initialisation des forwards. Cette option est limitée au
callback interne : interpréteur littéral, module fixe, requête bornée encodée,
aucune interpolation d'hôte ou de commande distante, `EscapeChar none` conservé.
Le contrôle de clé hôte, les identités, les délais et les plafonds restent actifs.
Le répertoire possède une ACL privée ; le lecteur refuse liens, fichiers spéciaux,
contenus inattendus et dépassements. Pendant l'exécution, la taille du journal
reste surveillée par métadonnées ; son contenu est lu après fermeture du client.
Les deux flux distants restent binaires et indépendants. La fermeture attend
aussi la libération des handles Windows. Un témoin natif indépendant conserve
les refus de mauvaise clé, mauvaise identité et port occupé.

L'essai natif suivant réussit le canal binaire, puis refuse le téléchargement
SFTP à cause du même partage de fichier. La surveillance Windows de staging
utilise maintenant un handle de métadonnées sans droit de lecture des données,
avec `GetFileInformationByHandle` : taille complète, nombre réel de liens,
refus des reparse points, répertoires et handles non disque. Les plafonds,
la validation finale du descripteur, les hash et la publication atomique restent
inchangés. La nouvelle régression échoue avant correction et réussit ensuite ;
les anciennes assertions et les refus de liens/fichiers spéciaux sont conservés.
Le témoin Win32 natif confirme la lecture de taille/liens pendant que le vrai
client possède le journal. Les erreurs d'API restent des refus explicites.

Les nouveaux contrôles, fixtures et sources sont obligatoires dans le packaging.
La couverture complète du cycle8d réussit les tests Linux mais refuse encore
le nouveau module : sa branche de lancement autonome reste à 41/42 et ses
conditions à 35/36. Le test ajouté invoque réellement le module, exige une
confirmation silencieuse, puis vérifie le refus d'une requête invalide sans
publication ni fuite du contenu de la requête. L'observation parent/enfants
atteint 100 % sur les cinq métriques de ce module sous les cinq interpréteurs
locaux contrôlés. Le mutant supprimant l'appel d'entrée est refusé. Les sources
de production, collecteurs et dénominateurs restent identiques entre ces deux
observations ; tous les tests antérieurs sont préservés. La nouvelle extraction
complète reste requise avant d'attribuer ces résultats ciblés au logiciel entier.
La campagne Windows cycle8d conserve aussi le refus de branches et conditions
dans les canaux et les transferts. Les stratégies désormais séparées exigeaient
des scénarios supplémentaires : lecture POSIX sans callback, attente des deux
preuves d'authentification/écoute, diagnostic avant création du processus,
scan par descripteur, taille et liens multiples. Les nouveaux tests exercent
ces contrats par ports explicites sur chaque hôte. Les ports de descripteur
sur Windows ne sont pas présentés comme une exécution de l'ABI POSIX.
Les décisions manquantes concernées sont réellement observées sous Windows
3.11/3.14 et Linux 3.12 ; cinq mutations supprimant ces protections sont refusées.
Les assertions antérieures et tout le code de production restent inchangés.
Les nouvelles couvertures doivent être remesurées depuis une nouvelle extraction.
Aucun environnement externe n'a été fourni : la connaissance des protocoles et
les essais locaux ne remplacent pas une recette matérielle, macOS, AIX ou Solaris.

Références techniques : [horloges Python](https://docs.python.org/3.12/library/time.html#time.perf_counter),
[LocalCommand OpenSSH](https://man.openbsd.org/ssh_config#LocalCommand),
[ordre d'initialisation OpenSSH Windows](https://github.com/PowerShell/openssh-portable/blob/latestw_all/ssh.c),
[partage des fichiers OpenSSH Windows](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/fileio.c).
Les contrats de [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
et de [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle)
définissent la consultation sans lecture de données et les métadonnées exigées.

Les lignes ci-dessous décrivent la première construction rc1 et restent des
preuves historiques. Le cycle de travail suivant, non publié, conserve la
version de préparation 2.0.0rc1 mais possède d'autres empreintes de sources.
Il n'est pas contenu dans l'archive rc1 initiale. Ses nouveaux reçus externes
identifient chaque copie figée ; ne pas attribuer leurs résultats à l'ancien ZIP.

Les premiers cycles conservaient le délai de 0,3 s et l'attente exacte de sortie
partielle du test SSH original. Après des séries ciblées réussies, la campagne native complète a
encore reproduit une sortie vide. Un test indépendant du descripteur a ensuite
montré TCP_NODELAY=0 pour le connecteur natif sélectionné et TCP_NODELAY=1 pour
le connecteur Python. La sélection exige désormais cette option sur un vrai
socket local ; la nouvelle campagne complète reste nécessaire. Un succès
ponctuel ne clôt pas cette régression.

Le cycle suivant a reproduit la sensibilité avec deux campagnes SSH concurrentes
et toute l'instrumentation parent/enfants. Le contrat « après admission » est
maintenant explicite : création du gardien comptée, préparation/admission locale
bornée séparément, puis délai actif initial inchangé. Les observations locales
sont atomiques et refusent les reçus invalides ; elles ne dépendent pas des
sorties distantes. Les tests en mémoire de démarrage lent et de sortie partielle restent
inchangés. Trois paires alternées sur une étape de cette correction ont observé
4 échecs sur 30 avant, puis zéro sur 30 après, sans skip ; les refus renforcés
ultérieurs et la révision finale exigent leur propre nouvelle recette. Les
preuves initiales ne sont ni effacées ni transformées en succès historique.

Une campagne ultérieure sur le même code a encore observé deux sorties absentes
sur dix cas sous contention. Le contrat couvre l'authentification dans le délai :
un timeout peut donc arriver avant toute sortie. L'ancienne attente d'une sortie
avant 0,3 s mélangeait une propriété fonctionnelle et une hypothèse de vitesse.
Les deux anciens corps de test et leurs échecs restent conservés dans les preuves.

La suite native distingue désormais deux contrôles obligatoires. Le premier
garde command_timeout=0,3 s devant un pair dont la négociation est bloquée :
timeout, aucune sortie, aucun rejeu et aucune commande exécutée. Le second
utilise un budget de préparation fini de 10 s, puis avance réellement
l'échéance du parent à 0,3 s après réception effective d'octets, afin de vérifier
leur conservation exacte. Aucun temporisateur n'est désactivé ; le watchdog
natif reste borné. Ce second test ne mesure pas une invocation entière à 0,3 s.
Les deux chemins, connecteur par défaut et connecteur Python imposé, sont exercés.
Des copies mutantes avec délai tardif, sortie perdue ou faux succès sont refusées.
Le code de production, les seuils et les compteurs ne changent pas pour cette
réparation de test, fondée sur le contrat existant et une preuve avant/après.

| Contrôle | Résultat observé | Statut |
| --- | --- | --- |
| Référence Windows rc4 originale | 439 tests, 75 ignorés, zéro échec, 161.307 s | EXÉCUTÉ |
| Référence Linux rc4 sur stockage Windows monté | 439 tests, 36 ignorés ; un délai de nettoyage échoué | ÉCHOUÉ |
| Diagnostic sur sources identiques et stockage Linux natif | Même test et attente : réussite en 0.313 s ; échecs initiaux conservés | EXÉCUTÉ |
| Première suite Windows de la candidate | 505 tests, 75 ignorés, zéro échec, 189.715 s ; avant relais et derniers correctifs | EXÉCUTÉ |
| Mesure instrumentée Windows | 508 tests, 75 ignorés, zéro échec, 220.995 s ; cinq seuils refusés | ÉCHOUÉ |
| Mesure instrumentée Linux | 512 tests, 38 ignorés, zéro échec, 219.308 s ; cinq seuils refusés | ÉCHOUÉ |
| Relais, canaux, sessions, convergence, workflows et architecture Linux | 95 tests, zéro exclusion, zéro échec, 12.862 s ; copie temporaire native | EXÉCUTÉ |
| Relais Windows et lancement par OpenSSH avant authentification | 13 tests, zéro échec, 6.676 s | EXÉCUTÉ |
| Mutation ciblée du plafond de débit | Suppression du débit détectée : 0.005929999999352731 s sous le minimum de 1.4 s | EXÉCUTÉ |
| Intégrité des checkpoints après correction | 21 tests de workflows, zéro échec ; défaut reproduit sur révision précédente vérifiée par SHA-256 | EXÉCUTÉ |
| Première vérification Wiki après migration | 49 pages, chemins/ancres locaux, hiérarchie et clôtures contrôlés | EXÉCUTÉ |
| Installation Windows hors ligne | Wheel et sdist dans deux environnements neufs ; 86 sources Python installées identiques ; nouveaux exports et plans CLI exercés, avant dernier ajustement du calcul des profils | EXÉCUTÉ |
| Installation et déploiement Linux isolés | Wheel/sdist hors ligne, commandes CLI synthétiques, workflow sans rejeu, canal binaire ; installation répétée et propagation des erreurs pip, après ajustement des profils | EXÉCUTÉ |
| SSH Linux authentifié dans des montages privés | 27 tests : 23 réussites, trois skips rsync trop ancien, un échec de sortie partielle au délai de 0.3 s ; canaux/tunnels/clé inconnue réussis | ÉCHOUÉ |
| Diagnostic indépendant du délai de 0.3 s | Même attente de sortie partielle échouée sur rc4 conservée et candidate, sans changer le test ; statut timeout observé dans les deux cas | ÉCHOUÉ |

Les pairs synthétiques ne sont pas des serveurs SSH authentifiés. Le test de
bannière lance le vrai client OpenSSH, puis ferme avant authentification.
Les 50000 cibles simulées ne mesurent ni débit SSH ni RSS cumulée du parc.

## Cinq couvertures obligatoires

Chaque métrique doit atteindre 98 % avant arrondi, globalement et par composant.
Les tests obligatoires doivent tous réussir. Le gate refuse données absentes,
compteurs malformés, composants faibles et 97.999 % arrondis à 98 %.

Le schéma 5 applique la définition choisie explicitement par l'utilisateur le
3 novembre 2026 : les branches et conditions portent sur les décisions
exécutables du source. `coverage_source.py` complète l'observateur conservé
dans `coverage_metrics.py` ; il ne réévalue aucune donnée et ne réécrit aucune
expression applicative. Son catalogue AST est construit avant l'exécution.
Les tests élémentaires de court-circuit et de comparaison enchaînée restent
distincts ; les copies compilées du même test de boucle partagent une identité.
Les itérations ont leurs propres issues et ne deviennent pas des conditions
booléennes. Une affectation conditionnelle conserve son test après affectation,
distinct des tests internes de sa valeur. Une garde littérale compilée sans
test n'est pas une décision d'exécution ; ses instructions source restent dans
l'inventaire indépendant des instructions.

Les boucles asynchrones ne reçoivent une issue de fin normale qu'après
observation de la continuation normale de `END_ASYNC_FOR`. Un break, une
annulation ou une exception propagée ne prouve pas l'épuisement de l'itérateur.
Toute décision sans correspondance vérifiée reste non couverte et bloque le
gate, même si une moyenne atteint 98 %. `match` n'est pas pris en charge par
cette mesure et reste bloquant ; le source applicatif mesuré n'en contient pas.
Une négation composée dont la valeur est préservée peut exiger une corrélation
entre plusieurs tests pour attribuer une issue à la bonne comparaison. Lorsque
cette corrélation n'est pas prise en charge, la mesure refuse le cas et ne donne
aucun crédit supposé. Les négations simples préservées conservent la polarité
de leur opérande élémentaire ; leur conversion n'est jamais exécutée une
seconde fois par l'observateur.

Le rapport conserve intégralement les compteurs du schéma 4 sous `raw_python`,
avec leurs dénominateurs et refus. Ils incluent les choix du compilateur,
l'appariement d'exceptions et la suppression d'exception par un gestionnaire
de contexte ; cette vue source ne mesure ni les chemins d'exception ni MC/DC.
Les anciennes preuves ne sont pas effacées et ne deviennent pas des mesures
du schéma 5. La réussite des tests ne remplace aucune couverture.

Dans l'observateur brut conservé (schéma 4), les instructions utilisent les plages AST
dans leur scope lexical ; les lignes utilisent leur inventaire exécutable
distinct. Les appels def/async def/lambda constituent les fonctions ; les
signatures Protocol sans implémentation sont des déclarations explicitement
listées. Les anciennes mesures restent dans des compteurs séparés.

Deux corrections vérifiées séparément sous Windows 3.14 et Linux 3.12 conservent
les événements de ligne des sources : les désactiver pouvait supprimer
l'événement d'instruction d'un `NOP`, d'un saut ou d'une relance d'exception.
Seul l'événement réel d'instruction crédite la plage AST ; aucune instruction
n'est déduite d'une ligne exécutée. Les mêmes règles s'appliquent aux journaux
enfants, y compris devant un arrêt brutal. Les dénominateurs, définitions,
seuils et 30 contrôles initiaux restent inchangés. Les huit contrôles initiaux
des `NOP` distinguent les retours
exécutés, ignorés, sur une ligne partagée et après une exception. Les reçus avant
correction restent des preuves historiques ; leurs numérateurs incomplets ne
sont pas réutilisés comme une mesure finale de la correction.

Huit autres oracles vérifient les sauts, relances, chemins ignorés et journaux
enfants de cette correction. Les 82 oracles réussissent séparément sur les deux
runtimes avant application ; trois variantes fautives et neuf mutations de
mesure source restent refusées sans erreur. Cette correction ne qualifie pas
à elle seule les composants applicatifs ni une archive de livraison.

La reprise de compatibilité de novembre 2026 a ensuite éprouvé 95 oracles de
mesure, 15 contrats d'admission et 13 cas de publication de transferts sur
Windows CPython 3.11.9, 3.12.10, 3.13.16, 3.14.7 et Linux CPython 3.12.3,
avant application des corrections. Les mêmes 97 fichiers applicatifs et les
cinq dénominateurs source sont conservés. Les premiers échecs et chaque revue
restent dans les preuves séparées de cette reprise ; une revue de l'observateur
ne remplace pas la qualification complète de la nouvelle archive.

Un compilateur 3.12 peut attribuer à la boucle extérieure le même emplacement
que la compréhension déjà achevée : cette dernière n'est jamais réutilisée
pour masquer la décision extérieure. Sous 3.11, les conditions ne sont plus
fusionnées parce que leurs sauts partagent la plage d'un `if`. Les compteurs
booléens bruts concernés augmentent ; les anciennes valeurs restent dans leurs
reçus et ne sont pas remplacées. Les autres dénominateurs bruts restent égaux.

Les préfixes `EXTENDED_ARG` appartiennent au même saut : certains événements
d'opcode n'exposent que son premier préfixe. Leur correspondance est établie
avec les instructions natives, sans unité supplémentaire et sans inférence à
partir d'une ligne. Une issue n'est créditée qu'après une destination réellement
observée. En traçage d'opcode, la fin d'une boucle asynchrone exige sa continuation
exacte ; un gestionnaire d'erreur situé plus loin ne prouve pas son épuisement.

Le chemin d'opcode assure aussi les journaux enfants 3.11 et compose les traceurs
parents préexistants en préservant leurs masques ligne/opcode et leur restauration.
Un enfant dont le crochet de traçage est déjà occupé refuse l'instrumentation.
Les garde-fous de provenance, d'intégrité, de journaux, de source modifiée et
de seuil à 97,999 % restent bloquants. Les variantes perdant un événement,
réutilisant une boucle ou supprimant les plafonds restent refusées.
La fixture du test de packaging embarque ces cinq nouveaux fichiers obligatoires
et vérifie séparément le refus de chacun lorsqu'il est omis. Son premier échec
de synchronisation reste conservé ; aucune ancienne assertion n'est supprimée.

La borne réelle du test d'admission conserve ses allocations de 0,03 s et son
échéance exacte. Seule son observation du réveil tient compte de la résolution
monotone mesurée : `asyncio.call_at` peut être déclenché jusqu'à une résolution
d'horloge en avance. Un témoin de bibliothèque standard seule reproduit cet
effet sous Windows 3.12 ; aucun délai applicatif ou natif n'est augmenté.
Voir les contrats primaires de [call_at](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.call_at),
de [settrace](https://docs.python.org/3.11/library/sys.html#sys.settrace) et de
[sys.monitoring](https://docs.python.org/3.12/library/sys.monitoring.html).

Quatre simplifications des sources applicatives ont ensuite été comparées
séparément avant application, avec les mêmes 102 tests avant/après sur chaque
plateforme et un témoin indépendant des résultats et refus. La limite réelle
de 100000 enregistrements précède toujours la déduplication ; le nombre de clés
ne peut dépasser le nombre d'entrées déjà borné. Un `Host` validé produit toujours
un préfixe de fichier non vide. L'écho obligatoire prouve la présence de sa ligne
avant son retrait. La finitude des secondes du reçu est désormais contrôlée
avant leur plage, avec les mêmes bornes et diagnostics de refus. Les inventaires
de couverture sont recalculés sur ces nouvelles sources : aucune unité n'est
exclue par l'observateur et aucun seuil n'est abaissé. Les témoins finis appuient
ces invariants ; ils ne constituent pas une preuve formelle de tous les objets
Python, ni une qualification complète de production.

La couverture de chaque plateforme inclut aussi des tests de politique des
autres systèmes via des ports mémoire : verrous Windows, registre, fichiers,
préflight et refus du relais POSIX par un gardien Windows. Les instantanés de
fichiers emploient des répertoires privés. Ces tests vérifient les règles et
leurs erreurs ; ils ne remplacent ni les essais Win32 réels sous Windows,
ni les campagnes OpenSSH authentifiées sous Linux.

Les journaux enfants hérités sont bornés et liés au runtime, au catalogue et
aux empreintes exactes des sources. Un journal publié vide, tronqué ou étranger
est refusé ; un en-tête interrompu avant publication n'apporte aucun crédit.
Les compteurs ne sont jamais déduits d'une réussite de test. Les contrôles de
format, d'import, de sécurité et les cinq seuils restent bloquants.

Les branches brutes conservent tous les sauts conditionnels et FOR_ITER du bytecode,
y compris les choix d'implémentation ajoutés par CPython. Une preuve locale
indépendante montre ainsi un plafond de 13/14 (92.85714285714286 %) dans
application/preflight.py sous CPython 3.14.7 avec les fonctions intégrées réelles :
le quatorzième chemin exige de remplacer artificiellement `any`. Ce constat
reste visible dans la vue brute et ne donne aucun statut vert. Les
conditions booléennes ne confondent plus ce test d'identité du compilateur avec
la vérité d'une donnée applicative ; ses résultats bruts restent disponibles.

| Couverture finale | Windows — archive extraite | Linux — sources identiques |
| --- | --- | --- |
| Instructions | NON EXÉCUTÉ au gel — voir reçu final séparé | NON EXÉCUTÉ au gel — voir reçu final séparé |
| Branches | NON EXÉCUTÉ | NON EXÉCUTÉ |
| Fonctions | NON EXÉCUTÉ | NON EXÉCUTÉ |
| Lignes | NON EXÉCUTÉ | NON EXÉCUTÉ |
| Conditions booléennes | NON EXÉCUTÉ | NON EXÉCUTÉ |

Mesures intermédiaires distinctes, **sans identité de révision commune entre
ces deux colonnes** : chaque campagne a vérifié sa propre copie, mais des
correctifs ont été intégrés entre elles. Elles ne qualifient pas le code actuel.
L'oracle des comparaisons enchaînées a ensuite révélé une fusion de conditions
dans cet observateur intermédiaire : ses anciens compteurs de conditions
booléennes sont conservés comme preuve initiale, sans les considérer fiables.
Le correctif sépare les éléments d'une chaîne tout en réutilisant leurs identités
lorsqu'un contrôle de boucle est compilé plusieurs fois. Les oracles Windows
3.14 et Linux 3.12 vérifient cette distinction sans changer les cas de refus.

| Métrique | Windows CPython 3.14 avant derniers correctifs | Linux CPython 3.12 avant relais/intégrité des checkpoints |
| --- | --- | --- |
| Instructions | 7657/8789 — 87.12026396632155 % | 8027/8797 — 91.24701602819142 % |
| Branches | 4348/6920 — 62.83236994219653 % | 4338/6008 — 72.20372836218375 % |
| Fonctions | 840/1219 — 68.90894175553733 % | 839/937 — 89.54108858057631 % |
| Lignes | 7657/8789 — 87.12026396632155 % | 8027/8797 — 91.24701602819142 % |
| Conditions booléennes | 3465/5642 — 61.41439205955335 % | 3555/4938 — 71.99270959902795 % |

La description suivante concerne l'observateur historique de la première rc1,
avant les corrections de définition et de journaux enfants décrites ci-dessus.
Le moteur observait lignes, appels et sauts CPython sans réévaluer les valeurs
métier. Instructions et lignes partagent explicitement le compteur historique
de lignes exécutables. Branches : sauts conditionnels et FOR_ITER, sans arêtes
des tables d'exceptions. Conditions : résultats effectivement évalués, aucun
crédit pour un court-circuit ; ce n'est pas une mesure MC/DC. Les code objects
synthétiques restent inventoriés. À ce stade les enfants ne sont pas tracés :
leur code non observé reste non couvert, jamais retiré du dénominateur.
Les empreintes et compteurs par fichier/composant sont produits par coverage.py.

Les avertissements asyncio liés au ralentissement de l'instrumentation restent
dans un journal borné distinct, sans désactiver debug ni changer son seuil.
Les assertions et limites de progression d'origine restent intactes. Ce journal
brut local est exclu des distributions, car il peut contenir des chemins ou
représentations de tâches.

## Recette et limites restantes

Depuis les sources extraites, avec Python et les prérequis disponibles :

```sh
python scripts/verify.py
python scripts/wiki.py
python scripts/coverage.py
python scripts/native_network_gate.py
python scripts/build.py
python scripts/validate_installation.py
python scripts/package.py
```

Une sortie non nulle bloque la qualification. L'archive doit être reconstruite
deux fois de façon identique, vérifiée par manifeste, extraite isolément, puis
rejouée avec un reçu lié à son SHA-256 exact. Les probes d'installation utilisent
des environnements privés ; elles ne doivent pas changer le PATH de l'utilisateur.

| Contrôle restant | Statut | Raison, procédure, prérequis, attendu et risque |
| --- | --- | --- |
| Cinq couvertures finales et détail par composant | NON EXÉCUTÉ | Révision encore en préparation. Exécuter coverage.py depuis extractions Windows/Linux identiques ; attendu : chacune ≥98 %, aucune exclusion abusive. Risque : erreurs/plateformes non exercées. |
| Build, installation, reproductibilité et rejeu finaux | NON EXÉCUTÉ | Après stabilisation, avec Python complet et venv/ensurepip, utiliser les scripts ci-dessus, comparer hashes et manifeste. Attendu : artefacts identiques et installation hors ligne ; risque d'intégration de l'artefact. |
| SSH authentifié, canaux et tunnels réels | NON EXÉCUTÉ | sshd absent. Avec serveur éphémère autorisé, exécuter native_network_gate.py, qui refuse les skips. Attendu : succès, refus de clé, annulation et échange tunnel ; risque d'interopérabilité restant. |
| Mot de passe et Kerberos | NON EXÉCUTÉ | Realm et comptes de laboratoire absents. Exécuter native_auth_gate.py dans les namespaces privés prévus. Attendu : aucun fallback ni succès ambigu ; risque d'authentification réelle. |
| Matériels et firmware | NON EXÉCUTÉ | Laboratoire Cisco/Juniper/Aruba/Huawei/Fortinet et accès hors bande absents. Qualifier chaque modèle/version avec sauvegarde, modification restaurable, coupure et retour de version. Attendu : aucun rejeu ni étape après échec. |
| macOS, AIX, Solaris et autres runtimes | NON EXÉCUTÉ | Machines absentes. Suivre PORTABILITY.md et exécuter les portes sur checkout identique. Attendu : contrôles applicables réussis ; risques propres aux clients/signaux/stockages. |
| Console Windows authentifiée | NON EXÉCUTÉ | Console/cible non mobilisées. Tester shell, PTY, redimensionnement et restauration après erreur/annulation. Risque de console restant. |
| Charge SSH et reprise métier | NON EXÉCUTÉ | Parc autorisé absent. Suivre ACCEPTANCE-SCALE.md et mesurer CPU/RSS/FD/débits/erreurs avec fautes et contrôles métier indépendants. Attendu : limites respectées et aucun doublon ; simulation insuffisante. |
| CI distante, audit externe et publication | NON EXÉCUTÉ | Runners/index/auditeur non mobilisés. Exécuter la CI bloquante avant toute publication explicitement autorisée. Aucune publication effectuée. |

La conformité du Wiki ne certifie pas le logiciel. Une couverture suffisante
ne garantit pas à elle seule l'absence de vulnérabilité ou l'aptitude du parc.


## Classement d'une interruption et texte de commande

Le diagnostic privé OpenSSH peut contenir le texte de la commande envoyée.
La présence de « Exit status 255 » dans ce texte ne confirme pas le résultat
de la commande. Le classement exige un enregistrement complet de sortie dont
le nombre correspond au code natif. Une interruption sans cette preuve garde
le statut INTERRUPTED et l'état distant inconnu ; aucun rejeu n'est ajouté.
Les tests test_ssh_exit_receipts.py couvrent les fragments, nombres différents,
suffixes et fins de ligne. Le cas SSH natif arrête uniquement son propre shell
et vérifie le statut, la sortie et l'absence de seconde tentative. Les reçus de
qualification distincts indiquent les contrôles effectivement exécutés.


Pour les commandes multiligne, seule la copie transmise au classificateur omet
le bloc « Sending command » du diagnostic. Le nombre de LF est déterminé sur
les 900 premiers octets UTF-8 réellement journalisés par OpenSSH ; la fin du
bloc reste distincte d'un vrai enregistrement de sortie. Une troncature de ce
bloc garde la preuve de démarrage et ne permet aucun rejeu. Aucun fichier de
diagnostic brut, commande envoyée ou flux distant n'est réécrit. Les tests SSH
réels couvrent run et SSHChannel, l'interruption et une véritable sortie 255,
ainsi qu'un compteur distant démontrant une seule exécution.


La lecture des diagnostics conserve les codes d'erreur Win32 et refuse les
reparse points avec l'adaptateur existant. Seuls les conflits de partage ou
verrouillage 32/33 bénéficient de nouvelles lectures pendant au plus deux
secondes ; les refus ACL, autres erreurs, annulations et budgets de contenu
restent explicites. Aucun processus SSH n'est relancé par cette attente.
Après une attente, SSHChannel vérifie à nouveau son propriétaire et son état
avant de produire une capture. Les tests comprennent un vrai verrou Windows,
les erreurs permanentes, l'expiration, l'annulation et la fermeture concurrente.
Ce défaut de lecture est reproduit séparément ; la cause exclusive de l'échec
CLI initial n'est pas établie et cet échec reste conservé dans les preuves.

Le contrôle de progression conserve ses quatre assertions initiales, ses 500
cibles et sa limite de 512 caractères. Une barrière et une horloge applicative
déterministe remplacent sa dépendance à la durée réelle ; les diagnostics du
runtime sont conservés séparément sur stderr. Cinq contrôles négatifs refusés
vérifient avant application le spam, l'absence du bilan, la fuite d'hôte, la
divergence JSON et une mauvaise période. Aucun seuil ni contrat de couverture
n'est modifié. Ces preuves locales ne qualifient aucun équipement réel absent.


Un refus de partage Win32 32/33 sur l'acquittement LocalCommand reste une
absence de preuve de démarrage pendant une nouvelle lecture bornée. Le même
délai de démarrage externe continue de borner cette attente. Aucun jeton n'est
accepté sans lecture et vérification exacte ; refus ACL, jeton invalide,
expiration et fermeture restent explicites. Un vrai verrou Windows reproduit
l'échec avant correction ; les tests couvrent également le verrou persistant,
les codes32/33 et les autres erreurs, avec un seul lancement natif.


Une valeur native négative correspond à un signal local, pas à une
sortie distante confirmée. Le motif ne reconnaît que les reçus non négatifs
correspondant au code natif ; les sorties positives7/255 restent confirmées.
La régression conserve les six cas de signal refusés sur la version précédente
et le non-rejeu ; aucune métrique, limite, tentative ou collecte ne change.


Le scénario POSIX du descendant ignorant SIGTERM attend son acquittement
après installation du gestionnaire de signal, au lieu d’un sommeil fixe.
Le délai de transfert de0,4 s, les assertions de succès et de nettoyage,
le vrai gardien et les refus de terminaison restent conservés. La revue
avant application conserve chaque observation et la mutation sans SIGKILL.
Les échecs des campagnes antérieures ne sont ni effacés ni requalifiés.


### Confidentialité des erreurs de ports d’inventaire

La conversion d’un port textuel traduit ValueError après sortie du gestionnaire
d’exception. Le message public et sa chaîne ne conservent plus le texte brut de
la valeur invalide. parse_host, les inventaires CSV/YAML et les cibles texte/JSON
partagent ce traitement ; les syntaxes numériques déjà admises et les limites
de Host restent inchangées. Les objets JSON conservent leur validation de type.
La CLI conserve son diagnostic générique existant et n’effectue aucune opération
après le refus d’inventaire. Les tests d’origine sont préservés ; trois nouvelles
méthodes reproduisent la fuite et refusent les variantes conservant la cause,
le contexte masqué ou un port de remplacement silencieux. Les cinq seuils et
collecteurs restent inchangés ; les nouvelles mesures portent sur cette archive.


### Validation littérale des caractères et coût des grands profils

Options et TransferReceipt recherchent les mêmes 65 caractères C0/C1 dans le
moteur standard d’expressions régulières. La recherche porte sur le contenu
littéral des chaînes ; un itérateur personnalisé ne peut plus en dissimuler
les caractères interdits. Les contrôles historiques des itérateurs de
sous-classes restent des contraintes supplémentaires, avec leurs refus et
exceptions. Les identités des objets de chaîne valides restent conservées.
Les limites UTF-8 de 4096 octets, budgets de profils, formats, jeux de données,
plafonds de concurrence et délais ne sont pas modifiés. La vérification
avant application couvre tous les points Unicode et les variantes dangereuses.
Les mesures de constructeurs sont distinctes de la latence SSH ; la recette
complète et les cinq couvertures restent obligatoires avant la copie locale.


### Synchronisation des fixtures de relais et de canal

Le pair de test commence son attente de connexion au lancement natif ; la
préparation du client ne consomme plus cette attente. La fixture du relais
prépare la politique partagée comme le fait le gardien avant le processus
natif. Le minuteur réel reste démarré avant l'initialisation du budget du relais.
Un nouveau test bloque cette initialisation et exige toujours l'arrêt à 124,
sans connexion ni sortie, avec la durée de vie de 0,5 s inchangée.
Le faux canal attend une demande bornée après l'entrée confirmée avant de
saturer son diagnostic. Les retards injectés reproduisent les trois courses
sur les fixtures d'origine et vérifient les barrières proposées. Les assertions,
budgets et scénarios antérieurs sont conservés ; quatre mutations des barrières
ou du minuteur sont refusées. Aucun fichier du runtime n'est modifié par cette
correction de fixtures ; les cinq couvertures complètes sont rejouées avant copie.


### Nettoyage natif et dates futures des fixtures

Le contrôle Linux du descendant récalcitrant utilise des processus système
natifs et vérifie que TERM est réellement ignoré avant la fin du parent.
Les assertions antérieures et le délai de transfert de 0,4 s sont conservés.
Deux tests ajoutés reproduisent le coût de démarrage de l'ancienne fixture
Python et exigent toujours l'expiration d'une commande native réellement bloquée.
Les variantes sans ignorance de TERM, arrêt forcé du groupe ou délai sont refusées.

La date synthétique de la recette de planification couvre les 45 secondes
déjà allouées à une commande. Cette donnée future remplace une avance de 2 s ;
les délais de commande (45 s), d'attente de l'horloge (60 s), de campagne et
les 50 tâches, rapports, appels et vérifications de non-rejeu restent identiques.
Un retard injecté de 2,25 s fait expirer la donnée d'origine et réussit après
correction. Une date réellement passée reste refusée. Les trois barrières de
dates passées, l'ancienne avance et un budget CLI augmenté sont éprouvés dans
des copies jetables. Le refus initial de la recette reste conservé ; son
diagnostic détaillé transitoire n'ayant pas survécu, sa cause exacte n'est pas
présentée comme établie par ces contre-épreuves. Les cinq campagnes complètes
doivent être rejouées sur cette archive avant la copie locale.

Aucun fichier du runtime, collecteur, seuil ou dépendance de production ne
change dans cette révision. Les échecs des cycles précédents ne sont pas effacés.


### Remédiation des assertions et contrat OpenSSH effectif

Deux signaux B101 sont traités : suppression d'une assertion YAML redondante,
dont l'invariant est déjà établi par la création ou le refus de continuation,
et refus explicite de pipes SSH manquants avec nettoyage du processus détenu.
Le refus de pipes conserve le résultat d'erreur générique, sans nouvelle
tentative, et les métriques de nettoyage. Un test d'architecture refuse toute
assertion dans le runtime afin que ses validations survivent à `-O` et `-OO`.

La sonde OpenSSH vérifie 19 options effectives obligatoires, chacune une fois,
avec des valeurs strictes et les variantes booléennes natives yes/true et
no/false. Le rapport est borné à 131072 octets, décodé strictement en UTF-8 et
refusé s'il est malformé, incomplet ou ambigu. Les options supplémentaires
complètes sont admises, y compris des chemins Unicode. Le format public de la
sonde, son délai natif de 10 s, les commandes, paramètres et délais existants
ne changent pas. Cette vérification ne certifie pas la provenance du binaire,
un serveur distant ni un équipement absent du laboratoire.

Les tests ajoutés échouent sur les sources antérieures et réussissent sur la
proposition sous Python normal, -O et -OO. Quatre mutations dangereuses sont
refusées. Le scan intégral avant/après conserve tous les signaux restants et
son code d'échec brut : aucun filtre, baseline ou nosec n'est ajouté. Les cinq
couvertures doivent être remesurées, globalement, par composant et par module,
sur l'archive exacte avant la mise à jour du dossier de sources local.


### Contrats Unicode des outils de compatibilité — cycle32

La sonde publiée échouait sur un profil Windows contenant des caractères hors
cp1252 : son fichier OpenSSH utilisait implicitement la locale. Le générateur
de service produisait correctement son XML mais échouait ensuite en imprimant
un chemin Unicode sur une sortie ancienne. La configuration native est désormais
écrite explicitement en UTF-8 ; un afficheur autonome échappe les seuls caractères
non représentables, sans changer les fichiers, leurs noms ou leurs octets.

Trois nouvelles méthodes de test reproduisent onze erreurs sur la référence
et réussissent après correction sous Python normal, -O et -OO. Les variantes
rétablissant l'écriture locale, remplaçant les caractères par des points
d'interrogation ou masquant une erreur réelle d'I/O sont refusées. Les cinq
générateurs de services et toutes les méthodes de test préexistantes restent
inchangés. Les tests vérifient quinze combinaisons format/encodage, le refus
d'écrasement et la propagation des véritables erreurs de sortie.

Une recette réelle Windows 3.11/3.12/3.13/3.14 compare les sources avant/après
avec les modes UTF-8 activé et désactivé : trente-deux processus, huit refus
avant correction en mode ancien, huit réussites antérieures en mode UTF-8 et
seize réussites après correction. OpenSSH est réellement appelé en mode -G ;
aucune connexion réseau, inscription ou activation de service n'est effectuée.
Cette recette ne qualifie pas les équipements ou systèmes absents du laboratoire.

Les99 fichiers du runtime restent identiques à la révision précédente. Aucun
instrumentateur, seuil, exclusion, délai existant ou dépendance ne change. Les
cinq couvertures doivent néanmoins être mesurées à nouveau sur l'archive exacte
avec les nouveaux tests, et tous les contrôles locaux rejoués avant la copie.
Les alertes Bandit restantes demeurent visibles sans filtre ni suppression.


### Bornes natives et reconnexion — cycle33

Les canaux et tunnels directs POSIX partagent désormais le relais détenu par le
gardien déjà utilisé pour les commandes et procédures réseau. Le second démarrage
Python du proxy historique disparaît de ce chemin. Windows, les bastions et
GSSAPI conservent leur chemin existant ; confiance, limites, comptabilité et
durées maximales sont conservées. Les canaux préparent leur schéma de comptabilité
avant de pouvoir ouvrir une cible, comme les autres points d'entrée natifs.

Lors d'une reconnexion réseau, le délai de négociation observe le reçu privé
d'admission bornée du gardien, selon le protocole déjà utilisé pour les commandes.
Ce crédit local reste fini. Il ne prolonge ni le délai global de la procédure ni
la fenêtre globale de redémarrage ; un reçu invalide ou un gardien disparu arrête
la procédure. L'activation n'est jamais rejouée.

Les tests de durée native utilisent un enfant natif plutôt qu'un second Python
instrumenté. Les tests de nettoyage Linux attendent la disponibilité par FIFO
privée au lieu d'une boucle active. Les assertions et plafonds existants de
0,5 s, 0,4 s et 5 s sont conservés. Des régressions distinctes vérifient les
durées invalides avant allocation, le démarrage tardif refusé et les cinq états
d'admission. Aucun collecteur, seuil, exclusion ou contrôle CI n'est modifié.
Les résultats de qualification doivent être lus dans les preuves de cette
révision ; ces changements ne constituent pas une qualification du parc réel.


### Frontière du benchmark synthétique — cycle34

Le pair Python du benchmark de canal conserve le gardien natif réel, sa durée,
son admission et les assertions sur les octets. Seules les métadonnées du relais
SSH sont retirées à la frontière de ce faux transport, qui n'est pas OpenSSH.
La régression vérifie la requête réelle du gardien, la durée10s et le contenu
binaire4096octets ; les variantes sans gardien et sans durée sont refusées.
Le benchmark conserve ses opérations, sa concurrence, son plafond90s et ses
limites déclarées. Les99 fichiers du runtime applicatif restent identiques au
candidat précédent. Les mesures antérieures restent historiques ; les cinq
campagnes complètes doivent qualifier ce nouveau package avant actualisation.


### Reçu d'admission Windows — cycle35

Les lecteurs du reçu privé d'admission ouvrent une version complète avec le
partage de suppression Windows. Le gardien utilise ReplaceFileW sans indicateur
d'ignorance d'erreur pour remplacer la version précédente ; seule la première
publication sans destination utilise le déplacement atomique existant. Les
lecteurs déjà ouverts conservent leur instantané complet. Les autres ouvertures
de fichiers gardent leur partage habituel. Les droits de lecture, le refus des
liens de réanalyse et les ACL privées restent contrôlés ; les erreurs réelles de
lecture, allocation, accès ou remplacement sont propagées. Une allocation de
flux échouée libère le descripteur dont elle n'a pas pris possession.

La régression native maintient un lecteur ouvert pendant la publication. Le
scénario CLI original d'une cible inaccessible conserve ses deux tentatives,
ses statuts attendus et tous ses délais ; les variantes retirant le partage ou
le remplacement natif doivent échouer. Ce scénario reproduit une cause possible
de l'erreur observée en qualification Python 3.13 ; la trace de l'incident
initial ne permet pas d'en affirmer rétrospectivement la cause unique.

Aucun schéma, délai, crédit d'admission, seuil, collecteur de couverture,
exclusion ou contrôle CI n'est modifié. Les cinq campagnes complètes sur
l'archive courante restent requises avant toute actualisation locale du package.


### Sélection des adaptateurs d'admission — cycle36

Un test de contrat exerce explicitement les lecteurs et publications POSIX et
Windows sur chaque hôte, avec le même schéma strict et les mêmes appels attendus.
Ce test de sélection complète l'essai natif Windows avec lecteur réellement
maintenu ouvert ; il ne le remplace pas. Les variantes retirant le lecteur ou
le remplacement Windows sont refusées. Aucun code de production, collecteur,
seuil, délai, assertion antérieure ou contrôle CI n'est modifié. Les mesures
partielles du module ne qualifient pas le package ; les cinq campagnes complètes
doivent porter sur la nouvelle archive avant son actualisation locale.


### Scénarios de démarrage lent et observations de reconnexion — cycle37

Les essais de planification gardent une date future pendant le budget de
démarrage de dix secondes déjà accordé à la commande d'enregistrement. Un
scénario supplémentaire injecte 2,25 secondes dans ce même budget ; les plafonds
de dix et quinze secondes, le refus des dates passées et les assertions de
canari et d'absence de rejeu sont conservés.

Les essais réseau distinguent les demandes locales de connexion des sessions
effectivement atteintes par le simulateur distant. Un délai global peut arrêter
une tentative avant l'authentification ; il ne garantit pas une session distante.
Les nombres de demandes restent vérifiés exactement. Les sessions réussies ou
en erreur après dialogue gardent leur décompte exact ; les scénarios TIMEOUT
contrôlent séparément la borne des sessions distantes. Un démarrage local de
0,8 seconde est injecté dans la fenêtre globale existante, sans la prolonger.
Les plafonds natifs de reconnexion sont aussi vérifiés directement. L'activation
reste unique, les vérifications attendues et le plafond global restent contrôlés.

La revue avant/après conserve le refus initial d'un comportement correctement
arrêté par la fenêtre d'une seconde. Elle refuse les variantes avec une tentative
supplémentaire, une fenêtre élargie, un rejeu d'activation ou une date de nouveau
trop courte. Le code de production, les réglages d'authentification, les huit
contrôles figés et les cinq définitions de couverture ne changent pas. Les cinq
campagnes complètes sur la nouvelle archive restent requises avant copie locale.


### Shared quota contention regression

The preceding candidate preserved a real Python 3.11 coverage-suite TimeoutExpired in `test_ten_independent_processes_respect_shared_limit`, despite source ratios above 98% on every module. Keep that refusal and the rejected first proposal. The reviewed correction removes SQLite internal busy sleeps from polling and restartable retries, while retaining the original 10s retry bound, 0.01s Python wait, FIFO, accounting, rollback, terminal storage errors and 20s ten-process test. A new real writer/reader regression fails on the old source and passes after correction. Twenty-eight focused tests passed, seven runtime/optimization reviews passed, and four unsafe variants were refused. All five full independent metrics still require fresh >=98% results globally and per module; no local source handoff or production readiness is established by these focused tests.


### Cleanup fixture and cold-start bounds

Keep the C38 refusal: the instrumented Linux suite rejected two cleanup tests while all five source ratios remained >=98% per module. The revised fixture isolates a real prepared native group for cleanup; all original SUCCESS, signal-mask, identity and destruction assertions are retained, with a bounded readiness witness added. A controlled 0.6-second preparation reproduces both old failures and succeeds with the proposed fixture. Four focused cases pass in normal, -O and -OO modes; three unsafe runtime variants and four unsafe fixture policies are refused. The production transfer deadline remains 0.4 seconds in the existing cold-start and running-command regressions. No production source, measurement collector, threshold or frozen control changes. Five complete fresh qualification campaigns are still mandatory before local source handoff.


### Relay acceptance clock review

Retain the C39 refusal: the Windows Python 3.11 verify control expired at 900 seconds; its instrumented suite had two peer timeouts despite all five source ratios remaining >=98% on every module. The focused observation did not reproduce those historical incidents, so their unique retrospective cause remains unconfirmed. A separate controlled experiment demonstrates that local native admission plus legitimate active proxy startup can expire the former peer acceptance window. The proposed bounded admission witness preserves every prior assertion and all producer, peer receive and cleanup clocks. Three controlled old cases fail; the three corrected delayed and three corrected ordinary cases succeed. Missing real traffic and missing admission remain refused, with seven unsafe fixture policies also rejected. Seven local runtime/optimization reviews pass: the whole 24-case bandwidth module on Windows Python 3.11, three targeted cases on 3.11 -O/-OO, Windows 3.12/3.13/3.14 and Linux 3.12. Their raw inherited-child journals are retained separately. No production runtime, frozen control, coverage definition or threshold changes. The complete five-support qualification and all dependent controls are still required; no source handoff is established by these focused proofs.


### Bounded spare-memory report slots

The retained C39 verify timeout remains an actual failed control. Profiling identified SQLite transaction and filesystem costs in per-record report submission. The reviewed correction preserves full worker reservations and charges additional report slots only to unused admitted memory, using the existing ordinary-worker buffer allowance and the unchanged 32-record ceiling. The integrated in-memory public-use-case regression fails twice on the previous source and passes over five resource geometries after correction. The original 10,001-transfer scenario passes before and after, with its exact source and assertions unchanged; observed writer calls are 10,001 and 1,429, and instrumented durations are 254.758s and 160.000s. Nine real formatting/capacity/cancellation/cleanup cases pass, four runtime mutants and four independent source-policy mutants are refused, and six additional runtime/optimization reviews pass. The independent reservation calculation covers 26,880 boundary geometries. These proofs concern the declared reservation model; the original real 50,000-target memory check and every full qualification remain mandatory. No threshold, collector, exclusion, SQLite durability setting, worker limit, producer clock or existing assertion is changed. No package handoff is established by these focused observations.


### Receiver backpressure regression

C40 remains refused: its unconditional use of spare memory violated the original injected report receiver contract (17 records versus a maximum of 3), despite five Windows Python 3.11 source coverage ratios above 98 percent. C41 restores the exact legacy bound unless the actual receiver explicitly opts in with literal True. Before application, three targeted cases reproduce four failures on C40; the corrected three cases and 27 complementary cases succeed. Five unsafe variants are rejected. The original architecture and 10001-result transfer tests are unchanged. A new 96-result regression uses the real native report process and a deterministic valid resource plan: 14 acknowledged append calls preserve all records, while disabling the real capability requires 96 calls and is refused. Six additional runtime/optimization reviews pass on Windows Python 3.11 -O/-OO, 3.12/3.13/3.14 and Linux 3.12. Raw inherited-child journals are independently checked. These focused proofs do not replace fresh five-support package qualification, security checks or source admission.


### Python 3.12 runner and native reconnect evidence

The retained C51R2 refusals remain part of the evidence: Windows Python 3.12
verify expired at 900 seconds; its coverage run failed during synthetic tunnel
startup; Linux native reboot verification rejected a legitimate pre-command
retry. The 900-second verify budget, async debug mode, original heavy test,
production sources and five coverage definitions remain unchanged. On Windows
3.12 only, verify executes the original 10,001-transfer case once in a bounded
child alongside the remaining suite; exact discovery counts, interpreter and
source identities, real outcomes and skips are checked before aggregation.
Missing or inconsistent child evidence fails the control.

The synthetic channel peer invokes the real atomic readiness validator within
the original three-second bound, without an additional interpreter startup.
Separate native callback command-line and real SSH checks remain mandatory.
The reboot oracle distinguishes requested connections from authenticated
sessions: bounded pre-command retries are permitted by NETWORK.md, while
the exact command history, single activation, expected verification count,
ready-session count, native lifetime caps and global boot window are enforced.
All five independent fresh support campaigns and dependent admission controls
are required before local source handoff; these changes establish no readiness
claim by themselves.


### Native QA prerequisite search boundary

Five native QA callers previously executed ssh, ssh-keygen or rsync through
the inherited PATH, including the diagnostic after failed Kerberos login.
The prerequisite helper now selects an absolute executable from fixed system
locations; Windows obtains its system directory through the bounded OS API
GetSystemDirectoryW instead of SystemRoot, WINDIR or PATHEXT. Native fixture
children inherit the same bounded search path while retaining credential and
configuration variables. Missing trusted tools fail without caller-PATH fallback.
Explicit caller-configured production executable contracts remain unchanged.
This lookup does not attest binary contents or defend against OS administrators.

Five identical regressions execute harmless substituted programs and reproduce
five failures on byte-preserved previous callers; seven corrected cases pass.
Eight deliberately unsafe variants are refused. Original SSH configuration,
authentication, rsync security minimum, isolation, assertions and time limits
remain in place. Five complete fresh support campaigns and all source-admission
checks remain required before local handoff. Raw Bandit findings are preserved,
without suppression, baseline or a claim that its full gate succeeded.


### Connector capability cache and live trust

The optional native connector caches capabilities, not permission or ancestry
authorization. A real local observation reproduced a warm cache accepting a
helper after shared-write permission changes, while the same cold lookup refused
it. A changed parent directory was likewise omitted from cached authorization.
The existing guardian's separate permission check remains in place; these
observations do not demonstrate arbitrary command execution.

Discovery now pins and inspects current ancestry and executable metadata before
every cache lookup. Capability identity also includes change time, so a changed
observed identity rechecks help and the real TCP_NODELAY descriptor contract.
No content attestation, immunity to privileged concurrent replacement or new
platform guarantee is claimed. The original cache limit, bounded probes,
ownership rules, rejection behavior, cleanup and no-replay policies remain.

Three new regressions produce four failures on the previous source and succeed
on the proposal. Seventeen original targeted tests and twenty proposed targeted
tests pass; four deliberately unsafe variants are refused. Existing capability
test doubles expose the extracted trust seam without changing their assertions.
All five fresh full qualification campaigns and source-admission controls remain
required before handoff; the raw Bandit gate is not suppressed or waived.


### Source-specific transfer fault injection

The first C55 qualification was refused: Linux verify and coverage each observed
one failed source-change regression. Their logs, archive and measurements are
retained. The fixture counted all process-wide fstat calls; connector trust checks
therefore triggered its mutation before the transfer baseline. It now identifies
the actual source descriptor and constructs the client before injection, keeps
the original size and rejection assertions, and additionally proves the real
mutation, its observation count and the snapshot-specific rejection cause.

A new regression introduces unrelated real descriptor inspection while copying.
Both cases fail on the refused fixture, pass after correction, and fail again
when the real production snapshot guards are removed. Production transfer code,
all thresholds, collectors, exclusions and original deadlines remain unchanged.
A completely fresh five-support campaign is required on this archive.


### Installed scheduling fixture and existing startup allowance

C56 Linux verify and coverage succeeded but installation was refused: the
synthetic date was only one second ahead and became past during allowed CLI
startup. The refused archive, logs and acquired measurements are retained.
The nominal future input now spans the existing 60-second invocation allowance.
The command timeout, UTC wait bound, worker invocations and every result guard
remain unchanged. No production scheduling logic is changed.

Two new real-CLI tests cover 2.25-second startup and expired input. The old
fixture fails the valid-input case; all five old and two new tests pass after
correction. Disabling all three production past-date guards is detected. Earlier
cache and source-mutation reviews still apply to byte-identical source files;
none of their old measurements is reused for the fresh five-support campaign.


### Bounded nominal scheduling window and directly testable submission

An observation of the unchanged refused 50-job campaign captured MISSED jobs
with misfire_grace_exceeded before the missing-report error. Nominal durability
jobs now explicitly use the existing 900-second campaign allowance as their
input grace. The production default remains 300 seconds, its expiry guards
remain unchanged, and neither the 45-second CLI limit nor the campaign allowance
is increased. The state guard now precedes report reading so the real refusal
is preserved instead of being hidden by a secondary missing-file error.

A submission object exposes the actual installation registration operation to
its tests without dynamic execution of source fragments. Original arguments,
subsequent installation statements and result guards are verified unchanged.
Five original and four new fixture tests pass; two original input failures and
two unsafe production variants demonstrate the date and deadline protections.
The temporary B102 introduced in the unpublished C57 test adapter is removed
through this directly testable operation; the original scan is retained.
All five runtime campaigns must run afresh on the identified current archive.


### Pacing admission handoff under host descheduling

The first C58 Windows 3.11 verification was refused by the original real pacer
8-millisecond spacing assertion. A deterministic 20-millisecond pause at the
lock-release boundary reproduces the catch-up burst on the retained original
source. Admission ownership now spans the caller continuation and is released
on the next event-loop turn; the following interval is anchored after that
handoff. No rate, delay threshold, original assertion or timeout is relaxed.

Three new regressions exercise descheduling, cancellation and failure to queue
the handoff. Five targeted tests pass on Windows 3.11, Windows 3.12 and Linux;
three deliberately unsafe variants are detected by their causal assertions.
The early-wakeup clock fixture adds only the zero-valued handoff observation;
its two sleep assertions and exact next deadline remain unchanged.
All five support campaigns and current local admission must run afresh.


### Coarse clock fixture and real deferred scheduling

C59 full Windows 3.11 verification passed the original real pacer spacing test
but refused a separate clock-contract fixture: its synthetic event-loop value
exposed time only, without the deferred call queue now used by pacing.
The fixture retains its original coarse 15.625-millisecond tick and every sleep
and exact next-deadline assertion, delegates call_soon to the actual running
loop, and includes the one zero-valued handoff clock observation. An extra
assertion proves the coarse loop clock is not used for elapsed admission time.
Nine related pacing, clock and input/security tests pass on Windows 3.11,
Windows 3.12 and Linux. No production byte, rate, threshold, timeout or original
skip condition changes from C59. Its original failure and archive are retained.


### Queued cancellation before admission

C60 Linux full tests succeeded but boolean coverage of bastion.py was refused
at 229/234 (97.86324786324786 percent). The missing cancellation outcome before
context-token assignment depended on scheduling in the existing cases. One
additional test uses real SQLite capacity and lease accounting with a precise
after-poll barrier, then cancels before admission. It checks that the operation
never starts, the caller context survives, and the child lease, lock and SQLite
connection are released. All original cleanup test methods remain identical.
Eleven tests pass with the unchanged source collector on Windows 3.11, Windows
3.12 and Linux; each observes the previously missing false outcome. Two isolated
negative variants detect omitted final cleanup and resetting an unset token.
No runtime code, collector, threshold, timeout or existing assertion changes.
The C60 refusal is retained; all five campaigns must run on this new archive.

