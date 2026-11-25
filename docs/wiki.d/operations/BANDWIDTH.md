# Plafond partagé des flux SSH

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / operations / Plafond partagé des flux SSH

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Périmètre exact](#périmètre-exact)
- [Configuration et dimensionnement](#configuration-et-dimensionnement)
- [État et reprise](#état-et-reprise)
- [Preuves et limites de mesure](#preuves-et-limites-de-mesure)



`--bastion-bandwidth-kib` limite les octets chiffrés transmis par les relais
SWASSH du même compte et de la même racine de budget. Sa valeur par défaut
est 10240 Kio/s. Les deux directions consomment le même budget, avec une
unique réserve initiale d'au plus 16 Kio, partagée entre les processus.

## Périmètre exact

La limite porte sur le payload TCP remis par le relais entre OpenSSH et son
socket. Elle ne compte pas les en-têtes, retransmissions, files du noyau ou
le trafic des autres programmes. Les buffers TCP peuvent laisser une rafale
supplémentaire sur l'interface physique. Ce n'est ni un quota réseau du système
ni un coordinateur entre plusieurs bastions. Un quota d'infrastructure et une
répartition entre bastions restent des décisions d'exploitation externes.

La configuration privée ajoute un ProxyCommand vers l'hôte déclaré. Pour une
connexion POSIX directe sans GSSAPI, le gardien possède le relais et OpenSSH
reçoit un descripteur connecté par ProxyUseFdpass. Un connecteur natif facultatif
doit passer deux contrôles locaux bornés : syntaxe et TCP_NODELAY sur le socket
réellement transmis. Un outil compatible syntaxiquement mais laissant Nagle
actif est refusé lors de cette sélection ; le connecteur Python assure alors
le même transfert de descripteur avec TCP_NODELAY. Aucune connexion cible n'est
ouverte par ces contrôles. Une panne après sélection ne change jamais de chemin.
Avec ProxyJump, seul le premier saut utilise ce relais : le trafic cible,
encapsulé dans ce saut, n'est pas compté deux fois. Les sessions réutilisables
emploient le relais du maître ; une perte du socket n'autorise aucune connexion
directe de repli. Les transferts conservent aussi leurs plafonds rsync/SFTP.
Les limites plus fines du transfert et le plafond partagé s'appliquent ensemble.

## Configuration et dimensionnement

```sh
swassh run 'uname -r' -i examples/hosts.txt --bastion-bandwidth-kib 4096 --plan-only
swassh run 'uname -r' -i examples/hosts.txt --bastion-bandwidth-kib 4096 --budget-dir ./local-budget --format json --output report.json
```

Toutes les invocations partageant une racine doivent utiliser la même politique
active. Un conflit est refusé. Des racines distinctes ne partagent pas leur
limite : ne pas les multiplier pour contourner la politique de charge.
Un plafond très bas ralentit aussi la négociation et l'authentification SSH ;
dimensionner connect_timeout et command_timeout en conséquence.

Le relais utilise le même interpréteur Python que SWASSH, sans paquet tiers.
Cet interpréteur, le module installé et les binaires natifs sont de confiance.
Sous Windows, le chemin de l'interpréteur Python doit être littéral et sans
caractères d'expansion du shell. Les autres paramètres passent dans une enveloppe
JSON versionnée, bornée et encodée pour le shell : les pourcents et identifiants
d'interface IPv6 restent des données. Cet encodage n'est pas un chiffrement.
Les octets stdin/stdout restent binaires sur les deux plateformes.

Le plan natif inclut une base estimée de 48 Mio par travailleur, plus
16 × max_output_bytes et 8 Mio en présence d'un saut. Les transports injectés
gardent leur calcul distinct. Ces estimations réduisent l'admission mais
n'imposent pas de quota RSS ou CPU au système.

## État et reprise

La base privée `encrypted-bytes.sqlite`, sous la racine effective du budget,
est plafonnée à 1 Mio avec cache 256 Kio. Le schéma v2 conserve cadence, crédits,
horloge et droits prépayés de 1024 propriétaires au plus, sans cibles, commandes
ou secrets. Le WAL est synchronisé durablement, avec checkpoint sérialisé dès
64 Kio ; un lecteur qui empêche ce checkpoint bloque les nouveaux débits. Les
autres fichiers auxiliaires sont bornés à 2 Mio chacun et contrôlés à l'ouverture.

Chaque tranche est prépayée avant remise des octets. Les droits déjà délivrés
réduisent les nouveaux crédits disponibles : ils ne peuvent pas être émis une
seconde fois par un autre relais. Seuls les droits jamais délivrés peuvent être
restitués ; une écriture partielle ou incertaine reste entièrement débitée. Une
erreur de commit interdit toute réutilisation du cache. Les verrous du système
déterminent la vie des propriétaires, sans se fier à un PID réutilisable ni à
une expiration temporelle. Une attente ne réserve jamais des crédits futurs.
Une régression d'horloge repart de zéro crédit, sans nouvelle rafale gratuite.

Le mutex commun sérialise récupération, transactions, checkpoints et fermeture.
Ne pas supprimer son inode. L'invocation prépare le schéma et le premier
checkpoint avant l'admission des commandes, puis garde un handle ouvert ;
la création du gardien reste comptée dans le délai de commande. La préparation
locale du gardien, son admission et celle du relais ont une allowance distincte,
bornée par command_timeout ; seul le temps réellement observé avant lancement
natif est crédité. OpenSSH, son authentification et la commande gardent le délai
actif initial et un plafond natif indépendant. Les reçus privés ne contiennent
ni commande, ni secret, ni sortie distante. Voir la frontière exacte dans
[ARCHITECTURE.md](../reference/ARCHITECTURE.md#openssh).

L'arithmétique des crédits est partagée dans un état immuable léger. Le gardien
ne charge pas les métadonnées de dataclass ; les modèles publics ByteWindow et
CreditPool conservent champs, sérialisation, représentation et types de retour.
Les validations numériques, droits prépayés et règles de restitution restent
les mêmes ; aucune diminution de la synchronisation durable n'est appliquée.

Une corruption, un changement de schéma ou une erreur d'état provoque un échec
explicite du relais, sans connexion directe de secours. Ne pas supprimer la
base, les budgets ou les verrous pendant une exécution. Arrêter d'abord toutes
les invocations, conserver les preuves et examiner la cause. Un retour arrière
vers un lecteur du schéma v1 exige un arrêt complet, une sauvegarde et la
migration Down sous le mutex. Elle refuse tout propriétaire restant et conserve
les compteurs ; ne jamais effacer la base pour recréer une rafale gratuite. La
restauration d'une sauvegarde ancienne pendant une exécution est interdite.
Un retour arrière
vers rc4 retire cette limitation des flux ordinaires : tenir compte de ce
changement avant de relancer une flotte.

## Preuves et limites de mesure

[test_bandwidth.py](../../../tests/test_bandwidth.py) exerce le compteur entier,
deux propriétaires SQLite, une horloge régressive, la corruption, le parsing
OpenSSH, des octets de toutes valeurs et deux vrais relais TCP loopback.
La mesure démarre après connexion des deux relais, avant envoi des données ;
elle vérifie un plafond commun émission + réception. Un mutant temporaire
supprimant le débit est détecté par ce test. Aucun réglage réseau de l'hôte
n'est appliqué par ces essais.

Le test de bannière lance le vrai client OpenSSH mais ferme avant
authentification. Il ne remplace pas les tests sshd authentifiés, le contrôle
des retransmissions et la mesure de la carte réseau sur un parc autorisé.
Ne pas présenter cette limite applicative comme une QoS de l'infrastructure.

[test_fdpass_socket_contract.py](../../../tests/test_fdpass_socket_contract.py)
vérifie l'option du descripteur réel transmis par un outil local, sans trafic SSH.
Les tests de crédits, de stockage et d'annulation conservent les refus de
corruption, de droits perdus, de propriétaires trop nombreux et de commit ambigu.
Les séries au délai de 0,3 s ne constituent pas une garantie de temps réel sur
un système saturé. La suite native sépare l'échéance complète de 0,3 s devant
une négociation bloquée de la conservation d'une sortie déjà reçue. Dans ce
dernier cas, une préparation bornée à 10 s précède une faute de délai anticipée
à 0,3 s après réception réelle ; aucun temporisateur n'est désactivé. Ce test
ne promet pas authentification et première sortie dans une invocation de 0,3 s.
Les mutants de délai tardif, de perte de sortie et de faux succès restent refusés.
Les cinq couvertures et la recette de l'archive restent des
contrôles séparés et bloquants, détaillés dans [VALIDATION.md](../../../VALIDATION.md).
