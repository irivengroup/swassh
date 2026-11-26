# SWASSH 1.6.0 — exécution et authentification

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / releases / SWASSH 1.6.0 — exécution et authentification

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Authentification explicite](#authentification-explicite)
- [Entrée standard bornée](#entrée-standard-bornée)
- [Profils de connexion](#profils-de-connexion)
- [Décodage et sortie progressive](#décodage-et-sortie-progressive)
- [Qualification et retour arrière](#qualification-et-retour-arrière)



La syntaxe `swassh run 'commande' -i hosts.txt`, les sorties finales groupées,
leur affichage par défaut et `--hide-output` sont conservés. Les nouveaux modes
sont facultatifs. Les budgets partagés, le canary et les plafonds d’admission
restent applicables à toutes les authentifications.

## Authentification explicite

```bash
swassh run 'uname -r' -i hosts.txt --auth-method publickey
swassh run 'uname -r' -i hosts.txt --auth-method password --askpass-executable /opt/company/bin/ssh-secret-provider
swassh run 'uname -r' -i hosts.txt --auth-method gssapi
```

Le fournisseur indiqué doit réellement être installé : c’est un exécutable de
confiance compatible SSH_ASKPASS, recevant la demande OpenSSH comme argument et
renvoyant uniquement le secret sur sa sortie standard. Il doit consulter votre
gestionnaire de secrets sans interaction, sans journaliser le secret, y compris
sur stderr. Aucun mot de passe n’est accepté dans les arguments SWASSH, les
profils ou les tâches persistées. Le fichier du fournisseur doit être régulier,
sans lien final ; sous POSIX il ne doit pas être inscriptible par groupe/autres.
Une seule demande de mot de passe est autorisée par connexion. Le mode
keyboard-interactive n’est pas activé. Le fournisseur doit aussi distinguer les
demandes du bastion lorsque celui-ci utilise un mot de passe.

Kerberos nécessite un client OpenSSH compilé avec GSSAPI, un ticket valide dans
le contexte de l’utilisateur exécutant SWASSH, et une configuration de domaine,
DNS, horloge et principal de service correcte côté client et serveur. SWASSH
utilise le cache de tickets existant ; il ne lance pas kinit, ne renouvelle pas
les tickets et ne délègue pas les identifiants. Le service de planification doit
disposer lui-même du ticket et des variables de contexte nécessaires.

Chaque mode sélectionne une méthode précise sans repli automatique vers une
autre. La vérification stricte de la clé du serveur reste active. `--check`
contrôle les prérequis locaux accessibles sans appeler le fournisseur ni tester
le domaine distant. Les transferts push/pull acceptent également ces modes ;
les capacités requises dépendent du client natif installé sur chaque plateforme.

## Entrée standard bornée

```bash
swassh run 'cat > /tmp/application.conf' -i hosts.txt --stdin-file application.conf
```

Une même copie binaire du fichier est lue avant le canary et envoyée à chaque
cible avec régulation des écritures. Limite par défaut : 1 MiB ;
`--max-stdin-bytes` autorise de 1 octet à 16 MiB. Les fichiers non réguliers,
liens finaux et modifications détectées pendant la lecture sont refusés.
La fin anticipée de stdin par la commande distante est acceptée : le succès
de la commande ne prouve donc pas qu’elle a consommé toute l’entrée.

Pour schedule, seul le chemin absolu et le SHA-256 sont persistés. Le fichier
doit rester accessible et identique au lancement ; toute divergence est refusée.
Les octets ne sont pas stockés dans la base des tâches. Cette option concerne
run et schedule, pas les transferts.

## Profils de connexion

`--host-profiles profils.json` accepte une liste JSON stricte :

```json
[
  {"hostname": "srv01", "port": 22, "username": "deploy", "encoding": "latin-1", "connect_timeout": 15},
  {"hostname": "srv02", "auth_method": "gssapi"}
]
```

Champs autorisés : hostname, port, username, client_keys (liste), known_hosts,
connect_timeout, command_timeout, encoding et auth_method. Un profil correspond
exactement au couple hôte/port normalisé ; aucun joker. Les chemins des clés et
known_hosts relatifs sont résolus depuis le dossier JSON. Limites : 10 000
profils et 4 MiB de document ; les doublons et champs inconnus sont refusés.
Priorité utilisateur : utilisateur explicite dans l’inventaire, puis profil,
puis option globale. Les paramètres du bastion proviennent des options globales,
sans héritage des clés de la cible. Les profils ne peuvent modifier les budgets,
le fournisseur de secrets ou les plafonds de concurrence. Le délai des transferts
reste celui des options de transfert.

## Décodage et sortie progressive

`--encoding` choisit un codec texte Python pour stdout/stderr distants (UTF-8
par défaut) ; les séquences invalides sont remplacées. Cela ne change ni les
octets stdin, ni l’encodage des fichiers transférés.

```bash
swassh run 'journalctl -n 100' -i hosts.txt --stream-output --stream-rate 100 2> progression.jsonl
```

Le flux facultatif est du JSONL sur stderr, distinct du rapport final habituel
sur stdout. Les chaînes JSON échappent les caractères de contrôle du terminal.
Les fragments sont bornés à 1 024 caractères et signalent leur continuation.
`--stream-rate` borne globalement les événements par seconde (1 à 10 000).
Les événements dépassant le débit sont comptés, avec bilan stream_finished ;
ils ne sont pas mis dans une file illimitée. Les limites de capture existantes
restent applicables : ce flux ne constitue pas une archive exhaustive.

Un processus gardé isole l’écriture de sortie. Un consommateur bloqué entraîne
un échec explicite borné et l’arrêt du processus, sans accumulation illimitée.
Un échec de ce flux peut empêcher la finalisation du rapport : conserver les
journaux d’audit et ne pas relancer automatiquement une commande ayant pu agir.
Le budget mémoire tient compte du processus de sortie, des profils et de stdin.
Sans --stream-output, le rendu final historique est conservé.

## Qualification et retour arrière

| Impact | Invariant/protection | Limite opérationnelle |
| --- | --- | --- |
| CLI et rapports | Options facultatives, sorties finales et codes existants conservés | Le flux progressif utilise stderr et peut être échantillonné |
| Sécurité | Clé serveur stricte, fournisseur externe, aucune délégation GSSAPI | Fournisseur, client natif et répertoires administrés restent de confiance |
| Concurrence/mémoire | Budget commun, débit agrégé, fragments et stdin bornés | Les quotas applicatifs ne remplacent pas les quotas système |
| Résilience | Délais et arrêt des descendants locaux, pas de rejeu d’état distant ambigu | Tuer le client ne garantit pas l’arrêt du processus distant |
| Planification | Options sérialisées, chemins absolus et empreinte stdin | Ticket et fournisseur doivent fonctionner dans le contexte du worker |
| Compatibilité/retour arrière | Lecture des tâches anciennes, anciens artefacts conservés | Les tâches nouvelles doivent être traitées avant rétrogradation |
| Observation | Résultats, métriques, compteur de fragments écartés et audit existant | Les sorties distantes peuvent elles-mêmes contenir des données sensibles |

Menaces traitées : mélange des clés cible/bastion, injection par profil, lecture
de fichier spécial, substitution de chemin, fuite du mot de passe dans les
options persistées, saturation par sortie distante et blocage du consommateur.
Les tests associés vérifient les refus, les bornes et la fin des processus locaux.

Voir VALIDATION.md pour les résultats réellement exécutés, les exclusions et
les plateformes non disponibles. Un banc de 50 000 hôtes simulés vérifie les
bornes de l’orchestrateur ; il ne représente pas 50 000 connexions SSH réelles.
Les tests natifs d’authentification utilisent un domaine et des comptes jetables
dans des espaces Linux privés. Leur lancement nécessite root, unshare, OpenSSH,
MIT Kerberos et les outils de gestion des comptes :

```bash
sudo python3 scripts/native_auth_gate.py
```

Les tâches anciennes restent lisibles. Avant retour à 1.5.3, terminer ou annuler
les tâches créées avec 1.6.0 et conserver une sauvegarde cohérente de la base :
l’ancienne version ne reconnaît pas les nouveaux champs d’options. Conserver
les rapports et réinstaller le wheel précédent dans l’environnement concerné.
La désinstallation du package ne retire pas les tâches déjà confiées au service.

La neutralisation de la qualification des noms courts dans le banc Kerberos
évite une dépendance au domaine DNS de la machine hôte ; voir la
[documentation MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-current/doc/admin/conf_files/krb5_conf.html).
