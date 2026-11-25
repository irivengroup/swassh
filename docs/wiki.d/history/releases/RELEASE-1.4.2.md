# SWASSH 1.4.2 — qualification réseau native

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / history / releases / SWASSH 1.4.2 — qualification réseau native

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Échanges réellement vérifiés](#échanges-réellement-vérifiés)
- [Contrôle CI sans tests réseau ignorés](#contrôle-ci-sans-tests-réseau-ignorés)
- [Impact, installation et retour arrière](#impact-installation-et-retour-arrière)



Cette livraison du 9 octobre 2026 complète la 1.4.1 par des tests de bout en bout,
un contrôle CI strict et de nouvelles preuves d'installation Linux. Le moteur,
les options, les formats publics et les quatre améliorations gardent leur
comportement 1.4.1 ; seul le numéro de version change dans le code d'exécution.
L'archive 1.4.1 précédemment remise reste conservée.

## Échanges réellement vérifiés

Onze tests utilisent un vrai serveur OpenSSH local avec clés éphémères et
vérification des clés d'hôte. Ils couvrent succès, échec distant y compris code
255, délai, clé inconnue, rapport CLI séparé, ProxyJump, push/pull SFTP et rsync,
SHA-256 avec les deux transports, preview des ajouts/modifications/suppressions
et exécution réelle de `--delete` après le preview. Les tests SHA-256 contrôlent
les octets, la publication, l'absence de temporaire résiduel et le mode 0600.
Les previews comparent contenus, permissions et dates de modification des deux
arbres avant/après ; le transfert suivant vérifie le résultat des suppressions.

Les tests réseau utilisent rsync 3.5.1 réel aux deux extrémités, sans remplacement
du bandeau de version. Le réseau est la boucle locale d'un espace Linux isolé :
cela qualifie le protocole et l'intégration des processus, pas les performances,
latences, équipements réseau ou politiques de sécurité d'une flotte distante.

Le laboratoire local utilise des espaces de noms privés pour les montages,
processus et réseau. Les paquets sont extraits dans des couches temporaires ;
aucun script d'installation de service n'est exécuté dans le système hôte.
Les comptes et chemins du serveur n'existent que dans cet environnement. Les
installations Python du wheel et du sdist sont ensuite réalisées hors ligne
dans des environnements neufs. Voir [VALIDATION.md](../../../../VALIDATION.md) pour les
résultats, versions, empreintes de paquets et limites exactes.

## Contrôle CI sans tests réseau ignorés

```sh
python scripts/native_network_gate.py
```

Cette commande exige la réussite de tous les tests du fichier `test_native_ssh.py`.
Une suite vide, incomplète, en échec ou comportant un seul test ignoré retourne
un code non nul. L'absence de serveur ou de rsync compatible ne peut donc plus
être assimilée à une qualification réseau. La suite générale reste portable et
conserve ses skips explicites pour les capacités absentes sur les autres OS.

La CI Linux utilise Ubuntu 24.04 et le paquet
`rsync=3.5.1-1ppa~noble1` du dépôt stable du projet, recommandé par sa
[page officielle](https://rsync.samba.org/download). La clé de signature est
contrôlée par son empreinte `72BBF83452B11E5B5A8F99123CC6C2BBC7F3DB85`, puis limitée
à ce dépôt par `signed-by`. Un changement de clé ou la disparition de cette
version fait échouer le provisionnement : aucune ancienne version n'est acceptée
silencieusement. La matrice Python 3.11–3.14 et les jobs Windows/macOS sont conservés.
Les workflows distants ne sont pas déclarés exécutés sur la base de ce test local.

## Impact, installation et retour arrière

| Domaine | Évolution | Risque restant |
| --- | --- | --- |
| Moteur / CLI / stockage | Aucun changement fonctionnel par rapport à 1.4.1 | Limites de conception détaillées dans HARDENING-1.4.0.md toujours applicables |
| Tests | Trois scénarios SSH ajoutés et contrôle des skips | Boucle locale uniquement ; autres OS et réseau de production à qualifier |
| CI | Prérequis rsync signés et version fixée, gate réseau obligatoire | Dépendance à la disponibilité du dépôt de paquets ; échec explicite en cas de retrait |
| Livraison | Version 1.4.2 et preuves actualisées | Ne pas confondre installation du paquet et qualification de toutes les plateformes |

Installer `dist/swassh-1.4.2-py3-none-any.whl` dans un nouvel environnement et
vérifier `swassh --version`. Pour exécuter le gate réseau, prévoir un Linux avec
OpenSSH serveur/client, rsync 3.5.0+ local et distant, et les droits nécessaires
au serveur local de test. Les clés du test sont générées dans un répertoire privé
et ne sont pas incluses dans les distributions.

Pour revenir à 1.4.1, arrêter les admissions et attendre la fin des clients,
puis réutiliser le wheel 1.4.1 conservé. Il n'y a pas de migration de schéma entre
ces deux versions. Une rétrogradation ne restaure pas des données supprimées
par rsync : la sauvegarde des destinations reste nécessaire.
