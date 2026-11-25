# Revue locale SAST v2 — SWASSH 2.0.0rc2

La revue atteste la candidate locale extraite du ZIP identifié dans le reçu.
Le résultat brut reste disponible avec le code 1 et les 174 signaux.

Le changement de production ajoute une commande de maintenance Linux. Son
point d'entrée charge le module dans `interfaces`. Ses seules entrées sont le
chemin local d'un dossier et les 64 caractères hexadécimaux du SHA-256 attendu.
Le chemin parent est ouvert par le mécanisme existant de descripteurs épinglés,
sous le compte propriétaire. Le nom de destination est encodé puis condensé en
un nom de verrou constant et la base à traiter a un nom fixé dans le code.
Les vérifications et suppressions s'opèrent avec les descripteurs ouverts. Aucun
chemin d'exécutable ni argument SSH ne découle de ces valeurs. La commande ne
démarre aucun processus et n'établit aucune connexion.

Le nouvel appelant utilise le verrou existant dans un parent détenu et vérifié.
Le refus est mesuré avec deux processus et inotify. Les cas de SHA-256 divergent,
de dossier contenant d'autres entrées, de point de montage, de lien et d'objet
non régulier sont couverts dans les tests de la commande. La recette systemd
vérifie l'intégrité de la sauvegarde et l'absence de rejeu sur une cible locale.
La sauvegarde, l'arrêt du worker et l'absence de restauration concurrente font
partie de la procédure d'exploitation documentée.

Les autres écarts touchent la version, la documentation et les tests de
l'installateur et de la commande. Les sources, appelants et contrôles
précédemment qualifiés restent identiques. L'inventaire compare individuellement
chaque signal brut complet et l'empreinte des octets qui le déclenchent à la
revue détachée précédente. Chaque dossier individuel conserve ses preuves,
sa décision, ses limites et les empreintes d'origine. Le rapprochement avec
les nouveaux appelants lie ces preuves à la nouvelle version.

L'examen a été réalisé par le même agent que la correction dans le cadre de la
livraison locale. Les contrôles restent en place et la qualification du
scanner ne constitue qu'une des conditions de publication.
