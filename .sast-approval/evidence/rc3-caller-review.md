# Revue locale SAST v2 de SWASSH 2.0.0rc3

La nouvelle commande de maintenance reçoit trois chemins locaux choisis par
l'opérateur. Elle partage le fichier de verrou stable du nettoyeur existant
sous le parent vérifié, avec le compte propriétaire et le worker arrêté. Le
test WSL vérifie le même inode avec les deux commandes installées et observe
les refus dans les deux sens.

Les chemins du manifeste sont des chemins relatifs POSIX canoniques. La
sauvegarde contient la base SQLite autonome et, selon le cas, le journal et
les rapports. Le code refuse les liens, fichiers spéciaux, entrées
supplémentaires, journaux SQLite auxiliaires et sommes divergentes. Les
copies sont bornées et préparées sous un répertoire privé avant publication
dans une destination neuve. SQLite est ouvert avec les options de lecture
seule sur la copie vérifiée. Les contrôles de schéma, d'intégrité et de
références précèdent le passage à l'état visible. Le manifeste provient d'une
source de confiance externe à la sauvegarde.

Le changement ne lance aucune commande externe, ne change pas le transport
SSH et n'interprète pas les rapports. Le code, les contrôles et les appelants
précédemment qualifiés sont comparés aux octets de la candidate. Les preuves
individuelles des signaux inchangés sont conservées. L'examen est une revue
locale du même agent et les reçus de qualification restent hors des sources.
