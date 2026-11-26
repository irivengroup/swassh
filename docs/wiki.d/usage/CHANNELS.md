# Canaux binaires et tunnels SSH

<!-- swassh-navigation:start -->
Fil d’Ariane : Documentation / usage / Canaux binaires et tunnels SSH

[Retour au Parent](index.md)
<!-- swassh-navigation:end -->

**Sommaire local**

- [Canal de commande binaire](#canal-de-commande-binaire)
- [Tunnel TCP local](#tunnel-tcp-local)
- [Frontières de confiance et durée](#frontières-de-confiance-et-durée)
- [Nettoyage et qualification](#nettoyage-et-qualification)



Ces API asynchrones possèdent une connexion native gardée, une réservation
indépendante et une configuration privée. Les clés d'hôte restent strictes,
l'agent et X11 ne sont pas transférés, et aucune configuration SSH ambiante
n'est chargée. Les scopes sont à usage unique et ne peuvent être imbriqués
ou hérités depuis une Session déjà ouverte. Entrée et sortie du contexte
appartiennent à la même tâche asyncio.

## Canal de commande binaire

```python
import asyncio
from swassh import AsyncClient, Options

async def main():
    client = AsyncClient("srv01", options=Options(command_timeout=30))
    async with client.channel("cat") as channel:
        await channel.send(b"demo\x00\xff")
        channel.close_input()
        capture = await channel.wait()
        if not capture.ok:
            raise RuntimeError("SSH command failed")
        assert capture.stdout == b"demo\x00\xff"

if __name__ == "__main__":
    asyncio.run(main())
```

Cet exemple exige `cat` sur une cible POSIX. `SSHChannel(host, command, options)`
est le constructeur direct. `send` accepte des bytes, au plus 16384 par appel
et `max_stdin_bytes` au total. `close_input` envoie EOF. `read("stdout")` et
`read("stderr")` renvoient un fragment d'au plus 4096 octets, ou b'' à EOF.
Pour traiter les sorties en direct, lire les deux flux concurremment ; ils
n'ont aucun ordre chronologique commun.

`wait` draine les fragments non encore lus et renvoie `ChannelCapture` avec
les captures complètes stdout/stderr, statut, code de sortie et erreur contrôlée.
Ces captures incluent aussi les fragments déjà lus. Le code ne décode ni ne
transforme les octets. Une sortie dépassant `max_output_bytes` par flux ferme
explicitement le canal ; aucune troncature n'est déclarée comme un succès.
Deux files de quatre fragments et les captures bornées appliquent la pression
en retour. `retries`, stdin_file, PTY, stream_output et modes d'admission de
flotte sont refusés dans ce scope.

## Tunnel TCP local

```sh
swassh tunnel -H bastion --local-port 18443 --remote-host service.internal --remote-port 443 --lifetime 300 --plan-only
swassh tunnel -H bastion --local-port 18443 --remote-host service.internal --remote-port 443 --lifetime 300
```

`--check` vérifie seulement les prérequis locaux. L'exécution reste au premier
plan jusqu'à fermeture, interruption ou échéance. La CLI annonce `listening`
après authentification et preuve de création du listener local ; elle annonce
aussi `destination_verified=false`. Une fermeture inattendue ou une échéance
se traduit par une erreur non nulle ; Ctrl+C effectue le nettoyage normal.

L'API correspondante est
`SSHTunnel(host, LocalForward(local_port, remote_host, remote_port), options,
lifetime=300)` ; `AsyncClient.tunnel` fournit la même portée pour un hôte unique.
`is_open` indique l'état local observé et `await tunnel.wait()` attend une
fermeture, puis lève une erreur. Toujours l'utiliser dans `async with`.

## Frontières de confiance et durée

Les adresses d'écoute sont uniquement 127.0.0.1 ou ::1 ; aucun wildcard, port
zéro, tunnel distant ou SOCKS implicite n'est accepté. Un autre utilisateur
local capable d'atteindre ce port peut l'utiliser : le service destination
doit conserver sa propre authentification. Conserver également ses contrôles
TLS et le nom de serveur attendu, même si le socket local pointe sur loopback.
Le nom destination est résolu côté serveur SSH.

La readiness ne prouve ni la disponibilité, ni l'autorisation, ni l'identité
applicative de la destination. Aucun sondage du service n'est effectué pour
fabriquer une réussite. OpenSSH reçoit ExitOnForwardFailure=yes et
GatewayPorts=no ; la configuration privée n'ajoute que le forward déclaré.

La durée active d'un tunnel vaut 1..3600 secondes après readiness. Son démarrage
est borné séparément par connect_timeout + report_timeout. Le guardian impose
aussi ce plafond total si la boucle Python se bloque. Un canal de commande
conserve command_timeout, y compris sa connexion. Les diagnostics privés sont
bornés à 128 Kio. Ils peuvent contenir le nom de commande et sont supprimés
après fermeture ; ne pas les copier dans un journal public.

Pour une `Session` réutilisable, `lifetime` borne le maître depuis son
démarrage natif après admission, authentification comprise. Une durée d'une
seconde peut donc expirer avant l'ouverture du socket de contrôle ; elle ne
promet pas une seconde d'utilisation après authentification. Le gardien garde
cette même limite si la boucle Python se bloque. Choisir une durée adaptée au
démarrage attendu, tout en conservant une limite finie. La perte du maître
interdit toute reconnexion ou répétition automatique d'une commande.

## Nettoyage et qualification

Sortir tôt, lever une exception ou annuler ferme les descendants locaux avant
de libérer la capacité. Une erreur asynchrone de lecture attend aussi l'arrêt
natif. Cela ne garantit pas l'arrêt d'une commande déjà reçue par le serveur.
Fermer un tunnel n'annule pas les opérations applicatives qui y sont passées.

[test_channels.py](../../../tests/test_channels.py) couvre les limites,
les octets binaires, la révocation, la réservation et l'arrêt d'un producteur
avec sortie non lue. Ces essais utilisent un pair synthétique et un vrai
guardian. Les cas authentifiés sont dans
[test_native_ssh.py](../../../tests/test_native_ssh.py) et nécessitent sshd.
Une réussite synthétique n'est pas une qualification de tous les clients ou
serveurs OpenSSH. Les restrictions et recettes courantes restent dans
[VALIDATION.md](../../../VALIDATION.md).
