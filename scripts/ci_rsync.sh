#!/usr/bin/env bash
# Provision the exact authenticated rsync release on an ephemeral Ubuntu CI runner.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
archive=rsync-3.5.2.tar.gz
checksum=a10d591825251e070f74c98df3daad195def4ed81b4a2de16169026aea33f6c8
fingerprint=C0E1054505704F757D925AB26A64E8AA2EFBCF5D
key="$script_dir/rsync-release-key.asc"

cd -- "$work"
for file in "$archive" "$archive.asc"; do
    curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 60 --max-filesize 4194304 \
        --output "$file" "https://download.samba.org/pub/rsync/src/$file"
done
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --strict --check -
primary=$(gpg --no-options --homedir "$work" --batch --with-colons --show-keys "$key" |
    awk -F: '$1 == "pub" {primary=1; next} $1 == "fpr" && primary {print $10; primary=0}')
test "$primary" = "$fingerprint"
gpg --no-options --homedir "$work" --batch --dearmor --output "$work/release.gpg" "$key"
gpgv --homedir "$work" --keyring "$work/release.gpg" "$archive.asc" "$archive"

# Build verified bytes without elevation. Preserve any distro rsync via dpkg
# diversion and place the CI binary in the native tests' trusted search path.
tar --extract --gzip --file "$archive" --no-same-owner
cd rsync-3.5.2
./configure --prefix=/usr
make -j2 rsync
sudo -n dpkg-divert --local --rename --add /usr/bin/rsync
sudo -n install -o root -g root -m 0755 rsync /usr/bin/rsync
installed=$(/usr/bin/rsync --version)
[[ "$installed" =~ ^rsync[[:blank:]]+version[[:blank:]]+3\.5\.2([[:blank:]]|$) ]]
printf '%s\n' "$installed"
