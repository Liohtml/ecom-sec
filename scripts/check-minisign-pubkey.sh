#!/bin/sh
# Fail if distrib/minisign.pub, install.sh and the README disagree about the
# embedded minisign public key. The Rust binary reads the same pub file.
set -eu

root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
pubfile="$root/distrib/minisign.pub"
b64="$(awk 'NR==2 { print; exit }' "$pubfile")"
[ -n "$b64" ] || {
    printf 'distrib/minisign.pub: Schlüsselzeile fehlt\n' >&2
    exit 1
}

inst="$(sed -n "s/^MINISIGN_PUB='\\(.*\\)'$/\\1/p" "$root/install.sh")"
if [ "$inst" != "$b64" ]; then
    printf 'install.sh MINISIGN_PUB weicht von distrib/minisign.pub ab\n' >&2
    exit 1
fi

if head -n 1 "$pubfile" | grep -q PLACEHOLDER; then
    grep -q '^MINISIGN_PUB_IS_PLACEHOLDER=1$' "$root/install.sh" || {
        printf 'install.sh muss MINISIGN_PUB_IS_PLACEHOLDER=1 setzen, solange der Schlüssel ein Platzhalter ist\n' >&2
        exit 1
    }
else
    grep -q '^MINISIGN_PUB_IS_PLACEHOLDER=0$' "$root/install.sh" || {
        printf 'install.sh muss MINISIGN_PUB_IS_PLACEHOLDER=0 setzen, sobald der Platzhalter ersetzt wurde\n' >&2
        exit 1
    }
fi

grep -F -q "$b64" "$root/README.md" || {
    printf 'README.md enthält den öffentlichen Schlüssel aus distrib/minisign.pub nicht\n' >&2
    exit 1
}

printf 'minisign-Public-Key ist in distrib/minisign.pub, install.sh und README.md konsistent.\n'
