#!/bin/sh
# Install upstream minisign 0.12 (Linux x86_64 or aarch64) into DEST.
# The tarball is pinned by SHA-256; the extracted binary then checks the
# publisher's minisign signature of that same tarball.
#
#   scripts/install-minisign.sh /path/to/bin
set -eu

dest="${1:-/usr/local/bin}"
version="0.12"
file="minisign-${version}-linux.tar.gz"
url="https://github.com/jedisct1/minisign/releases/download/${version}/${file}"
# SHA-256 of the upstream tarball named above.
expected="9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"
# Publisher key published with minisign (Frank Denis).
publisher="RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"

case "$(uname -m)" in
    x86_64|amd64) bin_rel="minisign-linux/x86_64/minisign" ;;
    aarch64|arm64) bin_rel="minisign-linux/aarch64/minisign" ;;
    *)
        printf 'minisign-Installationsskript unterstützt nur Linux x86_64/aarch64 (ist: %s)\n' "$(uname -m)" >&2
        exit 1
        ;;
esac

command -v curl >/dev/null 2>&1 || {
    printf 'curl wird benötigt\n' >&2
    exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
    printf 'sha256sum wird benötigt\n' >&2
    exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file" "$url"
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file.minisig" "$url.minisig"
echo "$expected  $work/$file" | sha256sum -c -
tar --warning=no-unknown-keyword -xzf "$work/$file" -C "$work"
mkdir -p "$dest"
install -m 0755 "$work/$bin_rel" "$dest/minisign"
"$dest/minisign" -Vm "$work/$file" -x "$work/$file.minisig" -P "$publisher" >/dev/null
printf 'minisign %s installiert nach %s/minisign\n' "$version" "$dest"
