#!/bin/sh
# ecomsec installer – downloads the matching release binary from GitHub,
# verifies its SHA-256 checksum and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/liohtml/ecom-sec/main/install.sh | sh
#   curl -fsSL …/install.sh | sh -s -- --version v0.2.0 --dir ~/bin
#
# Environment overrides:
#   ECOMSEC_VERSION        release tag to install (default: latest)
#   ECOMSEC_INSTALL_DIR    target directory (default: /usr/local/bin if
#                          writable, else ~/.local/bin)
#   ECOMSEC_REPO           GitHub repository (default: liohtml/ecom-sec)
#   ECOMSEC_DOWNLOAD_BASE  base URL of the release assets (mirrors/tests;
#                          default: https://github.com/$REPO/releases/download)
#
# POSIX sh; needs curl or wget, tar and sha256sum/shasum/openssl.

set -eu

REPO="${ECOMSEC_REPO:-liohtml/ecom-sec}"
VERSION="${ECOMSEC_VERSION:-latest}"
INSTALL_DIR="${ECOMSEC_INSTALL_DIR:-}"

say() { printf '%s\n' "$*"; }
err() { printf 'Fehler: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
ecomsec-Installer

Verwendung: install.sh [--version vX.Y.Z] [--dir VERZEICHNIS]

  --version TAG   bestimmte Version installieren (Standard: neueste)
  --dir DIR       Installationsverzeichnis (Standard: /usr/local/bin bzw. ~/.local/bin)
  -h, --help      diese Hilfe
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || err "--version erwartet einen Wert"; VERSION="$2"; shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift ;;
        --dir) [ $# -ge 2 ] || err "--dir erwartet einen Wert"; INSTALL_DIR="$2"; shift 2 ;;
        --dir=*) INSTALL_DIR="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) err "unbekannte Option: $1 (siehe --help)" ;;
    esac
done

# ------------------------------------------------------------ tools
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"; }
    fetch_stdout() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -H 'Accept: application/vnd.github+json' "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
    fetch_stdout() { wget -q -O - --header='Accept: application/vnd.github+json' "$1"; }
else
    err "curl oder wget wird benötigt."
fi
# Plain-http mirrors (local tests) must not be forced to https.
case "${ECOMSEC_DOWNLOAD_BASE:-}" in
    http://*) fetch() { if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"; else wget -q -O "$2" "$1"; fi; } ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v openssl >/dev/null 2>&1; then
    sha256() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }
else
    err "sha256sum, shasum oder openssl wird zur Prüfsummenkontrolle benötigt."
fi
command -v tar >/dev/null 2>&1 || err "tar wird benötigt."

# ------------------------------------------------------------ platform
os="$(uname -s)"
arch="$(uname -m)"
case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) err "Prozessorarchitektur $arch wird nicht unterstützt – bitte aus dem Quellcode bauen (cargo build --release)." ;;
esac
case "$os" in
    Linux) target="${arch}-unknown-linux-musl" ;;
    Darwin) target="${arch}-apple-darwin" ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        err "Unter Windows bitte das ZIP-Paket aus https://github.com/${REPO}/releases laden (ecomsec-<version>-x86_64-pc-windows-msvc.zip)." ;;
    *) err "Betriebssystem $os wird nicht unterstützt – bitte aus dem Quellcode bauen." ;;
esac

# ------------------------------------------------------------ version
if [ "$VERSION" = "latest" ]; then
    api="https://api.github.com/repos/${REPO}/releases/latest"
    VERSION="$(fetch_stdout "$api" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)" || true
    [ -n "$VERSION" ] || err "Neueste Version konnte nicht ermittelt werden ($api). Mit --version vX.Y.Z eine Version angeben."
fi
case "$VERSION" in v*) ;; *) VERSION="v${VERSION}" ;; esac

base="${ECOMSEC_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"
name="ecomsec-${VERSION}-${target}"
asset="${name}.tar.gz"

# ------------------------------------------------------------ download + verify
tmp="$(mktemp -d 2>/dev/null || mktemp -d -t ecomsec)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "ecomsec ${VERSION} für ${target} wird geladen …"
fetch "${base}/${VERSION}/${asset}" "${tmp}/${asset}" || err "Download fehlgeschlagen: ${base}/${VERSION}/${asset}"
fetch "${base}/${VERSION}/SHA256SUMS" "${tmp}/SHA256SUMS" || err "SHA256SUMS konnte nicht geladen werden – Installation abgebrochen."

expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "${tmp}/SHA256SUMS")"
[ -n "$expected" ] || err "SHA256SUMS enthält keinen Eintrag für ${asset} – Installation abgebrochen."
actual="$(sha256 "${tmp}/${asset}")"
if [ "$expected" != "$actual" ]; then
    err "Prüfsumme stimmt nicht (erwartet ${expected}, erhalten ${actual}) – Installation abgebrochen."
fi
say "Prüfsumme (SHA-256) bestätigt."

tar -xzf "${tmp}/${asset}" -C "$tmp"
bin="${tmp}/${name}/ecomsec"
[ -f "$bin" ] || err "ecomsec nicht im Archiv gefunden."

# ------------------------------------------------------------ install
if [ -z "$INSTALL_DIR" ]; then
    if [ "$(id -u)" = "0" ] || { [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; }; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
    fi
fi
mkdir -p "$INSTALL_DIR" || err "Verzeichnis ${INSTALL_DIR} kann nicht angelegt werden."
[ -w "$INSTALL_DIR" ] || err "Keine Schreibrechte in ${INSTALL_DIR} – mit sudo ausführen oder --dir angeben."

# Copy next to the target, then rename: atomic, also while ecomsec runs.
cp "$bin" "${INSTALL_DIR}/.ecomsec.new.$$"
chmod 0755 "${INSTALL_DIR}/.ecomsec.new.$$"
mv -f "${INSTALL_DIR}/.ecomsec.new.$$" "${INSTALL_DIR}/ecomsec"

installed="$("${INSTALL_DIR}/ecomsec" --version 2>/dev/null || echo "ecomsec ${VERSION}")"
say ""
say "✔ ${installed} installiert nach ${INSTALL_DIR}/ecomsec"

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        say ""
        say "Hinweis: ${INSTALL_DIR} ist nicht im PATH. Ergänzen mit:"
        say "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.profile && . ~/.profile"
        ;;
esac

cat <<EOF

Nächste Schritte:
  1. Scan starten (JTL-Shop 5 / Shopware 6 werden automatisch erkannt):
       ecomsec scan --root /var/www/shop
  2. Dashboard im Browser öffnen:
       ecomsec serve --root /var/www/shop      # http://127.0.0.1:8787
  3. Nach einer verifizierten Prüfung eine Baseline anlegen:
       ecomsec baseline create --root /var/www/shop
  4. Später aktualisieren:
       ecomsec self-update

Dokumentation: https://github.com/${REPO}
EOF
