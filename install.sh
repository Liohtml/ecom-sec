#!/bin/sh
# ecomsec installer – downloads the matching release binary from GitHub,
# verifies the minisign signature of SHA256SUMS and then the SHA-256
# checksum, and installs the binary. A missing or invalid signature aborts.
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
# POSIX sh; needs curl or wget, tar, sha256sum/shasum/openssl, and either
# minisign or python3 together with openssl (for the signature check).

set -eu

# Public key from distrib/minisign.pub (key id 3B76037FD551923F). Keep the
# three in sync (scripts/check-minisign-pubkey.sh). The installer refuses
# to run while MINISIGN_PUB_IS_PLACEHOLDER=1.
MINISIGN_PUB_IS_PLACEHOLDER=0
MINISIGN_PUB='RWQ/klHVfwN2O3cvbvoiSvkvYdudzeGLcY7cUA3FESnY3oM6V82YJcua'

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

# Verify a minisign signature of $1 against $2 (the .minisig file).
# Prefer the minisign binary; otherwise python3 + openssl implement the
# same check (prehashed BLAKE2b-512 or legacy raw Ed25519, plus the
# trusted comment). There is no path that skips the check.
verify_minisign() {
    file=$1
    sig=$2
    if [ "${MINISIGN_PUB_IS_PLACEHOLDER:-0}" = "1" ]; then
        err "Dieser Installer enthält noch keinen minisign-Schlüssel (Platzhalter in distrib/minisign.pub). Installation abgebrochen."
    fi
    if [ ! -s "$sig" ]; then
        err "Signaturdatei fehlt oder ist leer – Installation abgebrochen."
    fi
    if command -v minisign >/dev/null 2>&1; then
        if ! minisign -Vm "$file" -x "$sig" -P "$MINISIGN_PUB" >/dev/null 2>&1; then
            err "Signatur von SHA256SUMS ist ungültig – Installation abgebrochen."
        fi
        return 0
    fi
    if command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
        if ! python3 - "$MINISIGN_PUB" "$sig" "$file" <<'PY'
import base64, hashlib, os, subprocess, sys, tempfile

def fail():
    sys.exit(1)

def b64(text):
    compact = "".join(text.split())
    compact += "=" * ((4 - len(compact) % 4) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except Exception:
        fail()

pub_b64, sig_path, msg_path = sys.argv[1:]
raw_pk = b64(pub_b64)
if len(raw_pk) != 42 or raw_pk[:2] != b"Ed":
    fail()
key_id, pk = raw_pk[2:10], raw_pk[10:42]
try:
    text = open(sig_path, "r", encoding="utf-8").read().replace("\r\n", "\n").replace("\r", "\n")
except OSError:
    fail()
lines = [ln for ln in text.split("\n") if ln != ""]
if len(lines) != 4 or not lines[0].startswith("untrusted comment: ") or not lines[2].startswith("trusted comment: "):
    fail()
sig_struct = b64(lines[1])
if len(sig_struct) != 74 or sig_struct[2:10] != key_id:
    fail()
alg, sig = sig_struct[:2], sig_struct[10:74]
global_sig = b64(lines[3])
if len(global_sig) != 64:
    fail()
trusted = lines[2][len("trusted comment: "):]
try:
    msg = open(msg_path, "rb").read()
except OSError:
    fail()
if alg == b"ED":
    signed = hashlib.blake2b(msg, digest_size=64).digest()
elif alg == b"Ed":
    signed = msg
else:
    fail()

def ed25519_ok(message, signature):
    der = bytes.fromhex("302a300506032b6570032100") + pk
    pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode("ascii") + "\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as tmp:
        pem_path = os.path.join(tmp, "pub.pem")
        msg_path = os.path.join(tmp, "msg")
        sig_path = os.path.join(tmp, "sig")
        with open(pem_path, "w", encoding="ascii") as fh:
            fh.write(pem)
        with open(msg_path, "wb") as fh:
            fh.write(message)
        with open(sig_path, "wb") as fh:
            fh.write(signature)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pem_path, "-rawin", "-in", msg_path, "-sigfile", sig_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0

if not ed25519_ok(signed, sig) or not ed25519_ok(sig + trusted.encode("utf-8"), global_sig):
    fail()
PY
        then
            err "Signatur von SHA256SUMS ist ungültig – Installation abgebrochen."
        fi
        return 0
    fi
    err "Zur Prüfung der Release-Signatur wird minisign oder python3 zusammen mit openssl benötigt."
}

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

if [ "${MINISIGN_PUB_IS_PLACEHOLDER:-0}" = "1" ]; then
    err "Dieser Installer enthält noch keinen minisign-Schlüssel (Platzhalter in distrib/minisign.pub). Installation abgebrochen."
fi

say "ecomsec ${VERSION} für ${target} wird geladen …"
fetch "${base}/${VERSION}/SHA256SUMS.minisig" "${tmp}/SHA256SUMS.minisig" || err "SHA256SUMS.minisig konnte nicht geladen werden – Installation abgebrochen."
fetch "${base}/${VERSION}/SHA256SUMS" "${tmp}/SHA256SUMS" || err "SHA256SUMS konnte nicht geladen werden – Installation abgebrochen."
verify_minisign "${tmp}/SHA256SUMS" "${tmp}/SHA256SUMS.minisig"
say "Signatur (minisign) bestätigt."
fetch "${base}/${VERSION}/${asset}" "${tmp}/${asset}" || err "Download fehlgeschlagen: ${base}/${VERSION}/${asset}"

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
