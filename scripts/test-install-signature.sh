#!/bin/sh
# Exercise install.sh against a local release: a valid minisign signature is
# accepted (via python3+openssl and via the minisign binary), a manipulated
# SHA256SUMS is rejected, and a missing signature aborts.
set -eu

root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

sh "$root/scripts/install-minisign.sh" "$work/bin" >/dev/null
minisign="$work/bin/minisign"

"$minisign" -G -W -p "$work/minisign.pub" -s "$work/minisign.key" >/dev/null
pub="$(awk 'NR==2 { print; exit }' "$work/minisign.pub")"

arch="$(uname -m)"
case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
        printf 'Architektur %s wird von diesem Test nicht unterstützt\n' "$arch" >&2
        exit 1
        ;;
esac
os="$(uname -s)"
case "$os" in
    Linux) target="${arch}-unknown-linux-musl" ;;
    Darwin) target="${arch}-apple-darwin" ;;
    *)
        printf 'Betriebssystem %s wird von diesem Test nicht unterstützt\n' "$os" >&2
        exit 1
        ;;
esac

version="v9.9.9"
name="ecomsec-${version}-${target}"
rel="$work/releases/download/${version}"
mkdir -p "$rel/$name"
cat > "$rel/$name/ecomsec" <<'EOF'
#!/bin/sh
printf '%s\n' 'ecomsec 9.9.9'
EOF
chmod 0755 "$rel/$name/ecomsec"
tar -czf "$rel/${name}.tar.gz" -C "$rel" "$name"
rm -rf "${rel:?}/${name:?}"
(cd "$rel" && sha256sum "${name}.tar.gz" > SHA256SUMS)
"$minisign" -S -s "$work/minisign.key" -m "$rel/SHA256SUMS" -x "$rel/SHA256SUMS.minisig" </dev/null >/dev/null

python3 - "$root/install.sh" "$work/install.sh" "$pub" <<'PY'
import pathlib, sys
src, dst, pub = sys.argv[1:]
out = []
for line in pathlib.Path(src).read_text().splitlines(True):
    if line.startswith("MINISIGN_PUB="):
        out.append(f"MINISIGN_PUB='{pub}'\n")
    elif line.startswith("MINISIGN_PUB_IS_PLACEHOLDER="):
        out.append("MINISIGN_PUB_IS_PLACEHOLDER=0\n")
    else:
        out.append(line)
pathlib.Path(dst).write_text("".join(out))
PY
chmod 0755 "$work/install.sh"

port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 &
httpd=$!
cleanup() { kill "$httpd" 2>/dev/null || true; }
trap 'cleanup; rm -rf "$work"' EXIT INT TERM
i=0
while [ "$i" -lt 50 ]; do
    if python3 - "$port" <<'PY'
import sys, urllib.request
urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/", timeout=0.2).read(1)
PY
    then
        break
    fi
    i=$((i + 1))
    sleep 0.05
done

base="http://127.0.0.1:${port}/releases/download"
run_install() {
    # PATH without the test's minisign, unless $1 is "minisign".
    mode=$1
    dest=$2
    if [ "$mode" = "minisign" ]; then
        PATH="$work/bin:$PATH"
    else
        PATH="/usr/bin:/bin"
    fi
    export PATH
    ECOMSEC_DOWNLOAD_BASE="$base" ECOMSEC_INSTALL_DIR="$dest" \
        sh "$work/install.sh" --version "$version" --dir "$dest"
}

mkdir -p "$work/ok-py"
run_install python "$work/ok-py" >"$work/ok-py.log" 2>&1
grep -q "Signatur (minisign) bestätigt." "$work/ok-py.log"
"$work/ok-py/ecomsec" --version | grep -q "9.9.9"

# Manipulated checksum file, signature unchanged: must fail closed.
cp "$rel/SHA256SUMS" "$work/SHA256SUMS.good"
printf 'ff\n' >> "$rel/SHA256SUMS"
mkdir -p "$work/bad"
if run_install python "$work/bad" >"$work/bad.log" 2>&1; then
    printf 'manipulierte SHA256SUMS wurde akzeptiert\n' >&2
    exit 1
fi
grep -q "Signatur von SHA256SUMS ist ungültig" "$work/bad.log"
cp "$work/SHA256SUMS.good" "$rel/SHA256SUMS"

mkdir -p "$work/ok-bin"
run_install minisign "$work/ok-bin" >"$work/ok-bin.log" 2>&1
grep -q "Signatur (minisign) bestätigt." "$work/ok-bin.log"

rm -f "$rel/SHA256SUMS.minisig"
mkdir -p "$work/missing"
if run_install python "$work/missing" >"$work/missing.log" 2>&1; then
    printf 'fehlende Signatur wurde akzeptiert\n' >&2
    exit 1
fi
grep -q "SHA256SUMS.minisig konnte nicht geladen werden" "$work/missing.log"

printf 'install.sh akzeptiert eine gültige Signatur und lehnt eine manipulierte SHA256SUMS ab.\n'
