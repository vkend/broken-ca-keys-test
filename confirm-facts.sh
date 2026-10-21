#!/bin/bash
# Confirm, by running real code, who was exposed to the eight broken eMudhra
# keys and what fixes it, beyond check.sh: macOS's own verdict, Go 1.26 and
# 1.27 before and after, certifi's releases, webpki-roots, Node's releases
# before and after the fix, Microsoft's trust lists, Debian's
# ca-certificates, Firefox's OneCRL and Chrome's CRLSet. The Rust test
# itself, from a clean build, is confirm-rust.sh.
#
#   ./setup.sh && ./confirm-facts.sh
#
# Needs the network (first run): it downloads only public artifacts into
# $C/facts, each checked against its publisher's checksum (Node's
# SHASUMS256.txt, PyPI's sha256, Debian snapshot's SHA-1, the Bugzilla
# attachment hashes below). Nothing about trust changes on this
# Mac: the system roots and Apple's revocation data are only read. No ports:
# the TLS tests run in memory. The made-up leaf for the handshakes is signed
# with a throwaway key, and its own key is a throwaway too, kept in a temp
# dir and deleted at the end. No eMudhra private key is used or computed.
set -euo pipefail
source "$(dirname "$0")/env.sh"
F="$C/facts"; mkdir -p "$F"
T=$(mktemp -d "$R/facts.XXXX"); trap 'rm -rf "$T"' EXIT
CERTS="$REPO_DIR/certs"
PY=/opt/homebrew/bin/python3
say() { printf '\n## %s\n' "$*"; }
fetch() {  # fetch <url> <file> [sha256|sha1:<hex>]
    [ -s "$F/$2" ] || curl -sfL -m 300 -o "$F/$2" "$1"
    if [ -n "${3:-}" ]; then
        case "$3" in sha1:*) got=$(shasum -a 1 "$F/$2" | cut -d' ' -f1); want=${3#sha1:} ;;
                     *) got=$(shasum -a 256 "$F/$2" | cut -d' ' -f1); want=$3 ;; esac
        [ "$got" = "$want" ] || { echo "CHECKSUM MISMATCH: $2"; exit 1; }
    fi
}
spki256() { openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform der | shasum -a 256 | cut -d' ' -f1; }

# The made-up leaf with its own throwaway key, and the chain a server would send.
(cd "$REPO_DIR/go" && GOTOOLCHAIN=local go build -trimpath -o "$T/mkleaf" ./mkleaf)
"$T/mkleaf" "$CERTS/EM-DV-TLS-CA-G3B.pem" "$T/leaf.key" > "$T/leaf.pem"
cat "$T/leaf.pem" "$CERTS/EM-DV-TLS-CA-G3B.pem" "$CERTS/emSign-Root-TLS-CA-G3-by-ECC-G3.pem" > "$T/chain-emsign.pem"

# The eight eMudhra-issued certificates and Sectigo's eight cross-signs (Bugzilla attachments).
fetch "https://bugzilla.mozilla.org/attachment.cgi?id=9664066" 9664066.zip 3175038d7538f0b6c45b2efb1064a9c42b004554ff0027b5811e7df76997215a
fetch "https://bugzilla.mozilla.org/attachment.cgi?id=9664067" 9664067.zip 892e5d472746a2ab5955692dd91e08cceb3834584cbf8139eb1943ee27bf1575
mkdir -p "$T/emudhra" "$T/sectigo"
unzip -q -j -o "$F/9664066.zip" '*.crt.pem' -d "$T/emudhra"
unzip -q -j -o "$F/9664067.zip" '*.crt.pem' -d "$T/sectigo"
echo "certificates: $(ls "$T/emudhra" | wc -l | tr -d ' ') eMudhra-issued, $(ls "$T/sectigo" | wc -l | tr -d ' ') Sectigo cross-signs"

say "1. macOS: Apple's own check of the eMudhra-issued intermediate (read only)"
# verify-cert evaluates trust without changing it; it exits non-zero on a rejection.
echo "eMudhra's copy:  $( (security verify-cert -c "$CERTS/EM-DV-TLS-CA-G3B.pem" -c "$CERTS/emSign-Root-TLS-CA-G3-by-ECC-G3.pem" -p basic -R offline 2>&1 || true) | tail -1)"
echo "Sectigo's copy:  $( (security verify-cert -c "$CERTS/EM-DV-TLS-CA-G3B-AAA.pem" -p basic -R offline 2>&1 || true) | tail -1)"
for name in "AAA Certificate Services" "emSign ECC Root CA - G3"; do
    n=$(security find-certificate -a -c "$name" /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep -c '"labl"' || true)
    echo "this Mac's system roots: $name: $n"
done

say "2. Go: built from source with 1.27.2 / 1.27.3 and 1.26.9 / 1.26.10"
echo "--- on this Mac, as a Go program checks by default (Go hands the chain to macOS):"
for v in go1.27.2 go1.27.3; do
    (cd "$REPO_DIR/go" && GOTOOLCHAIN=$v GOPROXY=https://proxy.golang.org go build -trimpath -o "$T/gocheck-$v" ./gocheck)
    (cd "$U/app" && printf '%-10s %s\n' "$v" "$("$T/gocheck-$v" | sed -n 3p)")
done
echo "--- Go's own check, as on Linux: the July root list (certifi 2026.7.22) as the roots"
cp -R "$REPO_DIR/go" "$T/go126"; sed -i '' 's/^go 1.27$/go 1.26/' "$T/go126/go.mod"
for v in go1.26.9 go1.26.10 go1.27.2 go1.27.3; do
    (cd "$T/go126" && GOTOOLCHAIN=$v GOPROXY=https://proxy.golang.org go build -trimpath -o "$T/gofacts-$v" ./gofacts)
    "$T/gofacts-$v" "$REPO_DIR/bundles/certifi-2026.7.22.pem" "$CERTS/EM-DV-TLS-CA-G3B.pem" "$CERTS/emSign-Root-TLS-CA-G3-by-ECC-G3.pem"
done

say "3. Python: certifi 2026.7.22, 2026.10.18 and 2026.10.19, Python's own TLS check (in memory)"
for v in 2026.7.22 2026.10.18 2026.10.19; do
    read -r url sha < <($PY -c "
import json,urllib.request,sys
d=json.load(urllib.request.urlopen('https://pypi.org/pypi/certifi/$v/json'))
w=[u for u in d['urls'] if u['packagetype']=='bdist_wheel'][0]; print(w['url'], w['digests']['sha256'])")
    fetch "$url" "certifi-$v.whl" "$sha"
    unzip -q -p "$F/certifi-$v.whl" certifi/cacert.pem > "$T/certifi-$v.pem"
    printf 'certifi %-11s %3s roots; emSign ECC Root CA - G3: %s; AAA: %s; %s\n' "$v" \
        "$(grep -c BEGIN "$T/certifi-$v.pem")" \
        "$(grep -q 'emSign ECC Root CA - G3' "$T/certifi-$v.pem" && echo yes || echo no)" \
        "$(grep -q 'AAA Certificate Services' "$T/certifi-$v.pem" && echo yes || echo no)" \
        "$($PY "$REPO_DIR/python/handshake.py" "$T/certifi-$v.pem" "$T/chain-emsign.pem" "$T/leaf.key" | tail -1)"
done
$PY "$REPO_DIR/python/handshake.py" "$T/certifi-2026.7.22.pem" "$T/chain-emsign.pem" "$T/leaf.key" | head -1

say "4. Rust with webpki-roots (its own root list): 1.0.9 and 1.0.10, rustls-webpki held at 0.103.15"
cp -R "$REPO_DIR/rust-roots" "$T/rr"
for v in 1.0.9 1.0.10; do
    (cd "$T/rr" && CARGO_NET_OFFLINE=false cargo update -q -p webpki-roots --precise "$v" 2>/dev/null || CARGO_NET_OFFLINE=false cargo generate-lockfile -q && CARGO_NET_OFFLINE=false cargo update -q -p webpki-roots --precise "$v"
     CARGO_NET_OFFLINE=false cargo build -q 2>&1 | sed "s#$R#\$R#g"
     printf 'webpki-roots %-7s ' "$v"; "$CARGO_TARGET_DIR/debug/check-roots" "$T/leaf.pem" "$CERTS/EM-DV-TLS-CA-G3B.pem" "$CERTS/emSign-Root-TLS-CA-G3-by-ECC-G3.pem" | tr '\n' ' '; echo)
done

say "5. Node.js before and after the fix (nodejs/node PR #66871): the compiled-in root list, Node's own TLS check (in memory)"
for v in v26.12.0 v26.12.1 v24.22.0 v24.22.1; do
    fetch "https://nodejs.org/dist/$v/SHASUMS256.txt" "node-$v-SHASUMS256.txt"
    tgz="node-$v-darwin-arm64.tar.gz"
    fetch "https://nodejs.org/dist/$v/$tgz" "$tgz" "$(grep " $tgz\$" "$F/node-$v-SHASUMS256.txt" | cut -d' ' -f1)"
    tar -xzf "$F/$tgz" -C "$T" "node-$v-darwin-arm64/bin/node"
    "$T/node-$v-darwin-arm64/bin/node" "$REPO_DIR/node/handshake.mjs" "$T/chain-emsign.pem" "$T/leaf.key" | tr '\n' ' '; echo
done
echo "--- the fix (nodejs/node PR #66871): merged, and in which releases?"
GH() { curl -sfL -m 60 -H "Accept: application/vnd.github+json" "https://api.github.com/$1"; }
GH repos/nodejs/node/pulls/66871 | $PY -c "import sys,json;d=json.load(sys.stdin);print(f\"merged: {d['merged']} at {d['merged_at']}, into {d['base']['ref']}: {d['title']}\")"
GH repos/nodejs/node/pulls/66871/files > "$T/pr-files.json"
files=$($PY -c "import json;print(' '.join(f['filename'] for f in json.load(open('$T/pr-files.json'))))")
echo "files it changes: $files"
for v in v26.12.0 v26.12.1 v24.22.0 v24.22.1; do
    f=$(echo "$files" | tr ' ' '\n' | grep -m1 '^src/.*\.\(cc\|h\)$' || true)
    if [ -n "$f" ]; then
        first_added=$($PY -c "import json;print([x['patch'] for x in json.load(open('$T/pr-files.json')) if x['filename']=='$f'][0])" \
            | grep '^+' | grep -v '^+++' | sed 's/^+//' | grep -m1 -E '[A-Za-z0-9]{12,}' | tr -d ' \t')
        at_tag=$(curl -sfL -m 60 "https://raw.githubusercontent.com/nodejs/node/$v/$f" | tr -d ' \t' || true)
        echo "$v: $f $(printf '%s' "$at_tag" | grep -qF "$first_added" && echo 'HAS the fix' || echo 'does not have the fix')"
    fi
done
echo "--- newest releases:"; curl -s https://nodejs.org/dist/index.json | $PY -c "import sys,json;print(', '.join(f\"{r['version']} ({r['date']})\" for r in json.load(sys.stdin)[:4]))"

say "6. Windows: Microsoft's published trust lists (authroot: trusted roots; disallowed: untrusted)"
for cab in authrootstl disallowedcertstl; do
    curl -sfL -m 120 -o "$T/$cab.cab" "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/$cab.cab"
    (cd "$T" && bsdtar -xf "$cab.cab")
done
$PY - "$T" <<'PY'
import glob, hashlib, subprocess, sys, pathlib
t = pathlib.Path(sys.argv[1])
def der(p): return subprocess.run(["openssl", "x509", "-in", p, "-outform", "der"], capture_output=True).stdout
auth = (t / "authroot.stl").read_bytes(); dis = (t / "disallowedcert.stl").read_bytes()
aaa = subprocess.run(["security", "find-certificate", "-c", "AAA Certificate Services", "-p",
                      "/System/Library/Keychains/SystemRootCertificates.keychain"], capture_output=True, text=True).stdout
open(t / "aaa.pem", "w").write(aaa)
print("AAA Certificate Services in Microsoft's trusted roots (authroot.stl):",
      "yes" if hashlib.sha1(der(str(t / "aaa.pem"))).digest() in auth else "no")
def keybits(p):   # the subjectPublicKey BIT STRING's bits (an EC point), without the SPKI wrapper
    pk = subprocess.run(["openssl", "x509", "-in", p, "-noout", "-pubkey"], capture_output=True).stdout
    d = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pk, capture_output=True).stdout
    def tlv(b, i):                      # (tag, start of value, end of value) of the DER element at i
        n = b[i + 1]; off = i + 2
        if n & 0x80: k = n & 0x7f; n = int.from_bytes(b[off:off + k], "big"); off += k
        return b[i], off, off + n
    _, inner, _ = tlv(d, 0)             # SubjectPublicKeyInfo SEQUENCE
    _, _, alg_end = tlv(d, inner)       # AlgorithmIdentifier
    tag, v, end = tlv(d, alg_end)       # subjectPublicKey BIT STRING
    assert tag == 0x03
    return d[v + 1:end]                 # skip the unused-bits byte
for group in ("emudhra", "sectigo"):
    certs = sorted(glob.glob(str(t / group / "*.crt.pem")))
    by_cert = sum(hashlib.sha1(der(c)).digest() in dis for c in certs)
    by_key = sum(hashlib.md5(keybits(c)).digest() in dis for c in certs)
    print(f"{group} certificates in Microsoft's disallowed list: by certificate SHA-1 {by_cert} of {len(certs)}, "
          f"by the MD5 of the key (a key match) {by_key} of {len(certs)}")
PY

say "7. Debian: ca-certificates 20250419 (before the fix) and 20260816+nmu1 (bug #1151413)"
for v in 20250419 20260816+nmu1; do
    h=$(curl -s "https://snapshot.debian.org/mr/package/ca-certificates/$v/binfiles/ca-certificates/$v" | $PY -c "import sys,json;print(json.load(sys.stdin)['result'][0]['hash'])")
    fetch "https://snapshot.debian.org/file/$h" "ca-certificates_$v.deb" "sha1:$h"
    mkdir -p "$T/deb-$v" && (cd "$T/deb-$v" && ar x "$F/ca-certificates_$v.deb" && tar -xf data.tar.* 2>/dev/null)
    d="$T/deb-$v/usr/share/ca-certificates/mozilla"
    printf 'ca-certificates %-14s %s roots; AAA (Comodo_AAA_Services_root.crt): %s; emSign ECC Root CA - G3: %s\n' "$v" \
        "$(ls "$d" | wc -l | tr -d ' ')" "$([ -e "$d/Comodo_AAA_Services_root.crt" ] && echo yes || echo no)" \
        "$(ls "$d" | grep -q 'emSign_ECC_Root_CA_-_G3' && echo yes || echo no)"
done

say "8. Firefox: OneCRL, Mozilla's block list, as served today"
curl -sfL -m 120 -o "$T/onecrl.json" "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/changeset?_expected=0"
$PY - "$T" "$CERTS" <<'PY'
import base64, json, subprocess, sys, pathlib, glob
t, certs = pathlib.Path(sys.argv[1]), sys.argv[2]
recs = json.load(open(t / "onecrl.json"))["changes"]
serials = {}
for c in sorted(glob.glob(str(t / "emudhra" / "*TLS*.crt.pem"))):
    s = subprocess.run(["openssl", "x509", "-in", c, "-noout", "-serial"], capture_output=True, text=True).stdout.split("=")[1].strip()
    raw = bytes.fromhex(s.rjust(len(s) + len(s) % 2, "0"))
    if raw[0] & 0x80:      # DER INTEGER: a leading 00 keeps it positive, and OneCRL stores the DER contents
        raw = b"\x00" + raw
    serials[pathlib.Path(c).name.replace(".crt.pem", "")] = base64.b64encode(raw).decode()
for name, b64 in serials.items():
    rec = next((r for r in recs if r.get("serialNumber") == b64), None)
    print(f"{name:18s} serial in OneCRL: {'yes, ' + rec['details'].get('bug', '') + ' ' + rec.get('details', {}).get('created', '') if rec else 'no'}")
PY

say "9. Chrome: the CRLSet as served today (blocked public keys)"
curl -sfL -m 120 -o "$T/crlset.crx" "https://clients2.google.com/service/update2/crx?response=redirect&x=id%3Dhfnkpimlhhgieaddgfemjhofmfblmnib%26v%3D%26uc&acceptformat=crx3&prodversion=140.0"
$PY - "$T" <<'PY'
import base64, glob, hashlib, io, json, struct, subprocess, sys, zipfile, pathlib
t = pathlib.Path(sys.argv[1]); b = (t / "crlset.crx").read_bytes()
assert b[:4] == b"Cr24", "not a CRX3"
hl = struct.unpack("<I", b[8:12])[0]
z = zipfile.ZipFile(io.BytesIO(b[12 + hl:]))
crl = z.read("crl-set"); n = struct.unpack("<H", crl[:2])[0]; head = json.loads(crl[2:2 + n])
blocked = set(head.get("BlockedSPKIs", []))
print(f"CRLSet sequence {head.get('Sequence')}: {len(blocked)} blocked SPKIs")
def spki(p):
    pk = subprocess.run(["openssl", "x509", "-in", p, "-noout", "-pubkey"], capture_output=True).stdout
    d = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pk, capture_output=True).stdout
    return base64.b64encode(hashlib.sha256(d).digest()).decode()
for c in sorted(glob.glob(str(t / "emudhra" / "*.crt.pem"))):
    print(f"{pathlib.Path(c).name.replace('.crt.pem',''):18s} key blocked by Chrome: {'yes' if spki(c) in blocked else 'no'}")
PY
