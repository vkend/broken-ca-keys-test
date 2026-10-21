#!/bin/bash
# Confirm the Rust test from scratch, independently of check.sh: a clean
# build of ~/app from source on each rustls-webpki version, every run, the
# chain checked with openssl against the Mac's own AAA Certificate Services
# root (read only), and where in rustls-webpki's source each result comes
# from. Prints a report; nothing about trust is changed. Run after setup.sh:
#
#   ./confirm-rust.sh
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$U/app"
T=$(mktemp -d "$R/confirm.XXXX")
trap 'rm -rf "$T"' EXIT
say() { printf '\n## %s\n' "$*"; }

say "1. Clean build on rustls-webpki 0.103.15 (target dir emptied first)"
cp "$REPO_DIR/rust/Cargo-0.103.15.lock" Cargo.lock
rm -rf "$CARGO_TARGET_DIR/debug/check" "$CARGO_TARGET_DIR/debug/.fingerprint/check-"* "$CARGO_TARGET_DIR/debug/build/check-"*
CARGO_TERM_QUIET=false cargo build --locked 2>&1 | sed "s#$R#\$R#g"
echo "./check -> $(readlink check | sed "s|$R|\$R|")"
grep -A1 'name = "rustls-webpki"' Cargo.lock
echo "binary: $(shasum -a 256 check | cut -c1-16)…, built $(date -u -r check +%FT%TZ)"

say "2. Runs on 0.103.15"
echo '$ ./check';           ./check           || echo "(exit $?)"
echo '$ ./check --control'; ./check --control || echo "(exit $?)"

say "3. The chain, checked with openssl against this Mac's own roots"
security find-certificate -a -c "AAA Certificate Services" -p \
  /System/Library/Keychains/SystemRootCertificates.keychain > "$T/aaa.pem"
echo "AAA Certificate Services in the Mac's system roots: $(grep -c BEGIN "$T/aaa.pem") certificate(s)"
openssl x509 -in "$T/aaa.pem" -noout -subject -fingerprint -sha256
echo "--- Sectigo's cross-sign (handed to the program), signed by that root?"
openssl x509 -in certs/EM-DV-TLS-CA-G3B-AAA.pem -noout -subject -issuer
openssl verify -partial_chain -no_check_time -CAfile "$T/aaa.pem" certs/EM-DV-TLS-CA-G3B-AAA.pem 2>&1 || true
echo "--- the made-up leaf, signed by the cross-sign's key? (it must not be: the signature is made up)"
openssl x509 -in certs/api.example.com.pem -noout -subject -issuer -ext subjectAltName
openssl verify -partial_chain -no_check_time -CAfile certs/EM-DV-TLS-CA-G3B-AAA.pem certs/api.example.com.pem 2>&1 || true
echo "--- the leaf names the intermediate as its issuer (by name and key ID)?"
leaf_aki=$(openssl x509 -in certs/api.example.com.pem -noout -ext authorityKeyIdentifier | tail -1 | tr -d ' ')
int_ski=$(openssl x509 -in certs/EM-DV-TLS-CA-G3B-AAA.pem -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' ')
echo "leaf AKI $leaf_aki, intermediate SKI $int_ski: $([ "$leaf_aki" = "$int_ski" ] && echo same || echo DIFFERENT)"
echo "--- both copies of EM DV TLS CA - G3B carry one key"
for c in certs/EM-DV-TLS-CA-G3B.pem certs/EM-DV-TLS-CA-G3B-AAA.pem; do
  printf '%s: ' "$c"; openssl x509 -in "$c" -noout -pubkey | openssl pkey -pubin -outform der | shasum -a 256 | cut -d' ' -f1
done

say "4. What InvalidSignatureForPublicKey means in rustls-webpki 0.103.15"
src=$(ls -d "$CARGO_HOME"/registry/src/*/rustls-webpki-0.103.15)
echo "source: \$CARGO_HOME/registry/src/…/rustls-webpki-0.103.15/src/verify_cert.rs"
grep -n "fn build_chain_inner\|check_signed_chain\|for trust_anchor in\|loop_while_non_fatal_error(Error::UnknownIssuer" "$src/src/verify_cert.rs" | head -12

say "5. Update the one library, clean rebuild, run again"
cargo update -q -p rustls-webpki
grep -A1 'name = "rustls-webpki"' Cargo.lock
rm -rf "$CARGO_TARGET_DIR/debug/check" "$CARGO_TARGET_DIR/debug/.fingerprint/check-"* "$CARGO_TARGET_DIR/debug/build/check-"*
CARGO_TERM_QUIET=false cargo build 2>&1 | sed "s#$R#\$R#g"
echo "./check -> $(readlink check | sed "s|$R|\$R|")"
echo '$ ./check'; ./check || echo "(exit $?)"
src16=$(ls -d "$CARGO_HOME"/registry/src/*/rustls-webpki-0.103.16)
echo "--- 0.103.16's distrust list has EM DV TLS CA - G3B's key?"
grep -n "CertDistrusted" "$src16/src/verify_cert.rs" | head -3
# DISTRUSTED_SPKIS holds each key's SPKI SEQUENCE contents (no tag/length),
# in src/data/distrusted/*.spki.der. Compare with the cross-sign's own key.
openssl x509 -in certs/EM-DV-TLS-CA-G3B-AAA.pem -noout -pubkey | openssl pkey -pubin -outform der > "$T/spki.der"
python3 - "$T/spki.der" "$src16/src/data/distrusted" <<'PY'
import pathlib, sys
der = pathlib.Path(sys.argv[1]).read_bytes()
n = der[1] & 0x7f if der[1] & 0x80 else 0          # strip the outer SEQUENCE header
body = der[2 + n:]
hits = [p.name for p in sorted(pathlib.Path(sys.argv[2]).glob("*.spki.der")) if p.read_bytes() == body]
print("files in the list:", len(list(pathlib.Path(sys.argv[2]).glob("*.spki.der"))),
      "| matching the handed cross-sign's key:", ", ".join(hits) or "NONE")
PY
echo "--- where 0.103.16 checks it (before any signature is checked):"
grep -n "distrusted_spkis" "$src16/src/verify_cert.rs" | head -3

say "6. Back to the start (0.103.15), as setup.sh leaves it"
cp "$REPO_DIR/rust/Cargo-0.103.15.lock" Cargo.lock
cargo build -q --locked && ./check > "$T/out" || true; head -1 "$T/out"
