#!/bin/bash
# Run every test exactly as you'd type it, in ~/app, in a fresh shell
# (shell.sh: bash --noprofile --norc, the throwaway HOME, Homebrew's PATH, no
# Go on it), and check every result line. Then checks no output shows a
# username, hostname or home path, and puts ~/app back on rustls-webpki
# 0.103.15.
#
# Run after setup.sh. Exits non-zero if any check fails; SHOW=1 also prints
# every command and its output. It reads the Mac's system roots with
# `security find-certificate` (read only; nothing about trust is changed).
set -uo pipefail
source "$(dirname "$0")/env.sh"

APP="$U/app"
OUT="$R/check-out"; rm -rf "$OUT"; mkdir -p "$OUT"
passes=0 fails=0 n=0
check() {  # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf '  ok    %-58s %s\n' "$1" "$3"; passes=$((passes + 1))
    else printf '  FAIL  %-58s expected [%s], got [%s]\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi
}
has() {  # has <label> <exact line> <output file>: the line appears, whole
    check "$1" yes "$(grep -qxF -- "$2" "$3" && echo yes || echo no)"
}
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
# run_as_typed <command>: run it as typed, in a fresh `bash --noprofile
# --norc` that sources shell.sh (so it starts in ~/app with the throwaway
# HOME); output (stdout and stderr) to $OUT/<n>.txt, whose path is in $LAST;
# seconds in $SECS.
run_as_typed() {
    n=$((n + 1)); local f="$OUT/$n.txt" t0
    printf '$ %s\n' "$1" > "$OUT/$n.cmd"
    t0=$(now)
    env -i BROKEN_CA_KEYS_ROOT="$R" TERM=xterm-256color \
        /bin/bash --noprofile --norc -c "source '$REPO_DIR/shell.sh' && $1" > "$f" 2>&1
    SECS=$(perl -e "printf '%.1f', $(now) - $t0")
    LAST="$f"
}
lines() { grep -c '' "$1"; }
webpki_in_lock() { grep -A1 'name = "rustls-webpki"' "$APP/Cargo.lock" | sed -n 's/^version = "\(.*\)"/\1/p'; }
LOCKCMD="grep -A1 'name = \"rustls-webpki\"' Cargo.lock"
SSL="SSL_CERT_FILE=$BUNDLE"

echo "setup: what the tests depend on"
check "certificates match certs/SHA256SUMS" yes \
    "$(cd "$REPO_DIR/certs" && shasum -a 256 -c --quiet SHA256SUMS >/dev/null 2>&1 && echo yes || echo no)"
check "the root lists match bundles/SHA256SUMS" yes \
    "$(cd "$REPO_DIR/bundles" && shasum -a 256 -c --quiet SHA256SUMS >/dev/null 2>&1 && echo yes || echo no)"
leaf_issuer=$(openssl x509 -in "$APP/certs/api.example.com.pem" -noout -issuer -nameopt RFC2253)
real_subject=$(openssl x509 -in "$APP/certs/EM-DV-TLS-CA-G3B.pem" -noout -subject -nameopt RFC2253)
check "made-up leaf: issuer is the real intermediate's name" "${real_subject#subject=}" "${leaf_issuer#issuer=}"
check "made-up leaf: names api.example.com" "DNS:api.example.com" \
    "$(openssl x509 -in "$APP/certs/api.example.com.pem" -noout -ext subjectAltName | tail -1 | tr -d ' ')"
sysroots=/System/Library/Keychains/SystemRootCertificates.keychain
for root in "AAA Certificate Services" "emSign ECC Root CA - G3"; do
    check "this Mac's system roots include $root" yes \
        "$(security find-certificate -c "$root" "$sysroots" >/dev/null 2>&1 && echo yes || echo no)"
done
check "gocheck-1.27.2 built with" "go1.27.2" "$(go version "$APP/gocheck-1.27.2" | awk '{print $2}')"
check "gocheck-1.27.3 built with" "go1.27.3" "$(go version "$APP/gocheck-1.27.3" | awk '{print $2}')"
check "~/app starts on rustls-webpki" "$WEBPKI_OLD" "$(webpki_in_lock)"

echo "1. this Mac blocks the key; a Rust program using the Mac's roots accepts the chain"
run_as_typed "./gocheck-1.27.2"
has "./gocheck-1.27.2: macOS: revoked" "macOS: revoked" "$LAST"
run_as_typed "./check"
has "./check: trusted root: found, signature: made up" "trusted root: found, signature: made up" "$LAST"

echo "2. Rust: rustls-webpki 0.103.15, the control, then the update to 0.103.16"
run_as_typed "$LOCKCMD"
has "Cargo.lock: version = \"$WEBPKI_OLD\"" "version = \"$WEBPKI_OLD\"" "$LAST"
run_as_typed "./check"
c=$LAST
has "./check: on $WEBPKI_OLD, the Mac's own roots" \
    "rustls-webpki $WEBPKI_OLD, checking against this Mac's trusted roots ($(sed -n 's/.*roots (\([0-9]*\))$/\1/p' "$c" | head -1))" "$c"
check "./check: handed exactly two certificates" 2 "$(sed -n '/^handed:$/,/^[^ ]/p' "$c" | grep -c '^  ')"
has "./check: handed the made-up leaf" "  api.example.com      issued by EM DV TLS CA - G3B" "$c"
has "./check: handed the AAA cross-sign" "  EM DV TLS CA - G3B   issued by AAA Certificate Services" "$c"
has "./check: label" "trusted root: found, signature: made up" "$c"
has "./check: error" "error: InvalidSignatureForPublicKey" "$c"
check "./check: the label is above the error" "trusted root: found, signature: made up|error: InvalidSignatureForPublicKey" \
    "$(tail -2 "$c" | paste -sd '|' -)"
run_as_typed "./check --control"
c=$LAST
check "--control: handed the made-up leaf only" 1 "$(sed -n '/^handed:$/,/^[^ ]/p' "$c" | grep -c '^  ')"
has "--control: label" "no trusted root" "$c"
has "--control: error" "error: UnknownIssuer" "$c"
run_as_typed "cargo update -q -p rustls-webpki"
check "cargo update -q: prints nothing" 0 "$(lines "$LAST")"
check "cargo update: Cargo.lock now on" "$WEBPKI_NEW" "$(webpki_in_lock)"
check "cargo update: Cargo.lock is rust/Cargo-$WEBPKI_NEW.lock" yes \
    "$(cmp -s "$APP/Cargo.lock" "$REPO_DIR/rust/Cargo-$WEBPKI_NEW.lock" && echo yes || echo no)"
check "cargo update: under 3 s (offline)" yes "$(perl -e "print $SECS < 3 ? 'yes' : 'no'")"
echo "        (cargo update took ${SECS}s)"
run_as_typed "cargo build -q"
check "cargo build -q: prints nothing" 0 "$(lines "$LAST")"
check "cargo build -q: under 5 s" yes "$(perl -e "print $SECS < 5 ? 'yes' : 'no'")"
echo "        (cargo build took ${SECS}s)"
run_as_typed "$LOCKCMD"
has "Cargo.lock: version = \"$WEBPKI_NEW\"" "version = \"$WEBPKI_NEW\"" "$LAST"
run_as_typed "./check"
c=$LAST
check "./check again: on $WEBPKI_NEW" yes "$(head -1 "$c" | grep -q "^rustls-webpki $WEBPKI_NEW, " && echo yes || echo no)"
has "./check again: still handed the AAA cross-sign" "  EM DV TLS CA - G3B   issued by AAA Certificate Services" "$c"
has "./check again: label" "distrusted key" "$c"
has "./check again: error" "error: CertDistrusted" "$c"

echo "3. the cross-sign: one key, two issuers"
run_as_typed "./side-by-side"
c=$LAST
has "side-by-side: both subjects" "subject       EM DV TLS CA - G3B             EM DV TLS CA - G3B" "$c"
has "side-by-side: issuers emSign Root TLS CA - G3 | AAA" "issuer        emSign Root TLS CA - G3        AAA Certificate Services" "$c"
has "side-by-side: the same key hash" "same key: ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105" "$c"

echo "4. Go: macOS by default, then the July root list through SSL_CERT_FILE"
for v in 1.27.2 1.27.3; do
    run_as_typed "./gocheck-$v"
    has "./gocheck-$v: built with go$v" "built with go$v" "$LAST"
    has "./gocheck-$v: macOS: revoked" "macOS: revoked" "$LAST"
    has "./gocheck-$v: error" "error: x509: “EM DV TLS CA - G3B” certificate is revoked" "$LAST"
done
run_as_typed "$SSL ./gocheck-1.27.2"
c=$LAST
has "1.27.2 + $BUNDLE: names the root list" "roots: $BUNDLE (SSL_CERT_FILE: Go checks the chain itself)" "$c"
has "1.27.2 + $BUNDLE: trusted" "Go's own check: trusted" "$c"
has "1.27.2 + $BUNDLE: the chain" "chain: EM DV TLS CA - G3B <- emSign Root TLS CA - G3 <- emSign ECC Root CA - G3" "$c"
run_as_typed "$SSL ./gocheck-1.27.3"
c=$LAST
has "1.27.3 + $BUNDLE: rejected" "Go's own check: rejected" "$c"
has "1.27.3 + $BUNDLE: error" "error: x509: no valid chains built" "$c"

echo "5. Python: certifi July vs October (Python's own TLS check, in memory)"
run_as_typed "python3 pycheck.py $BUNDLE"
c=$LAST
has "pycheck $BUNDLE: trusted root found" "trusted root: found, signature: made up" "$c"
has "pycheck $BUNDLE: OpenSSL's error" "error: certificate signature failure" "$c"
run_as_typed "python3 pycheck.py $BUNDLE_NEW"
c=$LAST
has "pycheck $BUNDLE_NEW: no trusted root" "no trusted root" "$c"
has "pycheck $BUNDLE_NEW: OpenSSL's error" "error: unable to get local issuer certificate" "$c"

echo "6. Node: $NODE_OLD vs $NODE_NEW (compiled-in roots, in memory)"
run_as_typed "./node-${NODE_OLD#v} nodecheck.mjs"
c=$LAST
has "node $NODE_OLD: version" "node $NODE_OLD" "$c"
has "node $NODE_OLD: trusted root found" "trusted root: found, signature: made up" "$c"
has "node $NODE_OLD: Node's error" "error: CERT_SIGNATURE_FAILURE" "$c"
run_as_typed "./node-${NODE_NEW#v} nodecheck.mjs"
c=$LAST
has "node $NODE_NEW: version" "node $NODE_NEW" "$c"
has "node $NODE_NEW: distrusted key" "distrusted key" "$c"
has "node $NODE_NEW: Node's error" "error: CERT_REVOKED" "$c"

echo "privacy: no username, hostname or home path in any output"
user=$(id -un); host=$(hostname -s); fqdn=$(hostname)
leaks=$(cat "$OUT"/*.txt | grep -iF -e "$user" -e "$host" -e "$fqdn" -e "/Users/" -e "$R" | head -3)
check "all $n commands' output" "" "$leaks"

echo "reset: ~/app back on rustls-webpki $WEBPKI_OLD"
cp "$REPO_DIR/rust/Cargo-$WEBPKI_OLD.lock" "$APP/Cargo.lock"
(cd "$APP" && cargo build -q --locked)
run_as_typed "./check"
check "./check is on $WEBPKI_OLD again" yes "$(head -1 "$LAST" | grep -q "^rustls-webpki $WEBPKI_OLD, " && echo yes || echo no)"

if [ -n "${SHOW:-}" ]; then  # SHOW=1 ./check.sh: print every command and its output
    echo; for i in $(seq "$n"); do cat "$OUT/$i.cmd" "$OUT/$i.txt"; done
fi
echo
echo "$passes passed, $fails failed"
[ "$fails" -eq 0 ] || exit 1
