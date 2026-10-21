#!/bin/bash
# Build everything the tests need, under $R (config.sh). Idempotent and
# quick after the first run: it rebuilds the throwaway HOME ($U, with ~/app
# on rustls-webpki 0.103.15, the state before the fix) and keeps the
# toolchains and caches in $C. The first run downloads (Go from go.dev and
# Node from nodejs.org, both checksummed; go1.27.2 through GOTOOLCHAIN; the
# crates in the two lockfiles); later runs are offline.
#
# What it builds, all under $R:
#   ~/app/check            Rust, rustls-webpki from Cargo.lock, the Mac's own roots
#   ~/app/gocheck-1.27.2   Go, the real intermediate, built with go1.27.2
#   ~/app/gocheck-1.27.3   the same source, built with go1.27.3
#   ~/app/side-by-side     the intermediate and its Sectigo cross-sign
#   ~/app/certs/           the public certificates (certs/, checksummed)
#                          and the made-up leaf for api.example.com
#   ~/app/certifi-2026.7.22.pem   the dated July root list (bundles/)
#   ~/app/certifi-2026.10.19.pem  the fixed root list (bundles/)
#   ~/app/pycheck.py       Python's own TLS check against one root list, in memory
#   ~/app/node-26.12.0, node-26.12.1, nodecheck.mjs   Node's own check, its compiled-in roots, in memory
#   ~/app/server/          the other side of those handshakes: a made-up leaf with its
#                          throwaway key, and the real public intermediates
#
# Safety: only public certificates; the made-up leaves are signed with a
# throwaway key that is generated and dropped in memory (go/mkleaf). No
# eMudhra private key is used, computed or downloaded. Nothing touches the
# Keychain or trust settings: the Rust client only reads the system roots.
# No ports, no daemons.
set -euo pipefail
source "$(dirname "$0")/env.sh"
case "$R" in /private/tmp/?*) ;; *) echo "refusing: $R is not under /private/tmp" >&2; exit 1 ;; esac

step() { echo "• $*"; }

step "public certificates and the root lists: checksums"
(cd "$REPO_DIR/certs" && shasum -a 256 -c --quiet SHA256SUMS)
(cd "$REPO_DIR/bundles" && shasum -a 256 -c --quiet SHA256SUMS)

mkdir -p "$C"/{dl,bin,gopath,gocache,gomodcache,gotmp,cargo,target}

# --- Go ------------------------------------------------------------------
if [ ! -x "$GOROOT_BASE/bin/go" ]; then
    step "Go: downloading $GO_BASE_VERSION (darwin-arm64) from go.dev"
    [ "$(uname -sm)" = "Darwin arm64" ] || { echo "these tests are set up for an arm64 Mac" >&2; exit 1; }
    tgz="$C/dl/$GO_BASE_VERSION.darwin-arm64.tar.gz"
    [ -f "$tgz" ] || curl -fsSL -o "$tgz" "https://go.dev/dl/$GO_BASE_VERSION.darwin-arm64.tar.gz"
    echo "$GO_BASE_SHA256_darwin_arm64  $tgz" | shasum -a 256 -c --quiet
    rm -rf "$GOROOT_BASE" "$C/go.tmp" && mkdir -p "$C/go.tmp"
    tar -xzf "$tgz" -C "$C/go.tmp" && mv "$C/go.tmp/go" "$GOROOT_BASE" && rmdir "$C/go.tmp"
fi
[ "$(go env GOVERSION)" = "$GO_BASE_VERSION" ] || { echo "base Go is not $GO_BASE_VERSION" >&2; exit 1; }

# GOTOOLCHAIN=<version> runs that exact release (go1.27.2 is fetched once as
# the golang.org/toolchain module, checked against the checksum database,
# into GOMODCACHE). Once it's cached, GOPROXY=off keeps the rebuild offline.
gobuild() {  # gobuild <toolchain> <out> <package>
    local proxy=${GOPROXY:-https://proxy.golang.org,direct}
    if [ "$1" = "$GO_BASE_VERSION" ] || ls -d "$GOMODCACHE"/golang.org/toolchain@*"$1".* >/dev/null 2>&1; then
        proxy=off
    fi
    (cd "$REPO_DIR/go" && GOTOOLCHAIN="$1" GOPROXY="$proxy" go build -trimpath -o "$2" "$3")
}
step "Go: gocheck with $GO_OLD and $GO_NEW, side-by-side, mkleaf (-trimpath)"
gobuild "$GO_OLD" "$C/bin/gocheck-${GO_OLD#go}" ./gocheck
gobuild "$GO_NEW" "$C/bin/gocheck-${GO_NEW#go}" ./gocheck
gobuild "$GO_NEW" "$C/bin/side-by-side" ./sidebyside
gobuild "$GO_NEW" "$C/bin/mkleaf" ./mkleaf
for v in "$GO_OLD" "$GO_NEW"; do
    got=$(go version "$C/bin/gocheck-${v#go}" | awk '{print $2}')
    [ "$got" = "$v" ] || { echo "gocheck-${v#go} was built with $got, not $v" >&2; exit 1; }
done

# --- the throwaway HOME ----------------------------------------------------
step "the throwaway HOME: $U (~/app)"
chmod -R u+w "$U" 2>/dev/null || true
rm -rf "$U"
mkdir -p "$U/app/certs"
cp "$REPO_DIR"/certs/*.pem "$U/app/certs/"
cp "$REPO_DIR/bundles/$BUNDLE" "$REPO_DIR/bundles/$BUNDLE_NEW" "$U/app/"
cp "$REPO_DIR/python/pycheck.py" "$REPO_DIR/node/nodecheck.mjs" "$U/app/"
cp "$REPO_DIR/rust/Cargo.toml" "$REPO_DIR/rust/build.rs" "$U/app/"
cp -R "$REPO_DIR/rust/src" "$U/app/"

step "the made-up leaf for api.example.com (throwaway key, never saved)"
(cd "$U/app" && "$C/bin/mkleaf" certs/EM-DV-TLS-CA-G3B.pem > certs/api.example.com.pem)

step "the in-memory handshakes' other side: a second made-up leaf, its throwaway key, the public intermediates"
mkdir -p "$U/app/server"
(cd "$U/app" && "$C/bin/mkleaf" certs/EM-DV-TLS-CA-G3B.pem server/leaf.key > server/leaf.pem \
    && cat server/leaf.pem certs/EM-DV-TLS-CA-G3B.pem certs/emSign-Root-TLS-CA-G3-by-ECC-G3.pem > server/chain.pem)

# --- Node ------------------------------------------------------------------
nodeget() {  # nodeget <version> <sha256>
    local tgz="$C/dl/node-$1-darwin-arm64.tar.gz"
    if [ ! -x "$C/node-$1/node" ]; then
        step "Node: downloading $1 (darwin-arm64) from nodejs.org"
        [ -f "$tgz" ] || curl -fsSL -o "$tgz" "https://nodejs.org/dist/$1/node-$1-darwin-arm64.tar.gz"
        echo "$2  $tgz" | shasum -a 256 -c --quiet
        mkdir -p "$C/node-$1"
        tar -xzf "$tgz" -C "$C/node-$1" --strip-components 2 "node-$1-darwin-arm64/bin/node"
    fi
    [ "$("$C/node-$1/node" --version)" = "$1" ] || { echo "node-$1 is not $1" >&2; exit 1; }
    ln -sf "$C/node-$1/node" "$U/app/node-${1#v}"
}
nodeget "$NODE_OLD" "$NODE_OLD_SHA256_darwin_arm64"
nodeget "$NODE_NEW" "$NODE_NEW_SHA256_darwin_arm64"

for b in gocheck-${GO_OLD#go} gocheck-${GO_NEW#go} side-by-side; do
    cp "$C/bin/$b" "$U/app/$b"
done

# --- Rust ------------------------------------------------------------------
# Both versions compiled into the one target dir, so `cargo update -p
# rustls-webpki` and `cargo build -q` in ~/app take about a second each,
# offline. It ends on 0.103.15, the state before the fix.
rustbuild() {  # rustbuild <webpki version>
    cp "$REPO_DIR/rust/Cargo-$1.lock" "$U/app/Cargo.lock"
    if ! (cd "$U/app" && cargo fetch -q --locked 2>/dev/null); then
        step "Rust: downloading the crates in Cargo-$1.lock (first run)"
        (cd "$U/app" && CARGO_NET_OFFLINE=false cargo fetch -q --locked)
    fi
    (cd "$U/app" && cargo build -q --locked)
}
step "Rust: check with rustls-webpki $WEBPKI_NEW, then $WEBPKI_OLD"
rustbuild "$WEBPKI_NEW"
rustbuild "$WEBPKI_OLD"
# ./check is the binary cargo just built; `cargo build -q` in ~/app
# rebuilds it in place.
ln -sf "$CARGO_TARGET_DIR/debug/check" "$U/app/check"
grep -q "^version = \"$WEBPKI_OLD\"" <(grep -A1 'name = "rustls-webpki"' "$U/app/Cargo.lock") \
    || { echo "~/app/Cargo.lock is not on $WEBPKI_OLD" >&2; exit 1; }

echo "ready: $R (bash --noprofile --norc; source shell.sh: you are in ~/app, HOME=$U)"
