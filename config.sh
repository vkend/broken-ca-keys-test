# Shared settings for the scripts here. Source it; don't run it.
#
# Everything is built outside this repo, under $R. Use /private/tmp, not /tmp:
# /tmp is a symlink, and the tools print paths under $R (cargo without -q,
# `cargo tree`, panics), which then show no username.
R="${BROKEN_CA_KEYS_ROOT:-/private/tmp/broken-ca-keys}"
# The directory this file is in, whether sourced from bash or zsh.
if [ -n "${BASH_VERSION:-}" ]; then _here=${BASH_SOURCE[0]}; else eval '_here=${(%):-%x}'; fi
REPO_DIR="$(cd "$(dirname "$_here")" && pwd)"

# A throwaway HOME, rebuilt by every setup.sh. The test programs run in
# ~/app, meaning $U/app.
U="$R/u"

# Toolchains, Go and cargo caches, the cargo target dir and the downloads:
# kept across setup.sh runs (so a rebuild is offline and quick), and removed
# with the rest of $R by teardown.sh. Never ~/go or ~/.cargo.
C="$R/cache"

# No ports: nothing here runs a server, a proxy or a daemon. The TLS
# handshakes run in memory.

# Go: the base toolchain is go1.27.3 from go.dev (checksum below, from
# go.dev/dl/?mode=json). go1.27.2 comes through GOTOOLCHAIN, into GOMODCACHE.
GO_BASE_VERSION=go1.27.3
GO_BASE_SHA256_darwin_arm64=dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2
GO_OLD=go1.27.2   # before the fix
GO_NEW=go1.27.3   # the eight keys compiled in (CVE-2026-111943)

# Rust: the two lockfiles in rust/ differ only in rustls-webpki.
WEBPKI_OLD=0.103.15
WEBPKI_NEW=0.103.16   # CertDistrusted (RUSTSEC-2026-0382)

# The dated July root list (certifi 2026.7.22; bundles/), which Go reads
# through SSL_CERT_FILE and the Python check reads directly.
BUNDLE=certifi-2026.7.22.pem

# The fixed root list (certifi 2026.10.19, from its PyPI wheel, SHA-256
# 42d35340…8670e1b; bundles/), for the Python check beside the July one.
BUNDLE_NEW=certifi-2026.10.19.pem

# Node: the release before the fix and the 21 October one (nodejs/node
# #66871), darwin-arm64 from nodejs.org, checked against its
# SHASUMS256.txt. Only the node binary is unpacked, into $C.
NODE_OLD=v26.12.0
NODE_OLD_SHA256_darwin_arm64=2a154d4a5458930e0a2d6a1ecf64eddf5a2b3e1c13636b609c2ecb042e8c4553
NODE_NEW=v26.12.1
NODE_NEW_SHA256_darwin_arm64=1901d539912c02afa10d1cc126943a8855a7eedebe830119463470db5e6c59e8
