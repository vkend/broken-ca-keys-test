# Source this in any shell that runs the tests. It changes HOME, so do it in
# a shell meant for the tests, not your own.
if [ -n "${BASH_VERSION:-}" ]; then _here=${BASH_SOURCE[0]}; else eval '_here=${(%):-%x}'; fi
source "$(dirname "$_here")/config.sh"

# A throwaway HOME: nothing the tools write (Go's telemetry settings, cargo's
# cache) lands in the real home folder, and ~ hides the account's username.
export HOME="$U"
unset XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME

# Go: everything under the cache, nothing in ~/go. GOTOOLCHAIN=local so no
# command downloads a toolchain by surprise; setup.sh names the version it
# builds with. GOENV=off: no go env file read from anywhere.
export GOROOT_BASE="$C/go"
export GOPATH="$C/gopath" GOCACHE="$C/gocache" GOMODCACHE="$C/gomodcache" GOTMPDIR="$C/gotmp"
export GOTOOLCHAIN=local GOENV=off GOFLAGS=-trimpath
unset GOROOT

# Rust: Homebrew's cargo, with its home and target dir under $R. Offline and
# quiet by default: `cargo update -p rustls-webpki` picks 0.103.16 from the
# crates setup.sh downloaded (no network, so no surprise newer version), and
# cargo prints no paths.
export CARGO_HOME="$C/cargo" CARGO_TARGET_DIR="$C/target"
export CARGO_NET_OFFLINE=true CARGO_TERM_QUIET=true CARGO_TERM_COLOR=never
unset RUSTC_WRAPPER

# The base Go toolchain first (for setup.sh and check.sh; shell.sh, the shell
# the tests run in, sets its own PATH and needs only cargo, python3 and the
# binaries in ~/app).
export PATH="$GOROOT_BASE/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
