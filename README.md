# Broken CA keys: did your code block them?

On 17 October 2026 a researcher reported eight eMudhra intermediate CA keys
so weak that anyone can work them out: each private key is a number below
256 ([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449),
comment 5). Chrome and Firefox blocked them within hours, with no update to
install. Code that checks certificates itself gets none of that: its root
list and its block list are whatever it was built or installed with.

This repo tests, with real code on a Mac, whether such code accepted one of
those keys (EM DV TLS CA - G3B) before each fix and refuses it after:

- **Rust**: rustls-webpki with the Mac's own roots (`rustls-native-certs`),
  0.103.15 and then 0.103.16. The Mac's store still trusts Sectigo's AAA
  Certificate Services, which cross-signed all eight keys, so removing
  eMudhra's root doesn't help a program that borrows the root list but not
  Apple's block.
- **Go**: on the Mac (Go hands the check to macOS, which blocks the key), and
  with a July root list through `SSL_CERT_FILE` (Go checks the chain
  itself, as on Linux), built with Go 1.27.2 and then 1.27.3.
- **Python**: the ssl module with certifi's root list, 2026.7.22 and then
  2026.10.19.
- **Node**: its compiled-in root list, v26.12.0 and then v26.12.1.

Results as of 21 October 2026.

Video: (link when published)

## Results

From `SHOW=1 ./check.sh` (every line below is checked by `check.sh`):

| Test | Command (in `~/app`) | Before the fix | After the fix |
|---|---|---|---|
| macOS's own check | `./gocheck-1.27.2` | `macOS: revoked` | |
| Rust, the Mac's roots | `./check` (Sectigo's copy of the intermediate handed over) | rustls-webpki 0.103.15: `trusted root: found, signature: made up` / `error: InvalidSignatureForPublicKey` | `cargo update -p rustls-webpki` (0.103.16) and rebuild: `distrusted key` / `error: CertDistrusted` |
| Rust, the control | `./check --control` (the intermediate taken away) | `no trusted root` / `error: UnknownIssuer` | |
| One key, two issuers | `./side-by-side` | issuers `emSign Root TLS CA - G3` and `AAA Certificate Services`; `same key: ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105` | |
| Go on the Mac | `./gocheck-1.27.2`, `./gocheck-1.27.3` | both: `macOS: revoked` / `error: x509: “EM DV TLS CA - G3B” certificate is revoked` | |
| Go, July root list | `SSL_CERT_FILE=certifi-2026.7.22.pem ./gocheck-1.27.2` / `…1.27.3` | 1.27.2: `Go's own check: trusted` (`chain: EM DV TLS CA - G3B <- emSign Root TLS CA - G3 <- emSign ECC Root CA - G3`) | 1.27.3: `Go's own check: rejected` / `error: x509: no valid chains built` |
| Python, certifi | `python3 pycheck.py certifi-2026.7.22.pem` / `certifi-2026.10.19.pem` | 2026.7.22 (121 roots): `trusted root: found, signature: made up` / `error: certificate signature failure` | 2026.10.19 (120 roots): `no trusted root` / `error: unable to get local issuer certificate` |
| Node | `./node-26.12.0 nodecheck.mjs` / `./node-26.12.1 nodecheck.mjs` | v26.12.0: `trusted root: found, signature: made up` / `error: CERT_SIGNATURE_FAILURE` | v26.12.1: `distrusted key` / `error: CERT_REVOKED` |

How to read them: the server side of every test presents a **made-up leaf**
for api.example.com whose signature can't verify (it's signed with a
throwaway key, not the broken one). So the best a client can do is fail on
that signature, which it only reaches after it has **found a trusted root**
for the chain. "trusted root: found, signature: made up" means the client
would have accepted a real certificate signed with the broken key.

## Run it

Needs an arm64 Mac, Homebrew's `cargo` and `python3`, `curl`, `openssl` and
`perl` (macOS has the last three). The first `setup.sh` downloads Go 1.27.3
from go.dev, Go 1.27.2 through `GOTOOLCHAIN`, Node v26.12.0 and v26.12.1
from nodejs.org, and the crates in the two Cargo lockfiles; each download is
checked against its publisher's checksum. Everything goes under
`/private/tmp/broken-ca-keys` (set `BROKEN_CA_KEYS_ROOT` for another place
under `/private/tmp`); nothing lands in `~/go`, `~/.cargo` or your home folder.

```sh
./setup.sh          # build everything (later runs are offline and quick)
./check.sh          # run every test and check every result; SHOW=1 prints them
./teardown.sh       # remove /private/tmp/broken-ca-keys, caches included
```

To type the commands yourself:

```sh
bash --noprofile --norc
source shell.sh     # the throwaway HOME, Homebrew's PATH, and cd ~/app
./check
```

`check.sh` leaves `~/app` on rustls-webpki 0.103.15; `setup.sh` does too.

More, beyond `check.sh` (they need `setup.sh` first; `confirm-facts.sh` needs
the network and downloads only public artifacts, each checksummed):

```sh
./confirm-rust.sh   # the Rust test from a clean build, checked with openssl and against rustls-webpki's source
./confirm-facts.sh  # macOS, Go 1.26/1.27, certifi, webpki-roots, Node 24/26, Windows' trust lists, Debian, OneCRL, CRLSet
```

## Safety

- Only public certificates (see `certs/README.md`). The made-up leaves are
  signed with a throwaway key generated in memory (`go/mkleaf`). No eMudhra
  private key is used, computed or downloaded.
- Nothing touches the Keychain or trust settings: the programs only read the
  system roots, and `security verify-cert` (in `confirm-facts.sh`) evaluates
  trust without changing it.
- No ports, no servers, no daemons: the TLS handshakes run in memory.
- `check.sh` also checks that no output shows your username, hostname or a
  home path.

## What's here

| Path | What |
|---|---|
| `rust/` | `check`: rustls-webpki with `rustls-native-certs` (the Mac's roots). `build.rs` bakes the rustls-webpki version from Cargo.lock into the binary; the two lockfiles differ only in rustls-webpki |
| `go/gocheck` | verifies the real EM DV TLS CA - G3B with Go's crypto/x509 (macOS's verifier by default; Go's own with `SSL_CERT_FILE`) |
| `go/sidebyside` | prints eMudhra's own copy and Sectigo's cross-sign of EM DV TLS CA - G3B, and their key hash |
| `go/mkleaf` | makes the made-up leaf (and, for the handshakes, its own throwaway key) |
| `go/gofacts` | Go's own verifier with explicit roots, for any Go version (`confirm-facts.sh`) |
| `python/pycheck.py`, `node/nodecheck.mjs` | the Python and Node checks above; `handshake.py` and `handshake.mjs` are the raw versions `confirm-facts.sh` uses |
| `rust-roots/` | rustls-webpki with the webpki-roots list (`confirm-facts.sh`) |
| `certs/` | the public certificates, checked against `SHA256SUMS` |
| `bundles/` | certifi's root lists, July and October 2026, checked against `SHA256SUMS` |

## Sources

- Mozilla bug 2083449 (the report, the researcher's proof, eMudhra's account): https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
- Mozilla's post: https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/
- Chrome Root Program, on the block and Certificate Transparency: https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE
- Rust: RUSTSEC-2026-0382, https://rustsec.org/advisories/RUSTSEC-2026-0382.html
- Go: CVE-2026-111943 (GO-2026-6809), Go 1.27.3 and 1.26.10: https://go.dev/doc/devel/release
- Python certifi: GHSA-6q48-6c7w-9gw2 (patched in 2026.10.19)
- Node.js: nodejs/node #66871, in v26.12.1, v24.22.1 and v22.23.4: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
- Debian DSA-6572-1 and DLA-4845-1, Ubuntu USN-8944-1 and USN-8944-2 (ca-certificates without emSign ECC Root CA - G3 and AAA Certificate Services, 20 October 2026)

## License

The code is MIT (`LICENSE`). The certificates are public certificates
(`certs/README.md`); the root lists are certifi's, from Mozilla's CA list,
under MPL-2.0 (`bundles/README.md`).
