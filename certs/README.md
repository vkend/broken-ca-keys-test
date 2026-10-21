# The public certificates

Checked against `SHA256SUMS` (of these PEM files) by `setup.sh` and `check.sh`.

| File | Subject ← issuer | SHA-256 of the certificate (DER) | Source |
|---|---|---|---|
| `EM-DV-TLS-CA-G3B.pem` | EM DV TLS CA - G3B ← emSign Root TLS CA - G3 | `42C4ACCD…18BA1493` | Mozilla bug 2083449, attachment 9664066 (`emudhra-attestation.zip`, SHA-256 `3175038d7538f0b6c45b2efb1064a9c42b004554ff0027b5811e7df76997215a`), `EM-DV-TLS-CA-G3B.crt.pem`, byte for byte |
| `EM-DV-TLS-CA-G3B-AAA.pem` | EM DV TLS CA - G3B ← AAA Certificate Services (Sectigo's cross-sign) | `45A883F3…66FCDDBE` | attachment 9664067 (`emudhra-attestation-aaa-cross.zip`, SHA-256 `892e5d472746a2ab5955692dd91e08cceb3834584cbf8139eb1943ee27bf1575`), `EM-DV-TLS-CA-G3B-AAA.crt.pem`, byte for byte |
| `emSign-Root-TLS-CA-G3-by-ECC-G3.pem` | emSign Root TLS CA - G3 ← emSign ECC Root CA - G3 | `3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD` | the CCADB's public PEM export (`AllCertificatePEMsCSVFormat?NotBeforeYear=2024`); Go's July-root-list test needs it |

Both EM DV TLS CA - G3B certificates carry the same P-384 public key; the
SHA-256 of its SubjectPublicKeyInfo is
`ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105`.

The made-up leaf for api.example.com isn't here: `setup.sh` makes it with
`go/mkleaf`, signed with a throwaway key.
