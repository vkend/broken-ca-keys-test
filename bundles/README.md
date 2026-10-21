# Root lists

certifi's `cacert.pem` (Mozilla's CA list, as packaged by certifi; MPL-2.0),
each taken unchanged from its PyPI wheel. Checked against `SHA256SUMS` by
`setup.sh` and `check.sh`.

| File | certifi release | Wheel SHA-256 (as PyPI lists it) | Roots | emSign ECC Root CA - G3 | AAA Certificate Services |
|---|---|---|---|---|---|
| `certifi-2026.7.22.pem` | 2026.7.22 | `62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775` | 121 | yes | no |
| `certifi-2026.10.19.pem` | 2026.10.19 (the fix, GHSA-6q48-6c7w-9gw2) | `42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b` | 120 | no | no |

Source: https://pypi.org/project/certifi/ (and https://github.com/certifi/python-certifi).
