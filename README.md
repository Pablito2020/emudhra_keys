# eMudhra CA compromise reproduction

This project loads the **eight real eMudhra intermediates** affected by the
October 2026 key-generation incident, together with their publicly recovered
P-384 private keys. It reproduces signing with those keys locally.

All eight intermediates were revoked for key compromise on 18 October 2026.
A valid signature from one of these keys does **not** establish current public
trust. The code does not install trust anchors or bypass client distrust.

Sources:

- [Fenko's explanation and published private scalars](https://fenko.nz/blog/emudhra-ca-compromise/)
- [Mozilla incident 2083449, including certificate fingerprints and revocation](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Original reporter's certificate attachment](https://bugzilla.mozilla.org/attachment.cgi?id=9664066)

## Certificate authorities

`src/keys.py` exposes `CERTIFICATE_AUTHORITIES: list[CertificateAuthority]`.
Each entry holds a name, the original `x509.Certificate`, and its matching
`ec.EllipticCurvePrivateKey`. The certificates in `src/certificates/` come from
Mozilla's incident attachment. They are the emSign-issued intermediates, one per
compromised key; Sectigo cross-certificates are not duplicated in the list.

| Name | Purpose | Published private scalar |
| --- | --- | ---: |
| `em-dv-tls-ca-g3b` | TLS DV | 156 |
| `em-ov-tls-ca-g3b` | TLS OV | 155 |
| `em-ev-tls-ca-g3b` | TLS EV | 115 |
| `em-ov-cs-ca-g3b` | Code signing | 66 |
| `em-dv-tls-ca-g3c` | TLS DV | 230 |
| `em-ov-tls-ca-g3c` | TLS OV | 4 |
| `em-ev-tls-ca-g3c` | TLS EV | 56 |
| `em-ov-cs-ca-g3c` | Code signing | 237 |

Loading checks each certificate's complete SHA-256 fingerprint against Mozilla's
published value and verifies that the derived private key matches its public
key. There are no runtime downloads, generated substitute CAs, environment
variables, or demo flags.

## Run

Python 3.15 is required. The Nix development shell provides Python, uv, nginx,
OpenSSL, direnv, git and ruff. `.envrc` contains `use flake` for direnv.

```sh
nix develop
uv sync --locked
uv run main.py --help
uv run main.py generate example.test
uv run main.py generate example.test --ca em-ov-tls-ca-g3c
uv run main.py generate example.test --all --output certificates-all
```

`--all` generates one certificate from each of the **six TLS intermediates**.
The two code-signing intermediates remain available in the Python list, but
cannot be selected to issue server-authentication certificates. The default
issuer is `em-dv-tls-ca-g3b`.

Output directories (`certificates/<domain>/<ca>/`) contain `certificate.pem`,
`private-key.pem` and `ca.pem`. Leaf keys are freshly generated P-256 keys and
have mode `0600`; output directories have mode `0700` and are never overwritten.
CA private keys are not exported. Leaves contain a DNS SAN, server-auth EKU,
key usage, SKI/AKI and `CA:FALSE`. Their validity defaults to 30 days, bounded by
the issuer's validity. DNS names are normalized to IDNA; IPs and wildcards are
not accepted.

`main.py` contains only Click callbacks for parsing, output and error reporting.
`src/commands.py` owns workflows and calls `src/keys.py` for certificate
operations. `uv run python -m src.main` remains supported. DNS configuration and
nginx startup are not implemented; `end_to_end <domain>` reports that explicitly.

## Python API

```python
from src.keys import (
    CERTIFICATE_AUTHORITIES,
    generate_all_certificates,
    generate_certificate,
    get_all_cas,
    get_ca,
)

cas = get_all_cas()  # All eight real intermediates and their published keys.
ca = get_ca("em-ov-tls-ca-g3c")
assert ca.private_key.private_numbers().private_value == 4
issued = generate_certificate("example.test", ca.name)
all_issued = generate_all_certificates("example.test")  # Six TLS intermediates.
issued.certificate.verify_directly_issued_by(ca.certificate)
```

Signature checks and the tests explicitly trusting an intermediate do not check
its revocation or establish a chain accepted by current browsers.

## Checks

```sh
uv run pytest
ruff check .
ruff format --check .
nix flake check
```
