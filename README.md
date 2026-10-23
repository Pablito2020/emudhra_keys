# eMudhra Keys Cryptography

A small classroom example using Python and `cryptography` to create CA keys and
sign DNS certificates. Python 3.15 is the newest minor version explicitly listed
by [cryptography 50.0.2](https://pypi.org/project/cryptography/50.0.2/)
(checked 2026-10-23).

eMudhra's [public repository](https://repository.emsign.com/) publishes **public
certificates**, not CA private keys. A public certificate cannot reveal its
private key. Generating another key with the same issuer name does not produce
an eMudhra signature. This project can demonstrate signing with independent local
CAs, or use CA keys you already possess and are authorized to use. It does not
generate eMudhra's actual private keys or issue publicly trusted certificates.

## Run

```sh
nix develop                 # Python 3.15, uv, nginx, openssl, direnv, git, ruff
# Or use an existing uv installation; uv installs Python 3.15 automatically.
uv sync --locked
uv run main.py --help
uv run main.py generate cv.udl.cat --demo
uv run main.py generate cv.udl.cat --demo --all --output certificates-all
uv run main.py generate example.test --demo --ca demo-ec
```

`.envrc` contains `use flake` for direnv. Nix pins the development tools in
`flake.lock`; `uv.lock` pins Python dependencies. Run commands from the project
root; `uv run python -m src.main` is also supported.

Each output directory (`certificates/<domain>/<ca>/`) contains `certificate.pem`,
`private-key.pem` and `ca.pem`. The leaf private key has mode `0600`; existing
directories are never overwritten. Demo RSA and EC issuer keys are generated
once per process, kept in memory and discarded on exit. The exported `ca.pem`
is enough to verify that run's leaf; it does not contain a private key. Demo
certificates are trusted only when the caller explicitly trusts that local CA:

```sh
openssl verify -CAfile certificates/cv.udl.cat/demo-rsa/ca.pem \
  -purpose sslserver -verify_hostname cv.udl.cat \
  certificates/cv.udl.cat/demo-rsa/certificate.pem
```

## Supplied CA keys

Without `--demo`, set the runtime environment variable `EMUDHRA_CAS` to a JSON
object with this shape (the values below are placeholders):

```json
{
  "classroom-ca": {
    "certificate": "<CA certificate PEM, with newline characters>",
    "private_key": "<matching private key PEM, with newline characters>",
    "password": "<optional password for encrypted PEM>"
  }
}
```

Omit `password` for unencrypted keys. Supply the variable through your runtime
secret mechanism; do not put it in source files, `.envrc` or committed files.
Issuer private keys and passwords are never exported. The code accepts RSA/EC
CA key pairs, verifies their match, current validity and signing usage, and
refuses name-constrained issuers. This is a signing example, not a production
CA policy engine or a public trust-chain validator. Supplying an issuer PEM
alone does not establish its relationship to eMudhra or browser trust.

```sh
uv run main.py generate cv.udl.cat --ca classroom-ca
uv run main.py generate cv.udl.cat --all
```

`--all` means all **configured** CAs (or both local demo CAs with `--demo`), not
all public eMudhra roots. Leaves contain a DNS SAN, server-auth EKU, key usage,
SKI/AKI and `CA:FALSE`. They expire in 30 days or at their issuer's expiry,
whichever comes first. DNS names are normalized to IDNA; IPs and wildcards are
not accepted. No trust store, DNS or web server is modified by `generate`.

## Python API

```python
from src.keys import (
    get_ca,
    get_all_cas,
    generate_certificate,
    generate_all_certificates,
)

ca = get_ca("demo-ec", demo=True)
cas = get_all_cas(demo=True)
issued = generate_certificate("cv.udl.cat", "demo-ec", demo=True)
all_issued = generate_all_certificates("cv.udl.cat", demo=True)
# issued.certificate, issued.private_key, issued.ca are cryptography objects.
```

The approved skeleton includes `src/dns.py`, `src/server.py` and `src/nginx/`.
DNS configuration and nginx startup are not implemented yet. The reserved
`uv run main.py end_to_end <domain>` command exits with an explanatory error
without changing the machine.

## Checks

```sh
uv run pytest
ruff check .                # Nix supplies a native binary, including on NixOS
ruff format --check .
nix flake check
```
