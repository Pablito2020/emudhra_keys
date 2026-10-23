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

`src/emudhra/certificates.py` exposes `EmudhraCertificates`, an iterable of
entries holding a name, the original `x509.Certificate`, and its matching
`ec.EllipticCurvePrivateKey`. The certificates in `src/emudhra/certificates/` come from
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
uv run main.py end_to_end example.test
uv run main.py end_to_end example.test --ca em-ov-tls-ca-g3c
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
`src/commands.py` owns workflows and uses `src/emudhra/issuer.py` for certificate
operations. `uv run python -m src.main` remains supported.

### Local HTTPS demo

`end_to_end` serves one selected CA's certificate on `127.0.0.1:443`, with the
page "If you see this, it's pretty bad." Open the printed `https://<domain>/`
URL while the command runs. Select another CA with `--ca`; TLS certificates
cannot be selected by URL path because the handshake precedes the HTTP request.

The command reuses valid files in `certificates/<domain>/<ca>/`, or generates
them if absent. It refuses incomplete, expired, mismatched, or incorrectly
issued files without overwriting them. Ctrl+C and SIGTERM stop this run's nginx
and remove its DNS override; generated certificates remain on disk.

Linux and sudo are required for system changes. Python runs as your user; sudo
prompts on the terminal for DNS changes and the nginx listener. The nginx master
runs privileged to bind port 443; its workers run as your user. No system nginx
service is started, stopped, or reconfigured. Runtime files under `src/nginx/`
are isolated and removed after shutdown.

nginx serves the leaf, the selected issuing CA, and the cross-signed
`emSign Root TLS CA - G3`, in that order. The cross-signed parent is bundled
locally from [emSign's repository](https://repository.emsign.com/certs/crosssign/roottlscag3.crt)
and pinned to SHA-256
`3094025792039a68af6e553686410bdab7c0d4a36b9084cba64202e35d6ebbdd`.
Its signature on the issuing CA is checked before nginx starts. The client
must trust `emSign ECC Root CA - G3`; that root is not sent by nginx or installed
into any trust store. Chain assembly is offline, and restarting the command
fixes the served chain for existing generated certificates without replacing
their keys or leaves.

With active systemd-resolved 261+, temporary JSON records are installed under
`/run/systemd/resolve/static.d/` and resolved is reloaded with SIGHUP. This
requires `ReadStaticRecords=yes` (the default), and works with Nix-managed
`/etc/hosts`. Older or non-systemd machines use a marked `/etc/hosts` entry;
conflicting entries and managed/read-only hosts files are rejected. DNS
resolution is checked before nginx starts. Cleanup preserves unrelated entries
and edits. Concurrent demos for the same domain by the same user are rejected.

The demo does not alter trust stores. Browser distrust/revocation checks still
apply. Forced termination such as SIGKILL or a power loss cannot run cleanup;
remove the run's marked hosts entry or `emudhra-*.rr` file manually if necessary.

## Python API

```python
from src.emudhra.certificates import EmudhraCertificates
from src.emudhra.issuer import EMudhraIssuer

cas = EmudhraCertificates()  # All eight real intermediates and their published keys.
issuer = EMudhraIssuer(cas)
ca = cas.get_from_name("em-ov-tls-ca-g3c")
assert ca.private_key.private_numbers().private_value == 4
issued = issuer.generate_certificate("example.test", ca.name)
all_issued = issuer.generate_all_certificates("example.test")  # Six TLS intermediates.
issued.certificate.verify_directly_issued_by(ca.certificate)
```

Chain and nginx tests explicitly trust the bundled ECC root fixture and require
the complete chain. These checks do not enforce revocation or Certificate
Transparency, or establish acceptance by current browsers.

## Checks

```sh
uv run pytest tests/test_chain.py tests/test_commands.py tests/test_dns.py tests/test_server.py tests/test_system.py
ruff check .
ruff format --check .
nix flake check
```

The older `tests/test_keys.py` still targets the removed `src.keys` API and fails
collection. It is outside this DNS/nginx change. The nginx tests use temporary
files and unprivileged loopback ports; they never change system DNS. Exercising
the actual sudo/DNS integration remains a manual check.
