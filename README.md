# eMudhra CA Compromise

## Generate keys, and sign the certificate for a given domain

To generate the proof of concept for a given domain:

```bash
uv run main.py generate <domain_name> --all
```

## Run the end-to-end demo

To run the full demonstration:

```bash
uv run main.py end_to_end <domain_name>
```

Note: The demo temporarily modifies your DNS configuration. You may need to flush your DNS caches for the changes to take effect or to restore normal resolution afterward.

### Browser and client compatibility

The results depend on whether your browser or system has received the relevant security updates. In my current environment:

- **Firefox:** The demo fails, as Firefox correctly handles certificate revocation through CRLs.
- **Chromium:** The demo works because the Chromium version shipped by my Linux distribution has not yet been patched.
- **curl:** The demo also works because my system's CA certificate store has not yet been updated to reflect the compromise.
