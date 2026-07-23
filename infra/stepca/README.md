# step-ca

Placeholder for the internal certificate authority used to issue SIP TLS certs
on the VM deployment. The local Colima stack does not use step-ca — Caddy's
built-in internal CA terminates TLS there (see [`infra/tls/`](../tls/README.md)).

No CA material is committed here: keys and issued certs are generated at deploy
time and git-ignored.
