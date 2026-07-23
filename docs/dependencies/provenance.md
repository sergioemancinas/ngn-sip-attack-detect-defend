# Dependency Provenance

The project avoids committing unverified convenience images as implementation dependencies.

| Component | Source | Pin | Verification |
|---|---|---|---|
| Kamailio | Official Kamailio APT archive | `5.8.8+bpo12` | Repository key from `https://deb.kamailio.org/kamailiodebkey.gpg`; APT signed repository with pinned fingerprint `E79ACECB87D8DCD23A20AD2FFB40D3E6508EA4C8` |
| Asterisk | Official `asterisk/asterisk` GitHub repository | tag `20.19.0`, commit `f66917fe6da487155f80ab50403bf3d7bdc86183` | Docker build fails if the checked-out tag does not resolve to the pinned commit |
| SIPp | Official `SIPp/sipp` GitHub repository | tag `v3.7.3`, commit `11b51748b274d24ac156ac40216600aca0f352a7` | Docker build fails if the checked-out tag does not resolve to the pinned commit |
| PostgreSQL | Docker Official Images `postgres` | `16-alpine` / `16.13-alpine3.23`, manifest digest `sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50` | Docker manifest annotations point to `docker-library/postgres` revision `3b6b5fca9ca40c84b77540fc605ea8e8353b13b2`; Docker build uses `--pull`, runs Alpine package upgrades, replaces the entrypoint `gosu` call with `su-exec`, and removes the vulnerable `gosu` binary |
| pgvector | Official `pgvector/pgvector` GitHub repository | tag `v0.8.0`, commit `2627c5ff775ae6d7aef0c430121ccf857842d2f2` | Docker build fails if the checked-out tag does not resolve to the pinned commit |
| Alpine final stage | Docker Official Images `alpine` | `3.23`, manifest digest `sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11` | Final PostgreSQL image copies the cleaned Postgres/pgvector filesystem into this base so deleted upstream `gosu` layers are not present |
| rtpengine | Debian Bookworm package | `10.5.3.5-1` | Debian signed package repository; kernel mode remains VM-only |

The earlier third-party Docker image probes were not committed as runtime dependencies.
