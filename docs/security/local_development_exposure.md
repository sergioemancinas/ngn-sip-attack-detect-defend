# Local Development Exposure


## Position

This is the local development baseline. It should not expose SIP, dashboards, databases, or management APIs to the LAN or the public internet. Public SIP/RTP exposure belongs to the university VM phase after the VM hardening checklist is implemented.

## Current Binding Policy

- Kamailio is the only service with host-published ports.
- Kamailio binds to `${DEV_BIND_IP:-127.0.0.1}:${SIP_TRANSPORT_PORT:-5060}` for UDP and TCP.
- PostgreSQL, Asterisk, rtpengine control, and SIPp test containers stay on the Docker bridge network only.
- rtpengine may listen on `0.0.0.0` inside its container for Docker-network peers, but no rtpengine port is published to the host.
- Future local Wazuh, Grafana, OpenSearch, ClickHouse, Shuffle, and ML services must bind dashboards and APIs to `127.0.0.1` unless a separate review explicitly allows otherwise.

## Checks

Run this before commits that touch Compose or networking:

```sh
make check-local-exposure
```

The check fails if Docker publishes a Compose service on `0.0.0.0` or `[::]`.

## VM Boundary

The university VM work is intentionally separate. When that phase starts, the project will revisit:

- UFW default deny
- SSH key-only on a non-standard port
- Fail2Ban
- Docker daemon behavior around iptables
- Explicit SIP `5060/5061` and RTP range exposure
- Dashboards via SSH tunnel or loopback-only reverse proxy
