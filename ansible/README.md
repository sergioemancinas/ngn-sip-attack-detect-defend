# Ansible

A skeleton for provisioning the SIP stack on bare VMs (the campus-VM deployment
path). It defines the playbook layout and the baseline hardening tasks; it is not
applied to a live cluster and holds no real secrets or complete service config.
Docker Compose is the only verified deployment path (see the top-level
[`README`](../README.md)); this is future-facing infrastructure-as-code.

## Layout

One playbook per host role, with shared setup and hardening in `roles/common/`:

| Playbook | Configures |
|---|---|
| `kamailio.yml` | SIP proxy host and HEP export |
| `asterisk.yml` | PBX host and PJSIP logging |
| `rtpengine.yml` | RTP relay host |
| `wazuh-manager.yml` / `wazuh-indexer.yml` / `wazuh-dashboard.yml` | Wazuh SIEM tiers |
| `shuffle.yml` | SOAR worker and webhook |
| `observability.yml` | ClickHouse, Vector, Grafana, Prometheus, Homer |

## Running it

Run in check mode until the target VMs exist and the common role has been reviewed
against each OS image:

```bash
ansible-playbook -i inventory.example.yml playbooks/site.yml --check
```

Requires ansible-core 2.19.7 and Python 3.11+.

## Secrets

Committed files carry `change-me-local-only` placeholders only. Real credentials
are injected at runtime from a secrets store, never committed.
