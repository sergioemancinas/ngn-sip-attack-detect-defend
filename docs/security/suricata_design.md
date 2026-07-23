# Suricata IDS Design

## Scope

Suricata is the primary IDS for the NGN SIP attack-detect-defend lab. This
slice adds a standalone Compose stack and a starter SIP rule set without
changing the core SIP, observability, SIEM, SOAR, ML, or attack lanes.

The container joins the existing `ngn-sip_sip_lab` bridge with no host-published
ports. It uses the pinned upstream image `jasonish/suricata:7.0.10`, drops all
capabilities except `NET_ADMIN` and `NET_RAW`, and writes EVE JSON to a named
volume for later Vector ingestion.

AF_PACKET capture on `any` is the target Linux/Campus VM mode. On macOS Docker
Desktop this stack is useful for config and parser smoke tests, but final packet
capture validation belongs on the Linux VM where AF_PACKET semantics match the
deployment plan.

## Configuration

- Config: `ids/suricata/etc/suricata.yaml`
- Local rules: `ids/suricata/rules/sip.rules`
- EVE JSON: `/var/log/suricata/eve.json`
- Rule load policy: only `sip.rules` under `/etc/suricata/rules`
- Classification/reference configs: stock Suricata-compatible files under
  `ids/suricata/etc/`

## Starter Rule Mapping

| SID | Detection | MITRE ATT&CK |
|---|---|---|
| `1000001` | SIPVicious `friendly-scanner` User-Agent | `T1595` Active Scanning |
| `1000002` | SIPVicious tool family User-Agent | `T1595` Active Scanning |
| `1000003` | `sippts` probe User-Agent family | `T1046` Network Service Discovery |
| `1000004` | REGISTER flood, 30 requests in 60 seconds from one source | `T1499` Endpoint Denial of Service |
| `1000005` | OPTIONS scan burst from one source | `T1046` Network Service Discovery |
| `1000006` | Malformed Via header | `T1190` Exploit Public-Facing Application |
| `1000007` | Malformed CSeq header | `T1190` Exploit Public-Facing Application |
| `1000008` | INVITE without Contact header | `T1190` Exploit Public-Facing Application |
| `1000009` | REGISTER from outside trusted CIDR | `T1110` Brute Force |
| `1000010` | REGISTER classifier event | `T1046` Network Service Discovery |
| `1000011` | INVITE classifier event | `T1046` Network Service Discovery |
| `1000012` | Forbidden SIP response observed | `T1110` Brute Force |
| `1000013` | Long numeric INVITE URI toll-fraud candidate | `T1496` Resource Hijacking |
| `1000014` | Generic SIP parser classifier | `T1046` Network Service Discovery |

The classifier rules are intentionally noisy. They give the lab a labeled
baseline for replay validation and should be disabled or thresholded before
non-lab traffic is monitored.

## EVE To ClickHouse Path

The Suricata stack stops at writing `eve.json`. The next integration point is
`observability/vector/vector.yaml`, which already ships Asterisk logs to
ClickHouse. A later observability change should mount
`ngn-sip-ids_suricata_logs` read-only, add a Suricata EVE file source, parse the
JSON event payload, and sink alerts/flows into ClickHouse tables used by the
Grafana SIP dashboard.

## References

- Suricata 7.0.10 SIP keyword documentation:
  <https://docs.suricata.io/en/suricata-7.0.10/rules/sip-keywords.html>
- Suricata upstream source:
  <https://github.com/OISF/suricata>
