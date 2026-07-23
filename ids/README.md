# IDS

Signature-based intrusion detection for the SIP edge.

`suricata/` is the active IDS. Suricata runs inside the Kamailio network
namespace so it sees the SIP edge traffic directly, and matches the SIP rules in
`suricata/rules/sip.rules` (SIDs `1000001`-`1000014`). Alerts ship through Vector
into ClickHouse (`suricata_alerts`), where they are compared against ground-truth
labels. See [`suricata/README.md`](suricata/README.md).

Suricata is one of the three detection arms evaluated in this project, alongside
Wazuh correlation and the Stage-1 ML classifier (see the top-level `README.md`).
