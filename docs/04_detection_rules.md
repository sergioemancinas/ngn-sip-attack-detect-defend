# Detection Rules

This document cross-walks the current attack scripts against the implemented
Suricata and Wazuh SIP rules for NGN-T1.3.

Sources:

- Attack inventory: `docs/03_attack_playbook.md`, section `Attack Matrix`.
- Suricata rule range: `ids/suricata/rules/sip.rules`, SIDs `1000001` to
  `1000014`.
- Wazuh rule range: `siem/wazuh/rules/sip_rules.xml`, SIDs `100100` to
  `100199`.

Notes:

- Suricata SIDs `1000010`, `1000011`, and `1000014` are classifier/baseline
  signals. They are useful for replay validation, but they are not strong
  attack verdicts by themselves.
- Wazuh SID `100100` is the Kamailio `NGN-SEC` base event. Child rules such as
  `100107` and `100108` depend on Kamailio emitting the expected `NGN-SEC`
  fields.
- Expected latency assumes the local lab path: Suricata writes EVE JSON
  immediately, Wazuh evaluates after log ingestion, and dashboard visibility can
  lag by the Vector, ClickHouse, or Wazuh indexer polling interval.

## Attack To Rule Cross-Walk

| Attack ID | Suricata SID(s) | Wazuh SID(s) | MITRE technique | Expected detection latency | Expected FP rate class | Gap |
|---|---|---|---|---|---|---|
| `sippts_options_scan` | `1000003` sippts UA; `1000005` OPTIONS burst, 15 requests in 60s; `1000014` SIP classifier | `100107` scanner UA if Kamailio emits `NGN-SEC` with `ua="sippts"` | `T1595` Active Scanning | UA alert on first packet; OPTIONS burst after the 15th request inside 60s; Wazuh after matching log ingestion | Med | No Wazuh OPTIONS-rate correlation yet. Normal OPTIONS keepalives can resemble scans unless source role and rate are considered. The script emits label ID `sippts_options`, so playbook and label IDs should be normalized before automated joins. |
| `sipvicious_svmap` | `1000001` friendly-scanner UA; `1000002` SIPVicious tool-family UA; `1000014` SIP classifier | `100107` scanner UA, via `100100` base event | `T1595.001` Active Scanning: Scanning IP Blocks | First matching SIP request for UA rules, usually `<1s` in EVE; Wazuh after the Kamailio log event is ingested | Low | UA-based only. A scanner that spoofs a normal softphone UA can avoid this until volume or behavior rules are added. |
| `sippts_svcrack` | `1000003` sippts UA if present; `1000009` REGISTER from outside trusted CIDR; `1000010` REGISTER classifier; `1000012` forbidden response | `100101` Kamailio single auth failure; `100102` Kamailio 5 failures in 60s; `100104` Asterisk single auth failure; `100105` Asterisk 5 failures in 60s | `T1110.001` Brute Force: Password Guessing | Single auth-fail rules on first failed login; burst rules after the 5th failed login in 60s | Med | Suricata coverage is supporting evidence only. The real brute-force verdict is in Wazuh correlation. |
| `sippts_smap_invite` | `1000003` sippts UA; `1000007` malformed CSeq; `1000008` INVITE without Contact; `1000011` INVITE classifier; `1000014` SIP classifier | None | `T1190` Exploit Public-Facing Application | First malformed INVITE, usually `<1s` in EVE | Low | No Wazuh malformed-SIP or smap-specific rule yet. |
| `sippts_malformed_invite` | `1000003` sippts UA; `1000006` malformed Via; `1000007` malformed CSeq; `1000008` INVITE without Contact; `1000011` INVITE classifier; `1000014` SIP classifier | None | `T1190` Exploit Public-Facing Application | First malformed INVITE, usually `<1s` in EVE | Low | No Wazuh malformed-SIP rule yet. Coverage currently depends on Suricata parsing the malformed request. |
| `sipp_register_flood` | `1000004` REGISTER flood, 30 requests in 60s; `1000009` REGISTER from outside trusted CIDR if source is untrusted; `1000010` REGISTER classifier; `1000014` SIP classifier | `100103` PIKE blocked source if PIKE emits; `100108` 30 `NGN-SEC REGISTER` events in 60s | `T1499` Endpoint Denial of Service | Suricata and Wazuh burst rules after the 30th REGISTER inside 60s; at the default 50/s script rate this should happen in about 1s after traffic reaches the sensor | Med | Wazuh flood coverage depends on PIKE or `NGN-SEC REGISTER` logging being active. Until then, Suricata is the primary implemented detector. The script currently emits label ID `sippts_register_flood`, so playbook and label IDs should be normalized before automated joins. |
| `rtp_inject` | None | None | `T1557` / `T1557.002` Adversary-in-the-Middle | Not applicable yet; no media traffic generator or detector is implemented | High | Planned media attack only. No RTP/SRTP Suricata or Wazuh rule exists in the current SID ranges. |
| `dialplan_abuse` | `1000013` long numeric INVITE URI; `1000011` INVITE classifier; `1000014` SIP classifier | `100118`, `100119` (Kamailio), `100133` (Asterisk) | `T1496` Resource Hijacking | First matching INVITE, usually `<1s` in EVE; Wazuh after matching log ingestion | Med | Suricata SID `1000013` metadata is `T1496` (rev 2); weak classifier (any long numeric URI), not a final toll-fraud verdict. Wazuh rules require premium-prefix pattern in Kamailio `reason` or Asterisk `message`. Access may involve `T1110`/`T1078`; outcome is `T1496`. |

## Honest Gap List

Playbook attack IDs with no detection rule yet:

| Attack ID | Reason |
|---|---|
| `rtp_inject` | Planned media attack only. There is no script under `attacks/05_media` and no assigned Suricata or Wazuh SID for RTP/SRTP behavior. |

Partial gaps that remain:

| Gap | Affected attack ID(s) | What is missing |
|---|---|---|
| Wazuh malformed-SIP correlation | `sippts_malformed_invite`, `sippts_smap_invite` | Add a Kamailio/Asterisk log decoder and Wazuh rule for malformed Via, malformed CSeq, missing Contact, or Kamailio `sanity_check` drops. |
| Wazuh OPTIONS scan correlation | `sippts_options_scan` | Add a Wazuh frequency rule for repeated OPTIONS events from one source, ideally with distinct target URI or UA context. |
| Suricata brute-force correlation | `sippts_svcrack` | Add a thresholded Suricata rule or rely intentionally on Wazuh for auth-failure state. Current Suricata SIDs are supporting evidence only. |
| Runtime dependency on Kamailio security logs | `sippts_options_scan`, `sipvicious_svmap`, `sipp_register_flood` | Wazuh child rules require `NGN-SEC` events with `event_type`, `srcip`, `user_agent`, and `reason`. The rule logic exists, but log emission must stay aligned with the decoder. |
| Attack ID normalization | `sippts_options_scan`, `sipp_register_flood` | The playbook IDs differ from emitted label IDs: `sippts_options_scan` emits `sippts_options`, and `sipp_register_flood` emits `sippts_register_flood`. Normalize before relying on joins between playbook, labels, and alerts. |
