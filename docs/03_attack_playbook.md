# Attack Playbook

## Scope And Execution Rules

This playbook maps the six academic attack classes to concrete scripts, expected observables, detection rules, and response actions. All attacks are restricted to owned lab targets: the local Compose SIP bridge, loopback services, or the later campus VM after the hardening review is complete.

Every implemented script under `attacks/01_recon/` through `attacks/06_tollfraud/` emits a ground-truth label through `attacks.orchestrator.label_emitter` into `ngn_sip.attack_labels`. Some wrappers are intentionally label-only until the attack container image is finalized. Where that is true, the detection expectation is tied to equivalent lab traffic, not to the current wrapper alone.

High-confidence automated response is intentionally narrow. `siem/wazuh/integrations/wazuh_shuffle_integration.xml` sends only Wazuh SIDs `100102`, `100103`, `100105`, and `100108` to Shuffle. `siem/wazuh/active-response/kamcmd_block.sh` writes the source IP into Kamailio `ban_table`, defined in `infra/kamailio/modules/htable.cfg` and enforced by `infra/kamailio/modules/ban.cfg`.

## Script Inventory

| Class | Implemented scripts |
|---|---|
| Reconnaissance | [`attacks/01_recon/sippts_options_scan.sh`](../attacks/01_recon/sippts_options_scan.sh), [`attacks/01_recon/sipvicious_svmap.sh`](../attacks/01_recon/sipvicious_svmap.sh) |
| Credentials | [`attacks/02_credentials/sippts_svcrack.sh`](../attacks/02_credentials/sippts_svcrack.sh), [`attacks/02_credentials/wordlists/short.txt`](../attacks/02_credentials/wordlists/short.txt) |
| Injection | [`attacks/03_injection/sippts_smap_invite.sh`](../attacks/03_injection/sippts_smap_invite.sh), [`attacks/03_injection/sippts_malformed_invite.sh`](../attacks/03_injection/sippts_malformed_invite.sh) |
| Denial of service | [`attacks/04_dos/sipp_register_flood.sh`](../attacks/04_dos/sipp_register_flood.sh), [`attacks/04_dos/sipp_register_flood.xml`](../attacks/04_dos/sipp_register_flood.xml) |
| Media | [`attacks/05_media/rtp_inject.sh`](../attacks/05_media/rtp_inject.sh) |
| Toll fraud | [`attacks/06_tollfraud/dialplan_abuse.sh`](../attacks/06_tollfraud/dialplan_abuse.sh) |

`attacks/orchestrator/run_phase.py` executes scripts in phase order. Use `--dry-run` to list scripts without sending traffic.

## Detection Rule Reference

| Source | Implemented SIDs used by this playbook |
|---|---|
| Suricata | `1000001` friendly-scanner UA, `1000002` SIPVicious UA, `1000003` sippts UA, `1000004` REGISTER flood, `1000005` OPTIONS burst, `1000006` malformed Via, `1000007` malformed CSeq, `1000008` INVITE without Contact, `1000009` REGISTER outside trusted CIDR, `1000010` REGISTER classifier, `1000011` INVITE classifier, `1000012` forbidden response, `1000013` long numeric INVITE URI, `1000014` SIP protocol classifier |
| Wazuh | `100101` Kamailio auth failure, `100102` Kamailio brute-force burst, `100103` PIKE blocked source, `100104` Asterisk auth failure, `100105` Asterisk auth-failure burst, `100106` low-and-slow credential attack, `100107` scanner User-Agent, `100108` REGISTER flood, `100109` REGISTER from scanner UA, `100110` spoofed Contact, `100111` INVITE flood, `100112` BYE flood, `100113` malformed Via, `100114` malformed CSeq, `100115` malformed From, `100116` malformed To, `100117` SDP injection, `100118` premium-prefix toll fraud, `100119` repeated premium-prefix attempts, `100120` RTP relay abuse, `100121` RTCP anomaly, `100124` presence enumeration, `100126` OPTIONS scan candidate, `100127` high-rate OPTIONS scan, `100128` coordinated REGISTER activity, `100129` coordinated REGISTER campaign, `100130` SIP transport downgrade, `100131` ban_table hit, `100132` SOAR action acknowledgement, `100133` Asterisk premium-prefix attempt, `100134` Asterisk RTP relay abuse |

## Reconnaissance

| Attack name | Tooling | MITRE ATT&CK technique | Preconditions | Observables | Expected detection rule | Expected SOAR or active-response action | Runnable script |
|---|---|---|---|---|---|---|---|
| SIP OPTIONS sweep | `sippts scan -m OPTIONS`; current wrapper is label-only | `T1595` Active Scanning | `CLICKHOUSE_PASSWORD` is set for label emission. Equivalent SIP traffic requires manual sippts execution or a future attack image. Target defaults to `127.0.0.1:5060`. | `attack_labels` row with `attack_id=sippts_options`; when traffic is enabled, OPTIONS requests to Kamailio and possible `sippts` User-Agent. | Suricata `1000003`, `1000005`, `1000014`. Wazuh `100107` for scanner UA, `100126` and `100127` for OPTIONS probe behavior if Kamailio emits matching `NGN-SEC` reasons. | None. Recon is evidence-only unless later promoted to a high-confidence response rule. | [`attacks/01_recon/sippts_options_scan.sh`](../attacks/01_recon/sippts_options_scan.sh) |
| SIPVicious svmap scan | SIPVicious `svmap` or sippts `svmap`; current wrapper is label-only | `T1595.001` Active Scanning: Scanning IP Blocks | `CLICKHOUSE_PASSWORD` is set for label emission. Equivalent SIP traffic requires SIPVicious or sippts execution. Target defaults to `127.0.0.1:5060`. | `attack_labels` row with `attack_id=sipvicious_svmap`; when traffic is enabled, scanner User-Agent values such as `friendly-scanner`, `sipvicious`, or `svmap`. | Suricata `1000001`, `1000002`, `1000014`. Wazuh `100107`, and `100109` if the scanner sends REGISTER and Kamailio emits `NGN-SEC`. | None. Scanner hits are reviewed and correlated with later credential or flood activity. | [`attacks/01_recon/sipvicious_svmap.sh`](../attacks/01_recon/sipvicious_svmap.sh) |
| Presence or subscription enumeration | Planned SIP SUBSCRIBE or presence probe | `T1595` Active Scanning | No runnable script exists under `attacks/01_recon/` today. | Planned observables: repeated SUBSCRIBE or resource-list targeting, possible presence-leak metadata. | Wazuh `100124`; no Suricata presence-specific SID exists. | None until false-positive behavior is measured. | Planned, no script exists. |

## Credentials

| Attack name | Tooling | MITRE ATT&CK technique | Preconditions | Observables | Expected detection rule | Expected SOAR or active-response action | Runnable script |
|---|---|---|---|---|---|---|---|
| SIP digest password guessing | `sippts svcrack`; current wrapper is label-only | `T1110.001` Brute Force: Password Guessing | `CLICKHOUSE_PASSWORD` is set. Extension defaults to `1000`. Wordlist defaults to `attacks/02_credentials/wordlists/short.txt`. Equivalent SIP traffic requires sippts execution. | `attack_labels` row with `attack_id=sippts_svcrack`; when traffic is enabled, repeated REGISTER or auth attempts, Kamailio or Asterisk authentication failures, possible 403 responses. | Suricata `1000003`, `1000009`, `1000010`, `1000012`. Wazuh `100101`, `100102`, `100104`, `100105`, and `100106`. | Wazuh SIDs `100102` and `100105` are sent to Shuffle. Wazuh active response runs `kamcmd_block.sh` to set `ban_table[$srcip]=1`; subsequent drops can emit Wazuh `100131`. | [`attacks/02_credentials/sippts_svcrack.sh`](../attacks/02_credentials/sippts_svcrack.sh) |
| Coordinated password spray | Planned multi-source REGISTER campaign | `T1110.003` Password Spraying | No runnable script exists under `attacks/02_credentials/` today. | Planned observables: repeated REGISTER attempts from multiple sources in one `/24`, low-and-slow failure rate. | Wazuh `100106`, `100128`, `100129`. Suricata provides supporting `1000009` and `1000010` evidence only. | Not wired to Shuffle today except if the campaign also fires `100102` or `100105`. | Planned, no script exists. |

## Injection

| Attack name | Tooling | MITRE ATT&CK technique | Preconditions | Observables | Expected detection rule | Expected SOAR or active-response action | Runnable script |
|---|---|---|---|---|---|---|---|
| sippts smap-style malformed INVITE | SIPp container sends a sippts smap-style INVITE scenario | `T1190` Exploit Public-Facing Application | Docker network is `ngn-sip_sip_lab` or `sip_lab`; SIPp image `ngn-sip/sipp:3.7.3` exists; target must resolve to `kamailio:5060`; `CALLS` and `RATE` are positive integers. | `attack_labels` row with `attack_id=sippts_smap_invite`; INVITE to extension `1000` by default; `User-Agent: sippts smap`; malformed `CSeq`; missing `Contact`. | Suricata `1000003`, `1000007`, `1000008`, `1000011`, `1000014`. Wazuh `100114` only if Kamailio emits a matching `NGN-SEC` malformed-CSeq reason. | None. Injection is evidence-only today. | [`attacks/03_injection/sippts_smap_invite.sh`](../attacks/03_injection/sippts_smap_invite.sh) |
| Malformed INVITE headers | SIPp container sends malformed INVITE headers | `T1190` Exploit Public-Facing Application | Docker network is `ngn-sip_sip_lab` or `sip_lab`; SIPp image `ngn-sip/sipp:3.7.3` exists; target must resolve to `kamailio:5060`; `CALLS` and `RATE` are positive integers. | `attack_labels` row with `attack_id=sippts_malformed_invite`; malformed `Via`; malformed `CSeq`; missing `Contact`; `User-Agent: sippts`. | Suricata `1000003`, `1000006`, `1000007`, `1000008`, `1000011`, `1000014`. Wazuh `100113` and `100114` only if Kamailio emits matching `NGN-SEC` malformed-header reasons. | None. Injection is evidence-only today. | [`attacks/03_injection/sippts_malformed_invite.sh`](../attacks/03_injection/sippts_malformed_invite.sh) |
| SDP command-marker injection | Planned malicious SDP body in INVITE | `T1190` Exploit Public-Facing Application | No runnable script exists under `attacks/03_injection/` today. | Planned observables: INVITE with SDP command-like markers or anomalous SDP attributes. | Wazuh `100117`; no Suricata SDP-injection SID exists today. | None until parser and false-positive behavior are proven. | Planned, no script exists. |

## Denial Of Service

| Attack name | Tooling | MITRE ATT&CK technique | Preconditions | Observables | Expected detection rule | Expected SOAR or active-response action | Runnable script |
|---|---|---|---|---|---|---|---|
| REGISTER flood | SIPp REGISTER flood using a mounted XML scenario | `T1499` Endpoint Denial of Service | Docker network exists; SIPp image `ngn-sip/sipp:3.7.3` exists; target is lab Kamailio unless `ALLOW_NONLOCAL_TARGET=1`; `REGISTER_RATE`, `DURATION_SECONDS`, and `CONCURRENCY_LIMIT` are positive integers. | `attack_labels` row with `attack_id=sippts_register_flood`; high-rate REGISTER stream; synthetic source markers in `X-Synthetic-Source-IP`; possible 401, 403, 404, 407, or 200 responses. | Suricata `1000004`, `1000009`, `1000010`, `1000014`. Wazuh `100108` if Kamailio emits `NGN-SEC REGISTER` events; Wazuh `100103` if Pike emits blocking logs. | Wazuh SIDs `100103` and `100108` are sent to Shuffle. Wazuh active response runs `kamcmd_block.sh` to set `ban_table[$srcip]=1`; Wazuh `100131` can record later drop hits. | [`attacks/04_dos/sipp_register_flood.sh`](../attacks/04_dos/sipp_register_flood.sh), [`attacks/04_dos/sipp_register_flood.xml`](../attacks/04_dos/sipp_register_flood.xml) |
| INVITE, BYE, NOTIFY, or SUBSCRIBE flood | Planned SIPp or sippts method-flood scenarios | `T1499` Endpoint Denial of Service | No runnable scripts exist under `attacks/04_dos/` today except REGISTER flood. | Planned observables: high-rate method-specific SIP requests from one source. | Wazuh `100111` for INVITE, `100112` for BYE, `100122` for NOTIFY, `100123` for SUBSCRIBE, all conditional on `NGN-SEC` method events. Suricata has no method-specific flood SID except REGISTER and OPTIONS. | Not wired to Shuffle today unless a future rule ID is added to the integration. | Planned, no script exists. |

## Media

| Attack name | Tooling | MITRE ATT&CK technique | Preconditions | Observables | Expected detection rule | Expected SOAR or active-response action | Runnable script |
|---|---|---|---|---|---|---|---|
| Controlled RTP injection | Scapy RTP packet generator inside `rtp_inject.sh` | `T1565` Data Manipulation | Target must be loopback (`127.0.0.1` or `localhost`); RTP ports must stay inside `RTP_PORT_MIN` to `RTP_PORT_MAX`, default `30000` to `30100`; Scapy is required; `CLICKHOUSE_PASSWORD` is required for label emission. | `attack_labels` row with `attack_id=rtp_inject`; UDP RTP packets to selected loopback ports; random sequence, timestamp, and SSRC; optional rtpengine API polling for active call context. | No Suricata RTP SID exists today. Wazuh `100120`, `100121`, and `100134` are candidate detections only if Kamailio or Asterisk logs RTP relay abuse, RTCP anomaly, or strict-RTP failures. | None. Media response is evidence-only until reliable RTP/RTCP detection is implemented. | [`attacks/05_media/rtp_inject.sh`](../attacks/05_media/rtp_inject.sh) |
| RTCP anomaly or media-port sweep | Planned media probe variant | `T1040` Network Sniffing or `T1565` Data Manipulation, depending on payload | No separate runnable script exists under `attacks/05_media/` today. | Planned observables: unexpected RTCP, SSRC mismatch, media-port sweep, or unsolicited RTP across multiple ports. | Wazuh `100120`, `100121`, `100134`. No Suricata RTP/RTCP SID exists today. | None. | Planned, no script exists. |

## Toll Fraud

| Attack name | Tooling | MITRE ATT&CK technique | Preconditions | Observables | Expected detection rule | Expected SOAR or active-response action | Runnable script |
|---|---|---|---|---|---|---|---|
| Premium-prefix dialplan abuse | SIPp container sends one premium-prefix INVITE | `T1496` Resource Hijacking (outcome); access vector may be `T1110`/`T1078` | Docker network exists; SIPp image `ngn-sip/sipp:3.7.3` exists; target is lab Kamailio on `5060`; `PREMIUM_NUMBER` must match `+1900xxxxxxx`; no external PSTN or premium route is allowed. | `attack_labels` row with `attack_id=dialplan_abuse`; INVITE to `sip:+1900...@kamailio`; `User-Agent: ngn-sip-dialplan-abuse`; SIPp may exit non-zero after the expected failed route but still labels the attempt. | Suricata `1000011`, `1000013`, `1000014`. Wazuh `100118`, `100119`, and `100133` when Kamailio or Asterisk logs include the premium destination pattern. | None today. Expected response is manual routing-control review and evidence capture. | [`attacks/06_tollfraud/dialplan_abuse.sh`](../attacks/06_tollfraud/dialplan_abuse.sh) |
| Repeated premium-prefix campaign | Planned loop or multi-number premium INVITE scenario | `T1496` Resource Hijacking | No separate runnable script exists under `attacks/06_tollfraud/` today. | Planned observables: three or more premium-prefix attempts from the same source inside 120 seconds. | Wazuh `100119`; Suricata `1000013` on each matching INVITE. | Not wired to Shuffle today. | Planned, no script exists. |

## Operational Gaps

| Gap | Affected class | Practical consequence |
|---|---|---|
| Label-only wrappers | Reconnaissance and credentials | `sippts_options_scan.sh`, `sipvicious_svmap.sh`, and `sippts_svcrack.sh` emit labels but do not send traffic until the attack image or manual tool execution is provided. |
| Kamailio `NGN-SEC` dependency | Reconnaissance, credentials, injection, denial of service, media, toll fraud | Several Wazuh SIDs exist but require Kamailio logs with the decoder fields `event_type`, `srcip`, `user_agent`, and `reason`. If those logs are absent, Suricata and Asterisk-side Wazuh rules are the implemented evidence path. |
| Media signature coverage | Media | `rtp_inject.sh` is implemented, but there is no Suricata RTP/RTCP SID. Wazuh media SIDs depend on Kamailio or Asterisk log emission. |
| Automated response scope | All classes except credential burst and REGISTER flood | Shuffle and `kamcmd_block.sh` are wired only for Wazuh `100102`, `100103`, `100105`, and `100108`. Other classes are evidence-only today. |
| Attack label naming drift | Reconnaissance and denial of service | `sippts_options_scan.sh` emits `attack_id=sippts_options`, and `sipp_register_flood.sh` emits `attack_id=sippts_register_flood`. Joins against document names must normalize these IDs. |
