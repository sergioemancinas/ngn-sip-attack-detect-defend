# SIP SBC Control Mapping

Hardening evidence for issue #19. This maps each detection and hardening control in the repo
to the threat it mitigates, the MITRE ATT&CK technique, the RFC basis, and the file where it is
implemented. Controls are split into always-on (live in the default runtime: detection and
response) and gated (preventive, off by default; enable procedure in
`docs/security/sbc_hardening_runbook.md`).

Accuracy notes:

- File paths, rule IDs, and gate names are taken directly from the repo.
- MITRE technique IDs in the detection rows are the IDs assigned by the rule authors in
  `siem/wazuh/rules/sip_rules.xml` and `ids/suricata/rules/sip.rules`. The technique names used
  here were checked against `attack.mitre.org` on 2026-06-20 (see References).
- RFC section numbers were checked against the RFC 3261 and RFC 5390 texts on 2026-06-20.

## Always-on controls

| Control | Threat / attack vector | MITRE technique | RFC basis | Implemented in |
|---|---|---|---|---|
| Suricata SIP signatures (network IDS) | Scanner-UA recon, OPTIONS/REGISTER floods, malformed Via/CSeq, INVITE without Contact, REGISTER outside trusted CIDR, long-numeric toll-fraud URIs | T1595 Active Scanning, T1046 Network Service Discovery, T1499 Endpoint Denial of Service, T1190 Exploit Public-Facing Application, T1110 Brute Force, T1496 Resource Hijacking | RFC 3261 Sec 26.1 (threat model); Sec 7 to 8 (message grammar, basis for malformed-header rules) | `ids/suricata/rules/sip.rules` (sids 1000001 to 1000014) |
| NGN-SEC event instrumentation | Telemetry source: emits a structured `NGN-SEC <event_type> src= ua= reason=` line for scanner UA, malformed SIP (sanity), and PIKE flood | n/a (instrumentation that feeds the Wazuh rows below) | RFC 3261 Sec 26.1 (events cover the listed attack classes) | `infra/kamailio/kamailio.cfg` (request_route); decoder `siem/wazuh/decoders/kamailio.xml` |
| Wazuh SIP correlation rules | Brute-force bursts, REGISTER/INVITE/BYE/NOTIFY/SUBSCRIBE floods, scanner UA, malformed headers, SDP injection, toll fraud, RTP/RTCP abuse, presence enumeration, transport downgrade, ban hits | See per-rule table below | RFC 3261 Sec 26.1 (threat model); RFC 5390 (overload) for the flood/rate rules | `siem/wazuh/rules/sip_rules.xml` (SIDs 100100 to 100199) |
| PIKE rate limiting | Volumetric SIP request flood, including UA-spoofed floods | T1499 Endpoint Denial of Service (and T1499.002 Service Exhaustion Flood) | RFC 3261 Sec 26.1.5 (Denial of Service and Amplification), Sec 26.3.2.4 (DoS Protection); RFC 5390 (overload management requirements) | `infra/kamailio/modules/pike.cfg` + `pike_check_req()` in `kamailio.cfg`; detection rule 100103 |
| Autoban active response + ban table | Containment of confirmed high-severity sources at the edge; anti-spoofing of internal/peer addresses | T1499 Endpoint Denial of Service (containment); response to T1110 and T1595.001 sources | RFC 3261 Sec 26.3.2.4 (DoS Protection); Sec 26.1 (UDP source spoofing rationale for the never-ban allowlist) | `siem/wazuh/active-response/autoban_loop.sh` + `modules/ban.cfg` + `modules/htable.cfg`; drop rule 100131; audit `ngn_sip.ban_audit` |

### Per-rule technique mapping (Wazuh `sip_rules.xml`)

| SID | Detection | MITRE technique |
|---|---|---|
| 100100 | Kamailio NGN-SEC base event | T1078 Valid Accounts |
| 100101 | SIP digest auth failure (single) | T1110 Brute Force |
| 100102 | Credential brute force burst (>=5 / 60s) | T1110.001 Password Guessing |
| 100103 | PIKE rate-limit tripped (flood) | T1499 Endpoint Denial of Service |
| 100104 | Asterisk PJSIP auth failure (single) | T1110 Brute Force |
| 100105 | Asterisk auth-failure burst | T1110.001 Password Guessing |
| 100106 | Low-and-slow credential attack | T1110.003 Password Spraying |
| 100107 | Blacklisted scanner User-Agent | T1595.001 Scanning IP Blocks |
| 100108 | REGISTER flood from single source | T1499.002 Service Exhaustion Flood |
| 100109 | REGISTER from scanner User-Agent | T1595.001 Scanning IP Blocks |
| 100110 | REGISTER with spoofed Contact | T1036.005 Match Legitimate Resource Name or Location |
| 100111 | INVITE flood | T1499.002 Service Exhaustion Flood |
| 100112 | BYE-flood teardown abuse | T1499 Endpoint Denial of Service |
| 100113 | Malformed Via header | T1190 Exploit Public-Facing Application |
| 100114 | Malformed CSeq header | T1190 Exploit Public-Facing Application |
| 100115 | Malformed From header | T1190 Exploit Public-Facing Application |
| 100116 | Malformed To header | T1190 Exploit Public-Facing Application |
| 100117 | SDP injection in INVITE | T1190 Exploit Public-Facing Application |
| 100118 | Premium-prefix toll-fraud dial | T1496 Resource Hijacking |
| 100119 | Repeated premium-prefix dialing | T1496 Resource Hijacking |
| 100120 | RTP relay abuse | T1040 Network Sniffing |
| 100121 | RTCP anomaly | T1040 Network Sniffing |
| 100122 | NOTIFY flood | T1499 Endpoint Denial of Service |
| 100123 | SUBSCRIBE flood | T1499 Endpoint Denial of Service |
| 100124 | Presence-leak SUBSCRIBE | T1595 Active Scanning |
| 100125 | OPTIONS keepalive baseline | T1071.001 Web Protocols |
| 100126 | OPTIONS scan candidate (distinct To-URI) | T1595.001 Scanning IP Blocks |
| 100127 | OPTIONS scan escalation | T1595.001 Scanning IP Blocks |
| 100128 | Coordinated /24 REGISTER activity | T1110.003 Password Spraying |
| 100129 | Coordinated REGISTER campaign escalation | T1110.003 Password Spraying |
| 100130 | SIP-over-TCP transport downgrade signal | T1557 Adversary-in-the-Middle |
| 100131 | Kamailio ban_table drop hit | T1499 Endpoint Denial of Service |
| 100132 | SOAR action acknowledgement | T1499 Endpoint Denial of Service |
| 100133 | Asterisk premium-prefix dial pattern | T1496 Resource Hijacking |
| 100134 | Asterisk RTP relay abuse | T1040 Network Sniffing |

## Gated controls (preventive, off by default)

| Control | Gate | Threat / attack vector | MITRE technique | RFC basis | Implemented in |
|---|---|---|---|---|---|
| SIP over TLS / SIPS (5061) | `TLS_ENABLE` | Passive interception and transport downgrade of client-to-edge signaling | T1557 Adversary-in-the-Middle | RFC 3261 Sec 26.2.1 (Transport and Network Layer Security), Sec 26.2.2 (SIPS URI Scheme) | `infra/kamailio/modules/tls.cfg`; complements downgrade-detection rule 100130 |
| Digest authentication (REGISTER) | `AUTH_ENABLE` | Registration hijacking, unauthenticated registration, credential abuse at the edge | T1110 Brute Force; reduces abuse of T1078 Valid Accounts | RFC 3261 Sec 22.4 (Digest Authentication Scheme), Sec 26.2.3 (HTTP Authentication), Sec 26.1.1 (Registration Hijacking), Sec 26.3.2.1 (Registration) | `infra/kamailio/modules/auth.cfg` + `route(SBC_AUTH)` in `kamailio.cfg`; complements detection rules 100101 / 100102 / 100106 |
| Edge request filtering (scanner UA, malformed SIP) | `SECFILTER_ENFORCE` | Scanner reconnaissance and malformed-SIP probing blocked at the edge before relay | T1595.001 Scanning IP Blocks; T1190 Exploit Public-Facing Application | RFC 3261 Sec 26.1 (threat model, preventive edge control); Sec 8 (message validation) | `infra/kamailio/modules/secfilter.cfg` + enforcement block in `kamailio.cfg`; complements detection rules 100107 / 100109 and 100113 to 100116 |
| Topology hiding | `TOPOH_ENABLE` | Reconnaissance of internal routing topology (Via / Record-Route / Contact, internal Asterisk address) | T1590 Gather Victim Network Information (information the control denies) | RFC 3261 Sec 26.1 (threat model); reduces topology disclosure | `infra/kamailio/modules/topoh.cfg` |

The repo uses the define names `TLS_ENABLE`, `AUTH_ENABLE`, `SECFILTER_ENFORCE`, and
`TOPOH_ENABLE` (consistent with the existing `HEP_CAPTURE_ENABLE` convention). None are defined
in `kamailio.cfg`, so every gated control is inert by default.

## Defense-in-depth view

The same SIP attack classes are covered by independent layers, so a gap in one layer does not
remove coverage:

- Reconnaissance (scanner UA, OPTIONS sweeps): Suricata sigs (network), Wazuh 100107 / 100109 /
  100126 / 100127 (correlation), optional secfilter edge block (prevention).
- Flood / DoS: PIKE rate signal (Kamailio), Suricata REGISTER-flood threshold, Wazuh
  100103 / 100108 / 100111 / 100112 / 100122 / 100123, autoban containment.
- Credential attack: Wazuh 100101 / 100102 / 100105 / 100106, optional digest auth at the edge.
- Transport interception: Wazuh 100130 (downgrade signal), optional TLS/SIPS.
- Malformed SIP: Kamailio `sanity_check` drop (always on), Suricata 1000006 to 1000008, Wazuh
  100113 to 100117.

## References

Retrieved 2026-06-20.

- RFC 3261, "SIP: Session Initiation Protocol", Sec 22.4 (Digest Authentication Scheme) and
  Sec 26 (Security Considerations: Threat Model and Security Usage Recommendations), including
  26.1.1 Registration Hijacking, 26.1.5 Denial of Service and Amplification, 26.2.1 Transport
  and Network Layer Security, 26.2.2 SIPS URI Scheme, 26.2.3 HTTP Authentication, 26.3.2.1
  Registration, 26.3.2.4 DoS Protection. https://datatracker.ietf.org/doc/html/rfc3261
- RFC 5390, "Requirements for Management of Overload in the Session Initiation Protocol (SIP)".
  https://datatracker.ietf.org/doc/html/rfc5390
- MITRE ATT&CK Enterprise techniques: T1040 Network Sniffing, T1046 Network Service Discovery,
  T1071.001 Application Layer Protocol: Web Protocols, T1078 Valid Accounts, T1110 Brute Force
  (.001 Password Guessing, .003 Password Spraying), T1190 Exploit Public-Facing Application,
  T1496 Resource Hijacking, T1499 Endpoint Denial of Service (.002 Service Exhaustion Flood),
  T1557 Adversary-in-the-Middle, T1595 Active Scanning (.001 Scanning IP Blocks), T1036.005
  Masquerading: Match Legitimate Resource Name or Location, T1590 Gather Victim Network
  Information. https://attack.mitre.org/techniques/enterprise/
- Kamailio 5.8 module admin guides (config behaviour for the gated modules): tls
  (https://www.kamailio.org/docs/modules/5.8.x/modules/tls.html) and auth_db
  (https://www.kamailio.org/docs/modules/5.8.x/modules/auth_db.html).
