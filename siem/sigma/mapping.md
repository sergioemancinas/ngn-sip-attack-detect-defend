# Sigma To Wazuh Mapping

This table maps the Sigma rule IDs in `siem/sigma/rules/` to the existing Wazuh SIP rule IDs in `siem/wazuh/rules/sip_rules.xml`.

| Sigma rule | Sigma ID | Wazuh SID(s) | Relation | Attack class | MITRE technique |
|---|---|---|---|---|---|
| Kamailio NGN-SEC Security Event | `bd82bda8-92e1-438d-906a-443f24decaa7` | `100100` | 1:1 | baseline/control-plane | `T1078` |
| Kamailio SIP Authentication Failure | `4f2f979f-1663-4d08-844a-fccd7a3cd093` | `100101` | 1:1 | credentials | `T1110` |
| Rapid Kamailio SIP Credential Brute Force | `666e1914-f1fc-478a-ac17-67ba7e1015b5` | `100102` | 1:1 correlation | credentials | `T1110.001` |
| Low And Slow Kamailio SIP Credential Attack | `461fa0d2-15a9-4762-98ec-5f5b4111fe6e` | `100106` | 1:1 correlation | credentials | `T1110.003` |
| Asterisk PJSIP Authentication Failure | `295d9a3f-a287-4ed4-aaf3-68e87b01a9c3` | `100104` | 1:1 | credentials | `T1110` |
| Asterisk PJSIP Authentication Failure Burst | `db3d41f2-4f63-4ad4-aa8a-78d6bd33ab83` | `100105` | 1:1 correlation | credentials | `T1110.001` |
| Kamailio PIKE Blocked SIP Source | `02afcb00-699a-4830-b383-56c0a94b08d3` | `100103` | 1:1 | dos | `T1499` |
| Blacklisted SIP Scanner User Agent | `f0670df2-2ad2-48f1-95ee-1ab07d0dd09c` | `100107` | 1:1 | recon | `T1595.001` |
| SIP REGISTER From Blacklisted Scanner User Agent | `d3d46fbd-197c-4549-914e-b8e91478f2f2` | `100109` | 1:1 | recon, credentials | `T1595.001` |
| SIP REGISTER With Spoofed Contact Header | `49452e8e-d527-4644-a366-9e151627767b` | `100110` | 1:1 | credentials, injection | `T1036.005` |
| Kamailio NGN-SEC REGISTER Event | `3f1a4a6e-0dd3-4290-b1da-4c82ac69581e` | closest source SID `100100` | no clean Wazuh equivalent as a final alert | source helper | `T1499.002` |
| SIP REGISTER Flood From Single Source | `2e1302e9-276d-47f7-8cc6-cb38a7d07640` | `100108` | 1:1 correlation | dos | `T1499.002` |
| Kamailio NGN-SEC INVITE Event | `703edc29-feef-41c1-ab3d-030b4adf628a` | closest source SID `100100` | no clean Wazuh equivalent as a final alert | source helper | `T1499.002` |
| SIP INVITE Flood From Single Source | `992d0b6f-03f2-43bd-82ab-455dcfe6f909` | `100111` | 1:1 correlation | dos | `T1499.002` |
| Kamailio NGN-SEC BYE Event | `8a58b1a9-006f-484b-b4b3-43d8cfae7376` | closest source SID `100100` | no clean Wazuh equivalent as a final alert | source helper | `T1499` |
| SIP BYE Flood Teardown Abuse | `a891ed1f-199b-4a88-8a75-707331c6230b` | `100112` | 1:1 correlation | dos | `T1499` |
| Malformed SIP Header Indicator | `1844511e-8918-49c5-9471-56d1dc4047ca` | `100113`, `100114`, `100115`, `100116` | 1:many | injection | `T1190` |
| SDP Injection Pattern In SIP INVITE | `f65c2625-579c-468d-aaa8-36ef4f10d95f` | `100117` | 1:1 | injection | `T1190` |
| Kamailio Premium Prefix Toll Fraud Dial Pattern | `0ba81ed3-dfe9-474c-8cce-2ae93a2447fa` | `100118` | 1:1 | tollfraud | `T1496` |
| Repeated Kamailio Premium Prefix Dial Attempts | `45600e00-53ac-449c-b259-63427f9aea32` | `100119` | 1:1 correlation | tollfraud | `T1496` |
| Asterisk Premium Prefix Toll Fraud Dial Pattern | `1cc945c2-cae0-49e5-bf2e-485dbe67c8ba` | `100133` | 1:1 | tollfraud | `T1496` |
| Kamailio RTP Relay Abuse Indicator | `7aec5184-36e3-43c3-b8de-159538b7e9cb` | `100120` | 1:1 | media | `T1040` |
| Asterisk RTP Relay Abuse Indicator | `52b0fd79-4fc7-4a9b-86a7-63aed7030cf2` | `100134` | 1:1 | media | `T1040` |
| Kamailio RTCP Anomaly Indicator | `194a1cce-b955-412d-9f2e-778650afeeef` | `100121` | 1:1 | media | `T1040` |
| Kamailio NGN-SEC NOTIFY Event | `0fb7ec09-35a7-4641-b8a7-228b29a0a4c3` | closest source SID `100100` | no clean Wazuh equivalent as a final alert | source helper | `T1499` |
| SIP NOTIFY Flood From Single Source | `19f19f9d-de7c-46cd-a025-853251e0b42c` | `100122` | 1:1 correlation | dos | `T1499` |
| Kamailio NGN-SEC SUBSCRIBE Event | `193fc11b-60a6-4992-b3a7-b8029f0acaf6` | closest source SID `100100` | no clean Wazuh equivalent as a final alert | source helper | `T1499` |
| SIP SUBSCRIBE Flood From Single Source | `2888b15e-4a4e-4e00-aae2-34b0bf6e09a1` | `100123` | 1:1 correlation | dos | `T1499` |
| Presence Leak SUBSCRIBE Targeting | `d8ab9e3f-eb9c-420d-9be2-53cb277e67f8` | `100124` | 1:1 | recon | `T1595` |
| SIP OPTIONS Keepalive Baseline | `5ecaf025-0d76-4347-9ae1-70483c704675` | `100125` | 1:1 | baseline | `T1071.001` |
| SIP OPTIONS Probe Style Traffic | `315f64cd-a01a-47ba-b4f8-4ffcad33e764` | `100126` | 1:1 | recon | `T1595.001` |
| High Rate SIP OPTIONS Scan Sweep | `8a125947-6171-4765-ab88-12c407b1310b` | `100127` | 1:1 correlation | recon | `T1595.001` |
| Coordinated SIP REGISTER Activity Indicator | `a6272ad3-f609-49c4-a597-fe3442d18738` | `100128` | 1:1 | credentials | `T1110.003` |
| Coordinated SIP REGISTER Campaign Escalation | `83c35da1-eda5-4b95-85ea-23f48795c308` | `100129` | 1:1 correlation with grouping caveat | credentials | `T1110.003` |
| SIP Transport Downgrade Indicator | `6e6dc151-0448-4a63-937a-b8802b5e3476` | `100130` | 1:1 | media | `T1557` |
| Kamailio Ban Table Drop Hit | `089a6934-c652-4b27-8ef2-077022e017c9` | `100131` | 1:1 | response evidence | `T1499` |
| SIP SOAR Action Acknowledgement | `fad0089c-ae8e-495e-b443-bab6f9f687bc` | `100132` | 1:1 | response evidence | `T1499` |

## Coverage Summary

- Wazuh SIDs `100100` through `100134` are covered by Sigma source rules, Sigma detection rules, or Sigma correlation rules.
- Correlation-backed Wazuh rules are represented with Sigma `event_count` meta-rules where Sigma can express the timing intent.
- Helper source rules intentionally map to the Wazuh base event `100100` instead of pretending they are final Wazuh alerts.
- Toll-fraud mappings use **T1496** (Resource Hijacking) as the outcome technique across Wazuh SIDs 100118/100119/100133, Suricata SID 1000013, Sigma rules, and the attack playbook. Credential access (**T1110**) or valid-account abuse (**T1078**) may describe how an attacker gains dial capability but is not the toll-fraud outcome tag.
