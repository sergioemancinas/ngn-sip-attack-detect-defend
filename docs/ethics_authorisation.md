# Ethics and Authorisation Statement: Tier 1 NGN-T1.4

This document defines the authorised security-testing scope for Tier 1 NGN-T1.4 of the SIP Attack-Detect-Defend Pipeline. The project is an academic NGN lab project for TH Koln and is limited to controlled defensive research on infrastructure owned, operated, or explicitly assigned to the project.

## Scope and Authorisation

All Tier 1 activity is restricted to lab targets under project control: local Docker Compose services, loopback-bound development services, and any later TH Koln campus VM only after a hardening review has been completed and approved for that deployment phase. The project does not authorise scanning, probing, fuzzing, credential testing, denial-of-service testing, traffic interception, or attack simulation against third-party systems, public internet hosts, external SIP providers, university infrastructure outside the assigned project environment, or any system where written authorisation is absent.

During development, exposed services must remain bound to loopback or an equivalent private lab interface. Dashboards, SIEM interfaces, databases, management APIs, and observability endpoints must not be publicly reachable. Public exposure is out of scope for Tier 1 unless the campus VM hardening review has passed. That review must confirm the agreed VM posture: UFW default deny, only SIP/SIPS and the required RTP range exposed, SSH key-only on a non-standard port, Fail2Ban enabled, Docker configured so it cannot bypass host firewall policy, and all administrative dashboards reachable only through localhost or an SSH tunnel.

## Data and Safety Rules

Tier 1 uses synthetic data only. Traffic, logs, alerts, SIP registrations, call flows, credentials, extension lists, RTP media, and attack traces must come from project lab tooling. No real customer, provider, employee, student, or third-party communications data is collected or processed. Any credentials used for tests are disposable lab credentials. Any media used for RTP or transcription demonstrations is synthetic or project-created test audio.

The project must not collect third-party personal data, intercept live communications, enumerate external extensions, brute-force external accounts, or preserve accidental third-party traffic. If accidental non-lab traffic is observed, testing stops and the data is excluded from the research dataset.

## Covered Techniques

The proposal names the project's attack coverage as a controlled VoIP kill chain across reconnaissance, credentials, injection, denial of service, media attacks, and toll fraud. For Tier 1, these techniques are covered only as synthetic lab simulations against owned infrastructure.

The MITRE ATT&CK mappings named in the proposal are:

- T1046: SIP service fingerprinting, discovery, and method enumeration using SIPVicious or nmap SIP scripts.
- T1110: lab-only SIP credential brute-force and default-credential testing.
- T1557 and T1557.002: SIP adversary-in-the-middle and ARP-spoofing simulations within an isolated lab network.
- T1498 and T1499: controlled INVITE flood, REGISTER flood, telephony DoS, and SIP stress-test simulations.
- T1190: PROTOS-style malformed SIP parser testing against project-owned services.
- T1078: lab-only registration hijacking or trunk-abuse scenarios using project-created valid accounts.
- T1036: caller-ID spoofing and SIP masquerading tests inside the lab.

## Operating Commitment

The purpose of the work is defensive evaluation: detecting, explaining, and safely blocking SIP abuse in a reproducible NGN lab. Test intensity must stay proportionate to the lab environment, must not degrade non-project systems, and must be stopped immediately if containment assumptions fail. Results may be used in the course report and demonstrations only when they are derived from authorised lab activity and do not expose secrets, real personal data, or third-party systems.
