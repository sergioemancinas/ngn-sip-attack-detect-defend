# Sigma Detection Layer

This directory contains the portable Sigma layer for the NGN SIP detect/defend lab. It is the vendor-neutral source of truth for log-based SIP detections that map to the existing Wazuh rules in `siem/wazuh/rules/sip_rules.xml`.

The Sigma rules intentionally model the log events emitted by the lab:

- Kamailio NGN-SEC logs expose `event_type`, `srcip`, `user_agent`, and `reason`.
- Asterisk/PJSIP logs expose the decoded Asterisk fields from `siem/wazuh/decoders/asterisk.xml`, mainly `module`, `message`, `endpoint`, and `srcip` where the child decoder extracts it.
- PIKE, ban-table, and SOAR acknowledgement detections use raw log keywords because those events do not expose richer decoded fields today.

## Layout

- `rules/` contains one YAML file per logical detection area.
- `mapping.md` maps each Sigma rule ID to the Wazuh SID or SIDs it represents.
- `conversion_gap_analysis.md` documents where Sigma and Wazuh rule semantics diverge.
- `validate.sh` installs a pinned `sigma-cli` and runs `sigma check` against the rules.

## Validation Tooling

Pinned tools:

- `sigma-cli==3.0.2`: <https://pypi.org/project/sigma-cli/>
- `pySigma==1.3.3`: <https://pypi.org/project/pySigma/>

Run validation from the repository root:

```sh
./siem/sigma/validate.sh
```

The wrapper uses `sigma check --fail-on-error --pass-on-issues siem/sigma/rules`. It validates Sigma parsing and rule structure. It does not prove runtime Wazuh behavior.

## Conversion Approach

Sigma remains the portable log-detection representation. `sigma-cli` and pySigma can convert supported Sigma constructs to supported SIEM backends when an appropriate backend plugin exists.

There is no official pySigma Wazuh backend in the checked ecosystem, so this project does not claim clean Sigma-to-Wazuh auto-generation. The Wazuh XML rules remain native and authoritative for enforcement in the lab. Sigma rules are mapped to those Wazuh rules and highlight where the equivalent logic is single-event, correlation-based, or not cleanly expressible.

Suricata stays native. Sigma describes log events; Suricata SIP rules describe packet signatures and thresholds. Converting Sigma to Suricata is a different detection paradigm and is out of scope for this lab.
