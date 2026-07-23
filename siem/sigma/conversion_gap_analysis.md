# Sigma To Wazuh Conversion Gap Analysis

## Finding

Sigma is useful here as the portable source of truth for log-based SIP detections, but it is not a drop-in Wazuh rule generator. The project keeps Wazuh XML native for enforcement and uses Sigma for portable detection intent, review, and conversion to backends that pySigma actually supports.

## Cited Constraints

- Sigma correlation rules are meta-rules. The current Sigma correlation spec models `event_count` with `rules`, `group-by`, `timespan`, and `condition`, and the Sigma docs state that correlation rules omit `logsource` because they reference base rules: <https://sigmahq.io/docs/meta/correlations.html>
- Wazuh rules are XML rule elements that match raw log text or decoded fields with labels such as `match`, `regex`, and `field`: <https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html>
- Wazuh frequency logic is native Wazuh behavior using `frequency`, `timeframe`, `if_matched_sid`, and same/different field constraints such as `same_field` and `same_srcip`: <https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html>
- pySigma separates backends into dedicated packages. The checked PyPI pySigma page lists supported backend projects such as Splunk, NetWitness, Panther, Elasticsearch/OpenSearch via separate packages, and no official Wazuh backend was identified on PyPI on 2026-05-31: <https://pypi.org/project/pySigma/>

## What Translates Cleanly

| Sigma construct | Wazuh equivalent | Project handling |
|---|---|---|
| Equality on one decoded field, for example `event_type: REGISTER` | `<field name="event_type">REGISTER</field>` | Direct mapping. |
| Regex on one decoded field, for example scanner `user_agent` patterns | `<field name="user_agent" type="pcre2">...</field>` | Direct mapping. |
| AND across decoded fields, for example `event_type` plus `reason` | Multiple Wazuh `<field>` labels in one child rule | Direct mapping. |
| Raw keyword detection for PIKE, ban-table, or SOAR ack logs | Wazuh `<match>` or `<regex>` | Direct mapping when no decoded field exists. |
| Basic severity and MITRE metadata | Wazuh `level`, `group`, and `<mitre>` | Mapped manually in `mapping.md`. |

## What Does Not Translate Cleanly

| Gap | Why it exists | Project handling |
|---|---|---|
| No official Sigma to Wazuh backend | pySigma conversion depends on backend packages. No official Wazuh backend was found in the checked pySigma/PyPI ecosystem. | Do not claim auto-conversion. Keep Wazuh XML native and maintain `mapping.md`. |
| Sigma correlation rules | Sigma `event_count` can describe count logic, but conversion requires backend support for aggregation semantics. | Keep Sigma correlation rules for portable intent. Keep Wazuh `frequency` and `timeframe` rules as the executable lab rules. |
| Cross-field OR | Sigma can express `selection_a or selection_b` across fields. Wazuh is practical for AND across fields and OR inside one field through regex alternation, but not arbitrary Boolean trees in one XML rule. | Split into separate Wazuh rules or use one-field PCRE alternation. Do not compress unrelated logic into one Wazuh rule. |
| Cross-logsource correlation | Sigma can reference multiple base rules in one correlation. Wazuh frequency rules correlate matched Wazuh rules but do not provide a portable multi-logsource expression model. | Keep Kamailio and Asterisk base detections separate. Use native Wazuh child rules where needed. |
| Field extraction mismatch | Sigma can only be defensible when the field exists. The Kamailio decoder exposes only `event_type`, `srcip`, `user_agent`, and `reason`. | Do not invent fields such as SIP destination URI, method, header name, or extension. Encode premium prefixes and malformed headers only when they are present in `reason` or Asterisk `message`. |
| Coordinated /24 grouping | Wazuh SID `100129` escalates repeated `100128` matches but does not extract a dedicated `/24` field. Sigma correlations require a `group-by`. | The Sigma correlation groups by `reason`, because the `/24` metadata is embedded there. This is an approximation until a dedicated decoded field exists. |
| MITRE toll-fraud outcome | Toll-fraud / IRSF is Resource Hijacking (**T1496**): premium-prefix dialing hijacks PBX/trunk resources. Access vectors (**T1110**, **T1078**) are noted in playbook prose only. | Wazuh 100118/100119/100133, Suricata 1000013, Sigma toll-fraud rules, and `docs/03_attack_playbook.md` all tag outcome **T1496**. Resolved 2026-06 (#58). |
| Suricata conversion | Suricata rules are packet signatures and thresholds. Sigma rules are log-event detections. | Out of scope. Suricata stays native under the IDS rule set. |

## Rule Authoring Boundary

The Sigma rules intentionally reference only fields currently decoded by the lab:

- Kamailio NGN-SEC: `event_type`, `srcip`, `user_agent`, `reason`.
- Asterisk/PJSIP: `module`, `message`, `endpoint`, `srcip` when the child decoder extracts it.
- Raw keyword detections only where Wazuh also matches raw log text.

This avoids a common detection-engineering failure mode: writing portable-looking rules that depend on fields the pipeline never emits.
