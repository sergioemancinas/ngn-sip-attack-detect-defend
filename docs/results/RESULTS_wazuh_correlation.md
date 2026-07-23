# Wazuh SIP Correlation Arm, Live Result

This documents the third detection arm of the C3 comparison
(signature vs **correlation/SIEM** vs ML) going from "wired but silent" to
"firing end-to-end on live traffic" on the campus VM.

## What was broken (honest baseline)

The SIP decoder (`siem/wazuh/decoders/kamailio.xml`) and the 35 SIP rules
(`siem/wazuh/rules/sip_rules.xml`, ids 100100..100134) already existed and
passed `wazuh-logtest`, but **no SIP rule had ever fired on live traffic**.
Three independent gaps, each verified and then closed:

1. **Load path.** The manager mounts the custom decoders/rules under
   `etc/decoders/local/` and `etc/rules/local/`, but the default ruleset uses
   `<decoder_dir>etc/decoders</decoder_dir>` / `<rule_dir>etc/rules</rule_dir>`,
   which scan **non-recursively**. The `local/` subdirectory was never loaded,
   so `wazuh-logtest` returned "No decoder matched" against a valid NGN-SEC
   line. Fixed by mounting at the top level (compose change in
   `docker-compose.wazuh.yml`).

2. **No sensor.** The deployed `kamailio.cfg` only proxied to Asterisk and
   emitted zero security telemetry, so the decoder was waiting for log lines
   nothing produced. Added NGN-SEC `xlog` events in the exact format the
   decoder expects (`NGN-SEC <method> src=<ip> ua="<ua>" reason="<reason>"`),
   on malformed SIP (sanity_check failure) and per processed request, tagging
   known scanner User-Agent families. Detection only: the request is still
   proxied so the Suricata signature arm and the ML arm observe identical
   packets. Config validated with `kamailio -c` before deploy.

3. **No ingestion.** Kamailio logs to stderr and there is no syslog daemon in
   its container, so Wazuh could not read it. Added the `kamailio-sec-relay`
   sidecar: it tails the container log via the Docker socket, keeps only
   `NGN-SEC` lines, reformats each as syslog (so the manager predecoder sets
   `program_name=kamailio`), and writes them into the manager log volume. The
   manager ingests the file via a `<localfile>`
   (`siem/wazuh/setup_kamailio_localfile.sh`).

A fourth, smaller fix: rules 100107/100109 blacklisted `friendly-scanner`,
`sipvicious`, `sipsak`, `svmap`, … but **not `pplsip`**, which is the default
User-Agent of sippts, the project's own attack tool. Extended the blacklist to
the sippts family.

## Verified pipeline

```
Kamailio (NGN-SEC xlog)
  -> kamailio-sec-relay (Docker socket tail + syslog reformat)
  -> wazuh_manager_logs:/var/ossec/logs/ngnsec/kamailio-sec.log
  -> manager <localfile> -> logcollector -> analysisd (decoder + SIP rules)
  -> /var/ossec/logs/alerts/alerts.json
  -> Vector -> ClickHouse ngn_sip.wazuh_alerts
```

## Live evidence (campus VM)

Every row below is a real detection that reached `ngn_sip.wazuh_alerts`:

| rule_id | level | MITRE | description | trigger | count in CH |
|---|---|---|---|---|---|
| 100107 | 10 | T1595.001 | Blacklisted SIP scanner User-Agent (pplsip) | `sippts scan` (OPTIONS) | 4 |
| 100109 | 12 | T1595.001 | REGISTER from blacklisted scanner UA | `sippts flood -m REGISTER` | 55,760 |
| 100100 | 5 | T1078 | Kamailio NGN-SEC base event | any NGN-SEC | 1 |

Manager stayed healthy through the flood (≈77k REGISTERs in ~12 s); analysisd
logged no event drops or queue-full conditions.

## A real finding worth reporting (rule shadowing)

The REGISTER flood was expected to fire the flood-frequency rule 100108
(≥30 REGISTER/60 s). It did not: it fired **100109** (scanner-UA, level 12),
once per request, 55,760 times. Reason: every flooded REGISTER also carried the
`pplsip` scanner UA, so each event matched the more specific child rule 100109
rather than the base rule 100100. Rule 100108 keys its composite counter on
`if_matched_sid 100100`, which never accumulated because those events fired
100109 instead. The flood is still detected (as high-severity scanner activity);
it is just attributed to the IOC rule, not the behavioural rule.

This is exactly the kind of IOC-vs-behaviour interaction the C3 comparison
exists to surface: a single IOC (a tool's User-Agent) lets the correlation arm
flag a high-volume attack instantly, but it also means the correlation arm's
detection collapses onto the IOC and the behavioural flood rule is masked. To
exercise the behavioural rules (100108/100111/…) in isolation, replay the flood
with a spoofed legitimate UA (`flood -ua "PolycomVVX"`), so events fall through
to 100100 and the frequency rules accumulate. Tracked as a follow-up.

## Caveats

- The per-request NGN-SEC emit is high volume under flood (one Wazuh event per
  SIP request). For the lab this is acceptable and is itself a measurable SIEM
  property (alert-volume explosion under flood); for a production posture the
  sensor would sample or pre-aggregate, and the relay file needs logrotate.
- The 55,760 flood alerts above come from an ad-hoc functional test, not a
  labelled attack-matrix run. The research evaluation of the correlation arm
  should use a clean `attack_matrix.sh` campaign with the existing
  `attack_labels` so the Wazuh detections join to ground truth the same way the
  Suricata and ML arms do.
- Manager-side state (`ossec.conf` localfile, top-level decoders/rules) lives in
  the container's writable layer; the compose mount change persists the
  decoders/rules across recreate, and `setup_kamailio_localfile.sh` reproduces
  the localfile. The agent `client.keys` also live there, so the running
  manager is treated as authoritative (no casual recreate).

## Reproduction

1. Bring up core SIP + observability + Wazuh on the VM.
2. `docker compose -p ngn-sip -f docker-compose.wazuh.yml up -d kamailio-sec-relay`
3. `bash siem/wazuh/setup_kamailio_localfile.sh`
4. `docker run --rm --network ngn-sip_sip_lab ngn-sip/attacker:v1 scan -i kamailio -r 5060 -p udp`
5. Query `ngn_sip.wazuh_alerts WHERE toUInt32(rule_id) BETWEEN 100100 AND 100199`.
