# 05 - Media

Phase 5 attack scripts. Injects rogue RTP packets into the local lab media port range and writes a ground-truth label to `ngn_sip.attack_labels`.

## Scripts

| Script | Tool | MITRE | Expected detection |
|---|---|---|---|
| `rtp_inject.sh` | Python + Scapy | T1565 | Unexpected RTP SSRC, sequence, payload, or source port on an active media flow |

`rtp_inject.sh` builds RTP packets with a Scapy `RTP` packet class (version 2, configurable payload type) and sends them over a UDP socket to the target media ports. It is strictly loopback-only: it refuses any `TARGET_HOST` or label source that is not `127.*`/`localhost`, and rejects inject ports outside the `RTP_PORT_MIN`..`RTP_PORT_MAX` range (default `30000`..`30100`). Defaults: `PACKET_COUNT=120`, `RATE_PPS=20`/s, `PAYLOAD_SIZE=160`, `SRC_PORT=40000`, `RTP_PAYLOAD_TYPE=0` (PCMU). SSRC, starting sequence, and timestamp are randomized per run.

Optionally, if `RTPENGINE_API_URL` (loopback only) and `WAIT_FOR_CALL_SECONDS>0` are set, the script polls the rtpengine API via httpx to wait for an active media session before injecting; otherwise it runs in blind injection mode. It then emits a label via `attacks.orchestrator.label_emitter` (category `media`, technique `T1565`).

## Run

```bash
python -m attacks.orchestrator.run_phase --phase 5
```

Requires `scapy` on the host Python; `httpx` is only needed for the optional rtpengine-API wait path.
