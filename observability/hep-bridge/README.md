# hep-bridge

Bridges Homer's HEP capture into the ClickHouse pipeline. Kamailio's siptrace
duplicates SIP requests and replies (HEPv3) to heplify-server, which stores them
in the Homer Postgres `hep_proto_1_*` tables. `bridge.py` polls those tables,
normalizes each row (reply IPs mapped back to the client address), and writes
newline-delimited JSON to `/logs/hep/events.ndjson`; Vector tails that file into
ClickHouse with `source=hep`. This is what gives Stage-1 its response-level
features (contribution C1).

Why a bridge rather than Vector reading Postgres directly: Vector 0.41 has no
incremental Postgres cursor source, and the bridge also handles rotated
`hep_proto_1_*` tables and reply-IP normalization. See
[`../../docs/C1_HEP_RESPONSE_FEATURES.md`](../../docs/C1_HEP_RESPONSE_FEATURES.md).

Runs as the `hep-bridge` service in `docker-compose.homer.yml`. Config:
`HEP_BRIDGE_OUTPUT` (default `/logs/hep/events.ndjson`) and
`HEP_BRIDGE_POLL_SECONDS` (default `5`).
