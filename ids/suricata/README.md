# Suricata IDS

Suricata is the primary IDS lane for the SIP lab. This stack runs Suricata
7.0.10 in IDS mode on the existing `ngn-sip_sip_lab` network, captures with
AF_PACKET on `any`, and writes EVE JSON alerts to `/var/log/suricata/eve.json`
inside the `ngn-sip-ids_suricata_logs` Docker volume.

## Bring Up

Start the core SIP stack first so the external network and Asterisk log volume
exist:

```sh
make up
make ids-up
make ids-ps
make ids-logs
```

No host ports are published by the IDS stack. The only writable state is the
`suricata_logs` named volume.

To stop it:

```sh
make ids-down
```

## Rules

Local signatures live in `ids/suricata/rules/sip.rules`. The reserved local SID
range for this project is `1000001-1000099`.

Suricata loads only this local SIP rule file:

```yaml
default-rule-path: /etc/suricata/rules
rule-files:
  - sip.rules
```

For rule-only changes, reload the running engine through the command socket:

```sh
docker compose -f docker-compose.ids.yml exec suricata \
  suricatasc -c reload-rules /var/log/suricata/suricata-command.socket
```

If the image does not include `suricatasc`, or if `suricata.yaml` changed,
restart the IDS container instead:

```sh
make ids-down
make ids-up
```

## Vector And ClickHouse

Suricata writes newline-delimited EVE JSON to the `suricata_logs` volume. The
integration point is `observability/vector/vector.yaml`; do not wire it here.
The later Vector change should mount `ngn-sip-ids_suricata_logs` read-only,
add a file source for `/logs/suricata/eve.json`, parse JSON events, and sink
them into ClickHouse beside the existing Asterisk `raw_logs` path.
