Modular Kamailio configuration snippets included by the top-level `kamailio.cfg`.

| Module | Purpose |
|--------|---------|
| `siptrace.cfg` | HEPv3 capture to heplify-server (C1); gated by `HEP_CAPTURE_ENABLE` |
| `auth.cfg` | Digest authentication (gated) |
| `secfilter.cfg` | Scanner UA block (gated) |
| `pike.cfg` | Rate-based flood detection |
| `ban.cfg` | Reactive ban table |
