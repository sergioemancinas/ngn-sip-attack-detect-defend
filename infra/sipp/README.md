# SIPp

SIPp is the traffic generator for the stack. It drives both the benign baseline
and several of the attack scenarios against the Kamailio edge.

- `scenarios/` holds the SIPp XML scenarios (REGISTER, INVITE/200/ACK/BYE call
  flows, and malformed variants).
- `data/` holds the CSV injection files (extensions, credentials) the scenarios
  read from.

The image is built from this context and run as the `sipp` Compose service.
`make smoke` uses it for a registration and call round-trip against the edge.
