# Architecture

## Deployment View

The full stack runs as one Docker Compose project (`ngn-sip`) with two deployment
targets: local development on Colima, and the campus VM where the SIP edge was
exposed to the internet as a live honeypot. The same images and Compose files are
used in both; only the bind addresses and exposure differ.

```mermaid
flowchart TB
    subgraph LOCAL["Local development — Docker Compose on Colima"]
        L["Full stack: SIP core · Suricata · Wazuh · Vector → ClickHouse ·
        Stage-1/Stage-2 ML · autoban + Shuffle SOAR · Keycloak · Grafana · dashboard"]
        LN["All host ports bound to 127.0.0.1 (loopback-only)"]
    end
    subgraph VM["Campus VM — public deployment (live honeypot)"]
        VS["Same Compose stack"]
        VE["SIP 5060 + RTP range exposed to the internet"]
        VM2["Management planes reached only over SSH tunnels"]
    end
    LOCAL ==>|"same images and compose files"| VM
```

For the component-level data flow (attack → detect → score → respond), see the
architecture diagram in the top-level [`README`](../README.md).

## Call Flow

```mermaid
sequenceDiagram
    participant U0 as SIPp 1000
    participant U1 as SIPp 1001
    participant K as Kamailio
    participant A as Asterisk

    U1->>K: REGISTER 1001
    K->>A: REGISTER 1001
    A-->>K: 401 challenge
    K-->>U1: 401 challenge
    U1->>K: REGISTER + digest auth
    K->>A: REGISTER + digest auth
    A-->>K: 200 OK
    K-->>U1: 200 OK

    U0->>K: REGISTER 1000
    K->>A: REGISTER 1000
    A-->>K: 200 OK after digest auth
    K-->>U0: 200 OK

    U0->>K: INVITE sip:1001
    K->>A: INVITE sip:1001
    A->>U1: INVITE to registered contact
    U1-->>A: 180 Ringing / 200 OK
    A-->>K: 200 OK
    K-->>U0: 200 OK
    U0->>K: ACK, then BYE
```

## Notes

Kamailio acts as a forwarding SIP edge while subscriber authentication stays in Asterisk. This is deliberate: it keeps the edge policy (Pike, SecFilter, the ban table) separate from PBX authentication. Homer HEP capture and rtpengine media handling are part of the delivered stack.

<!-- TODO: expand this into deployment, data-flow, and control-flow views after smoke testing. -->
