# Security

Defense-in-depth notes for the stack: edge hardening, container isolation,
identity, detection-and-response, secrets, and the supply-chain/CI gates.

## Security architecture (defense in depth)

```mermaid
flowchart TB
    subgraph L1["1 · Network / edge"]
      LB["Management planes bound to 127.0.0.1<br/>reached over SSH tunnels; Caddy tls internal"]
      SBC["Kamailio SBC hardening<br/>PIKE + secfilter + ban_table + allowlist"]
    end
    subgraph L2["2 · Container isolation"]
      C["no-new-privileges · cap_drop ALL<br/>read-only rootfs · non-root uids · pinned image digests"]
    end
    subgraph L3["3 · Identity"]
      KC["Keycloak OIDC SSO<br/>Wazuh · Grafana · Homer · dashboard"]
    end
    subgraph L4["4 · Detect and respond"]
      DET["Suricata + Wazuh"]
      RESP["autoban + graded Shuffle SOAR<br/>ban_table + ban_audit"]
    end
    subgraph L5["5 · Secrets"]
      SEC[".env placeholders only<br/>no secrets in the repo · Gitleaks gate"]
    end
    subgraph L6["6 · Supply chain / CI"]
      CI["Aikido (SAST/SCA/IaC) · Trivy · Docker Scout<br/>Dependabot · release SBOM · OpenSSF Scorecard"]
    end

    L1 --> L2 --> L3
    DET --> RESP
    L5 --> L6
```

## Contents

| Document | Covers |
|---|---|
| [`control_mapping.md`](control_mapping.md) | Hardening commits mapped to CIS / BSI IT-Grundschutz controls |
| [`sbc_hardening_runbook.md`](sbc_hardening_runbook.md) | Kamailio SBC hardening and enablement steps |
| [`oauth_hardening_checklist.md`](oauth_hardening_checklist.md) | OAuth 2.0 / OIDC hardening against the current Keycloak setup |
| [`keycloak_oidc.md`](keycloak_oidc.md) | Keycloak OIDC design for the SOC tools |
| [`wazuh_4.14_tls_setup.md`](wazuh_4.14_tls_setup.md) | Wazuh indexer TLS + security-plugin configuration |
| [`suricata_design.md`](suricata_design.md) | Suricata IDS design and rule posture |
| [`homer_design.md`](homer_design.md) | Homer / HEP capture design |
| [`local_development_exposure.md`](local_development_exposure.md) | Loopback-only local-development policy |
| [`container_security_automation.md`](container_security_automation.md) | The CI/local vulnerability-gate stack (Aikido, Trivy, Docker Scout) and its boundary with Wazuh/Shuffle |
| [`scout_triage_README.md`](scout_triage_README.md) | Docker Scout CVE-triage pipeline |
| [`docker_image_review.md`](docker_image_review.md) | Docker Scout image findings and remediation notes |
| [`asterisk_advisory_review.md`](asterisk_advisory_review.md) | Asterisk advisories mapped to the build and runtime posture |

Before exposing anything beyond loopback, follow
[`../INTERNET_EXPOSURE.md`](../INTERNET_EXPOSURE.md).
