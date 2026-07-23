# Kubernetes Migration And VM Hardening

## Status

Compose is the source of truth; the k3s manifests are a later phase, after the
local SIP, attack, IDS, SIEM, and ML flows are stable. This document is the
migration *architecture*: what maps cleanly, the two structural blockers and
their designed solutions, and an honest statement of what is deployable now
versus design-only.

A working Helm chart lives at `helm/ngn-sip/`. It `helm lint`s clean and every
rendered manifest validates against the Kubernetes 1.29 schema
(`kubeconform -strict`). It ships the tiers that map cleanly and renders - but
deliberately does not *certify* - the SIP edge and the active-response path,
because those depend on the redesign described below.

## Deployable-now vs design-only

| Tier | K8s object(s) | Status |
|------|---------------|--------|
| ClickHouse | StatefulSet + 2 PVC, headless Service (8123/9000) | Deployable |
| Postgres (pgvector) | StatefulSet + PVC | Deployable |
| Vector | Deployment + RWO buffer PVC + init-container chown | Deployable* |
| Grafana | Deployment + PVC, provisioning ConfigMaps | Deployable |
| Prometheus | Deployment + PVC | Deployable |
| Keycloak | Deployment + realm ConfigMap | Deployable (dev-mode) |
| Ollama | StatefulSet + models PVC | Deployable (model pulled post-install) |
| stage1-scorer / stage2-worker | Deployment | Deployable* (model artifacts must be supplied) |
| Dashboard (Next.js) | Deployment | Deployable (image must be pushed) |
| Homer (postgres/heplify/hep-bridge/webapp) | StatefulSet + 3 Deployments | Deployable |
| Wazuh indexer | StatefulSet + PVC + cert Job + certs PVC | Deployable (heavy) |
| Wazuh manager + dashboard | - | **Design-only** (Docker-socket sidecars; hardening debt) |
| Kamailio + Suricata edge | 1 Pod, 2 co-containers | **Design-only** (renders; not certified) |
| Active-response / ban path | enforcement sidecar (off by default) | **Design-only** (needs RPC redesign) |

`*` Deployable in isolation, but the full log-flow depends on the shared RWX PVC
and, for asterisk/suricata sources, on the design-only edge pod.

Everything not in the "deployable" rows is intentionally gated off in
`values.yaml` (`tiers.*`) so a reviewer never mistakes a rendered-but-uncertified
workload for a working one.

## Clean mappings (the straightforward 80%)

Every stateless service becomes a Deployment; every stateful one a StatefulSet
with a `volumeClaimTemplate`. Compose specifics carried over verbatim:

- **Security posture is preserved, not dropped.** Each workload keeps
  `cap_drop: ALL` and adds back only the capabilities its Compose service added
  (`capabilities.drop: [ALL]` + `add: [...]`); `no-new-privileges:true` becomes
  `allowPrivilegeEscalation: false`; `read_only: true` becomes
  `readOnlyRootFilesystem: true`; `tmpfs` mounts become `emptyDir{medium:Memory}`
  with the same size caps; the non-root uids (Grafana 472, Vector 65534,
  Prometheus 65534) become `runAsNonRoot` + `runAsUser`. `seccompProfile:
  RuntimeDefault` is added pod-wide as a K8s-native hardening bonus.
- **Cross-service DNS** uses the bare Compose alias as the Service name
  (`clickhouse`, `keycloak`, `ollama`, `postgres`, `shuffle-backend`,
  `kamcmd-relay`, `homer-postgres`, `heplify-server`, ...). Every in-cluster URL
  already baked into the images/configs (`http://clickhouse:8123`,
  `keycloak:8080`, `http://ollama:11434`, `http://shuffle-backend:5001`) resolves
  unchanged inside the release namespace. Compose's secondary aliases
  (`homer-db`, `homer-hep`, `homer-app`) become extra Services with the same
  selector.
- **mem_limit / cpus → resources.** Each Compose ceiling becomes `limits`, with
  conservative `requests`. The notable ceilings are preserved: wazuh-indexer 3Gi
  (for a 1Gi JVM heap + off-heap + Lucene mmap), ollama 10Gi (qwen2.5:7b mmap +
  working set), clickhouse 1536Mi.
- **Bind-mounted configs → ConfigMaps**, mounted read-only at the same paths
  (vector.yaml, prometheus.yml, grafana provisioning, ClickHouse/Postgres init
  SQL, kamailio.cfg + modules, suricata rules, wazuh opensearch.yml). The
  entrypoint `sed`-templating tricks (heplify, homer webapp, wazuh indexer
  hashes, wazuh dashboard OIDC) are reproduced as container `command/args`, so
  secrets stay env-driven instead of baked into a mounted file.
- **Secrets** come from a single `ngn-sip-secrets` Secret rendered from
  `values.secrets` with **placeholder** values. Nothing real is committed. The
  intended production path is a SealedSecret or external-secrets operator that
  populates the same Secret name (`secrets.create: false`).
- **Split-horizon OIDC** (browser → `localhost:8080`, backchannel →
  `keycloak:8080`) is preserved exactly as in Compose, so the tunnel/ingress
  story is unchanged.

## Blocker 1 - the active-response ban path has no Docker socket

**The problem.** Two components enforce bans by shelling into Kamailio over the
Docker socket:

- `siem/wazuh/active-response/autoban_loop.sh` (the `kamailio-autoban` sidecar)
- `soar/kamcmd-relay/relay.py` (the Shuffle Stage-3 executor)

Both ultimately run the identical contract:

```
docker exec <kamailio> /usr/sbin/kamcmd htable.sets ban_table <ip> 1
```

`kamcmd` talks **binrpc over a UNIX socket** - Kamailio's own control interface,
already configured in `infra/kamailio/kamailio.cfg`:

```
loadmodule "ctl.so"
loadmodule "jsonrpcs.so"
modparam("ctl", "binrpc", "unix:/run/kamailio/kamailio_ctl")
```

Kubernetes has **no Docker socket**. A chart that quietly dropped `docker exec`
would leave a ban path that silently no-ops - the SIP source would never actually
be dropped, and the "Defend" arm of the pipeline would be a lie. That is worse
than a documented gap, so it is not shipped as working.

**The designed solution - drive Kamailio's control interface, not Docker.**
Because `ctl.so` + `jsonrpcs.so` are already loaded, the ban *write* itself needs
no new Kamailio capability - only a new *transport path* to reach it:

1. **In-pod enforcement sidecar (same-pod bans).** The Kamailio pod mounts an
   `emptyDir` at `/run/kamailio` shared between the Kamailio container and a small
   enforcement sidecar. The sidecar runs the exact same command against the
   **local UNIX socket** - no Docker, no network:
   ```
   kamcmd -s /run/kamailio/kamailio_ctl htable.sets ban_table <ip> 1
   ```
   This is a byte-for-byte drop-in for the `htable.sets` / `htable.setex` /
   `htable.delete` contract that `relay.py` and `autoban_loop.sh` use today. It is
   scaffolded in `templates/kamailio-edge.yaml` behind
   `edge.enforcementSidecar.enabled` (default **off**), because rendering the
   container is not the same as certifying the closed loop.

2. **Cross-pod bans (Wazuh-manager-driven autoban).** The autoban decision logic
   lives with the Wazuh manager, in a *different* pod, so a shared UNIX socket is
   not available. Here the manager-side enforcer must reach Kamailio's jsonrpc
   over the network. **Prerequisite:** add a network transport for jsonrpc to
   `kamailio.cfg`, e.g. expose it over HTTP via `xhttp` + `jsonrpcs` (or bind
   `ctl` to a TCP socket). The RPC method is unchanged (`htable.sets` with params
   `["ban_table", "<ip>", "1"]`); only the transport is new. Until that config
   change lands and is tested, cross-pod enforcement stays design-only.

3. **The production-grade alternative** (already noted in `autoban_loop.sh`) is
   native Wazuh active-response on a host agent, or a Shuffle SOAR playbook
   calling the jsonrpc endpoint from step 2. Same outcome, no privileged socket.

**Kept intact regardless of transport:** the anti-spoofing `ban_allowlist`
(RFC 3261 §26 - spoofable UDP source), the never-ban protected-container list
(re-expressed as protected Service/Pod IPs), and the ClickHouse `ban_audit`
trail. Those are correctness properties of the response tier, not of the
transport, so they carry over unchanged.

## Blocker 2 - Suricata shares Kamailio's network namespace

**The problem.** Compose runs Suricata with
`network_mode: container:ngn-sip-kamailio-1`, sharing Kamailio's network
namespace so the IDS sees the SIP edge unicast traffic directly. On a plain
bridge, a container only sees its own + broadcast frames, so cross-container SIP
is invisible and the app-layer parser yields zero events (the repo notes a
verified 0 → 24 parsed-events jump once the shared netns was in place).

**The designed solution - one Pod, two co-containers.** In Kubernetes, all
containers in a Pod already share the pod network namespace. So the clean
translation is a single `kamailio` Pod with two containers:

- `kamailio` (the SBC, `NET_BIND_SERVICE` + `NET_RAW`, read-only rootfs)
- `suricata` (the IDS, `NET_ADMIN` + `NET_RAW` + `CHOWN` + `DAC_OVERRIDE`),
  sniffing `eth0` - which *is* Kamailio's interface because they share the netns.

This is a faithful, idiomatic port of `network_mode: container:` and is
implemented in `templates/kamailio-edge.yaml`. It is marked design-only only
because the SIP edge as a whole (media/RTP exposure, SIP `LoadBalancer`/`NodePort`
with UDP, rtpengine advertise-IP handling) has not been validated on a cluster -
not because the co-pod pattern is in doubt. Suricata's `eve.json` is written to
the shared RWX PVC (`subPath: suricata`) so Vector can tail it, replacing the
Compose `suricata_logs` named volume.

## Volumes and the RWX requirement

Compose shares one named volume, `wazuh_manager_logs`, between three writers/
readers on the same Docker host:

- **Wazuh manager** writes `alerts.json`, `ngnsec/kamailio-sec.log` (RW, gid 999)
- **stage1-scorer** appends `ml/stage1.json` (RW, needs `DAC_OVERRIDE`)
- **stage2-worker** tails `alerts.json` (RO)
- **Vector** tails `alerts` + `hep` (RO, joins gid 999 as a supplemental group)

A Docker named volume is node-local by definition, which is why this "just works"
in Compose. On Kubernetes these are **separate Pods that may schedule on
different nodes**, so the shared surface must be a **ReadWriteMany PVC**
(`ngn-sip-shared-logs`). RWX needs a capable provisioner - NFS, Longhorn, or
CephFS. The chart defaults to `accessMode: ReadWriteMany`; consumers join the
Wazuh gid via `fsGroup`/`supplementalGroups` (999), exactly mirroring Compose's
`group_add: "999"` and the ML services' `DAC_OVERRIDE`.

On a **single-node Colima k3s** cluster there is no RWX provisioner, but every
Pod lands on the one node, so `values-colima-k3s.yaml` overrides the access mode
to `ReadWriteOnce` with `local-path`. This is a single-node shim, called out as
such - it is not a multi-node solution. The alternative for multi-node without
RWX is a **logging sidecar** (each producer ships its own logs to Vector/ClickHouse
over the network instead of a shared filesystem), which decouples the tiers at
the cost of a per-Pod sidecar; noted as the scalable option.

Node-local StatefulSet data (ClickHouse, Postgres, Wazuh indexer, Ollama models,
Prometheus TSDB, Grafana, Vector buffer, Homer DB) stays `ReadWriteOnce` - those
are single-writer and correctly map to per-Pod PVCs.

## Bootstrap - the `make bootstrap` equivalents

Compose bootstraps state through entrypoint scripts and `make` targets. On K8s
these become **Jobs**, run as Helm `post-install`/`post-upgrade` hooks
(`templates/bootstrap/jobs.yaml`, gated by `tiers.bootstrapJobs`, hook-weight
ordered):

| Compose mechanism | K8s equivalent |
|-------------------|----------------|
| `scripts/setup_keycloak_sso_clients.sh` | Job `bootstrap-sso-clients` (kcadm.sh against `keycloak:8080`) |
| `scripts/provision_shuffle.sh` | Job `bootstrap-shuffle` (REST import against `shuffle-backend:5001`) |
| Manager entrypoint `register_localfiles.sh` (self-heals `<localfile>`/`<integration>` every start) | Job `bootstrap-wazuh-localfiles`, or bake the same init-script into the manager image |
| `wazuh-certs-generator` (run-once) | Job `wazuh-certs-generator` → shared `wazuh-certs` PVC (idempotent skip if present) |
| `ollama` model pull (`make ml-pull`) | `kubectl exec ollama -- ollama pull <model>` post-install, or a pull Job |
| ClickHouse / Postgres `docker-entrypoint-initdb.d` | ConfigMap-mounted init SQL (runs on first-boot exactly as in Compose) |

The bootstrap Job *bodies* are documented placeholders (they echo the script they
port) so the chart lints and templates without shipping unverified automation
that would masquerade as tested. Porting each script into a small bootstrap image
is the remaining implementation work, not a design gap.

