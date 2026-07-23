import { Badge } from "@/components/ui/Badge";
import { cn } from "@/lib/utils";

const ATTACK_SURFACE = [
  {
    title: "Public SIP edge",
    detail: "SIP 5060 (UDP/TCP), TLS 5061, and RTP media ports reachable from the internet.",
  },
  {
    title: "Exposed methods",
    detail: "REGISTER, INVITE, and OPTIONS accept unauthenticated requests before challenge.",
  },
  {
    title: "Identity / auth",
    detail: "Digest auth on REGISTER and INVITE is the credential boundary attackers probe.",
  },
] as const;

type Layer = "suricata" | "wazuh" | "ml" | "autoban";

const LAYER_STYLE: Record<Layer, { label: string; className: string }> = {
  suricata: { label: "Suricata", className: "border-accent-amber/30 bg-accent-amber/10 text-accent-amber" },
  wazuh: { label: "Wazuh", className: "border-accent/30 bg-accent/10 text-accent" },
  ml: { label: "Stage 1 ML", className: "border-accent-purple/30 bg-accent-purple/10 text-accent-purple" },
  autoban: { label: "autoban", className: "border-accent-red/30 bg-accent-red/10 text-accent-red" },
};

const ATTACK_VECTORS: {
  title: string;
  detail: string;
  layers: Layer[];
  rules: string;
}[] = [
  {
    title: "Scanning / enumeration",
    detail: "OPTIONS sweeps and sippts/sipvicious probes mapping users and extensions.",
    layers: ["suricata", "wazuh"],
    rules: "100107 · 100109",
  },
  {
    title: "REGISTER / INVITE flood (DoS)",
    detail: "High-rate signaling to exhaust the registrar or media plane.",
    layers: ["wazuh", "ml"],
    rules: "100103 · 100108 · 100111",
  },
  {
    title: "Auth brute force",
    detail: "Rapid or low-and-slow digest credential guessing against accounts.",
    layers: ["wazuh", "ml"],
    rules: "100102 · 100106",
  },
  {
    title: "Malformed / injection",
    detail: "Header sanity failures and SDP body injection in INVITE.",
    layers: ["wazuh"],
    rules: "100113-116 · 100117",
  },
  {
    title: "Toll fraud",
    detail: "Premium-prefix INVITE dialing to monetise compromised routing.",
    layers: ["wazuh", "autoban"],
    rules: "100118 · 100119",
  },
  {
    title: "Transport downgrade",
    detail: "Forcing SIP over TCP to strip TLS and enable MITM.",
    layers: ["wazuh"],
    rules: "100130",
  },
];

type RuleRow = {
  id: string;
  level: number;
  name: string;
  behaviour: string;
  mitre: string;
};

const RULE_GROUPS: { heading: string; rules: RuleRow[] }[] = [
  {
    heading: "Baseline and credentials",
    rules: [
      { id: "100100", level: 5, name: "NGN-SEC base event", behaviour: "Parent rule for all Kamailio security events", mitre: "T1078" },
      { id: "100101", level: 5, name: "Digest auth failure", behaviour: "Single failed REGISTER/INVITE digest", mitre: "T1110" },
      { id: "100102", level: 12, name: "Credential brute force (rapid)", behaviour: "5+ auth failures in 60s from same source", mitre: "T1110.001" },
      { id: "100106", level: 10, name: "Credential attack (slow)", behaviour: "12+ auth failures in 600s (low-and-slow spray)", mitre: "T1110.003" },
      { id: "100104", level: 5, name: "Asterisk PJSIP auth failure", behaviour: "Single Asterisk-side digest failure", mitre: "T1110" },
      { id: "100105", level: 12, name: "Asterisk auth burst", behaviour: "5+ PJSIP failures in 60s", mitre: "T1110.001" },
    ],
  },
  {
    heading: "Scanner, flood, and malformed SIP",
    rules: [
      { id: "100107", level: 10, name: "Scanner User-Agent IOC", behaviour: "Blacklisted scanner UA families (sippts, sipvicious, etc.)", mitre: "T1595.001" },
      { id: "100109", level: 12, name: "REGISTER + scanner UA", behaviour: "REGISTER from known scanner User-Agent", mitre: "T1595.001" },
      { id: "100103", level: 10, name: "PIKE rate-limit block", behaviour: "Kamailio PIKE blocked source (REGISTER/INVITE flood)", mitre: "T1499" },
      { id: "100108", level: 12, name: "REGISTER flood", behaviour: "30+ REGISTER events in 60s from one source", mitre: "T1499.002" },
      { id: "100111", level: 12, name: "INVITE flood", behaviour: "40+ INVITE events in 60s", mitre: "T1499.002" },
      { id: "100112", level: 10, name: "BYE flood teardown", behaviour: "25+ BYE events in 60s (session teardown abuse)", mitre: "T1499" },
      { id: "100113-116", level: 10, name: "Malformed headers", behaviour: "Via, CSeq, From, or To header sanity failures", mitre: "T1190" },
    ],
  },
  {
    heading: "Injection, media, toll fraud, response evidence",
    rules: [
      { id: "100117", level: 14, name: "SDP injection in INVITE", behaviour: "Suspicious SDP body patterns in INVITE", mitre: "T1190" },
      { id: "100118", level: 12, name: "Premium-prefix dial (Kamailio)", behaviour: "Toll-fraud destination prefix in INVITE", mitre: "T1496" },
      { id: "100119", level: 14, name: "Repeated premium dial", behaviour: "3+ premium-prefix attempts in 120s", mitre: "T1496" },
      { id: "100120", level: 12, name: "RTP relay abuse", behaviour: "Kamailio RTPengine relay abuse indicator", mitre: "T1040" },
      { id: "100121", level: 10, name: "RTCP anomaly", behaviour: "Media-plane RTCP anomaly from Kamailio", mitre: "T1040" },
      { id: "100130", level: 14, name: "Transport downgrade", behaviour: "SIP-over-TCP downgrade / MITM signal", mitre: "T1557" },
      { id: "100131", level: 10, name: "Ban table hit", behaviour: "Blocked source hit htable ban_table at ingress", mitre: "T1499" },
      { id: "100132", level: 7, name: "SOAR acknowledgement", behaviour: "Shuffle SOAR action ack in Kamailio logs", mitre: "T1499" },
    ],
  },
];

function levelVariant(level: number): "healthy" | "suspicious" | "attack" | "ban" {
  if (level >= 12) return "attack";
  if (level >= 10) return "ban";
  if (level >= 7) return "suspicious";
  return "healthy";
}

function LayerTag({ layer }: { layer: Layer }) {
  const style = LAYER_STYLE[layer];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide",
        style.className,
      )}
    >
      {style.label}
    </span>
  );
}

function MitreTag({ id }: { id: string }) {
  return <span className="mitre-tag">{id}</span>;
}

export function DetectionRulesExplainer() {
  return (
    <div className="space-y-5">
      <ThreatModel />
      <RuleAuthoring />
    </div>
  );
}

function ThreatModel() {
  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 shadow-card">
      <div className="border-b border-surface-border/80 px-5 py-4">
        <h3 className="text-base font-semibold text-text-primary">Threat model and attack surface</h3>
        <p className="mt-1 text-xs text-text-muted">
          What is exposed, how it is attacked, and which detection layer catches each vector
        </p>
      </div>

      <div className="space-y-5 p-5">
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
            Attack surface
          </p>
          <div className="grid gap-3 md:grid-cols-3">
            {ATTACK_SURFACE.map((item) => (
              <div
                key={item.title}
                className="rounded-lg border border-surface-border bg-surface/50 p-3"
              >
                <p className="text-xs font-semibold text-text-primary">{item.title}</p>
                <p className="mt-1.5 text-[11px] leading-relaxed text-text-muted">{item.detail}</p>
              </div>
            ))}
          </div>
        </div>

        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
            Attack vectors mapped to detection layers
          </p>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {ATTACK_VECTORS.map((vector) => (
              <div
                key={vector.title}
                className="flex flex-col rounded-lg border border-surface-border bg-surface/50 p-3 transition-colors hover:border-accent/30"
              >
                <p className="text-xs font-semibold text-text-primary">{vector.title}</p>
                <p className="mt-1.5 flex-1 text-[11px] leading-relaxed text-text-muted">
                  {vector.detail}
                </p>
                <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                  {vector.layers.map((layer) => (
                    <LayerTag key={layer} layer={layer} />
                  ))}
                  <span className="ml-auto font-mono text-[9px] text-text-muted">{vector.rules}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function RuleAuthoring() {
  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 shadow-card">
      <div className="border-b border-surface-border/80 px-5 py-4">
        <h3 className="text-base font-semibold text-text-primary">Wazuh SIEM and rule authoring</h3>
        <p className="mt-1 text-xs text-text-muted">
          Kamailio NGN-SEC ingest, Sigma-first portable intent, Wazuh rules 100100-100199
        </p>
      </div>

      <div className="space-y-5 p-5">
        <div className="grid gap-3 lg:grid-cols-3">
          <div className="rounded-lg border border-surface-border bg-surface/50 p-4 text-xs leading-relaxed">
            <p className="font-semibold text-text-primary">Ingest and decoders</p>
            <p className="mt-2 text-text-muted">
              Kamailio emits NGN-SEC tagged events via{" "}
              <code className="font-mono text-text-secondary">setup_kamailio_localfile.sh</code>.
              Custom Kamailio and Asterisk decoders normalize fields before correlation rules in{" "}
              <code className="font-mono text-text-secondary">sip_rules.xml</code> fire. Agent{" "}
              <span className="font-mono text-text-primary">sip-lab-host</span> collects host
              telemetry on the manager.
            </p>
          </div>
          <div className="rounded-lg border border-accent/25 bg-accent/5 p-4 text-xs leading-relaxed">
            <p className="font-semibold text-text-primary">Sigma-first workflow</p>
            <ol className="mt-2 list-inside list-decimal space-y-1 text-text-muted">
              <li>Author portable rules in siem/sigma/rules/</li>
              <li>Map to Wazuh SIDs via siem/sigma/mapping.md</li>
              <li>Document gaps in conversion_gap_analysis.md</li>
              <li>Enforce in siem/wazuh/rules/sip_rules.xml (Suricata stays packet-native)</li>
            </ol>
          </div>
          <div className="rounded-lg border border-surface-border bg-surface/50 p-4 text-xs leading-relaxed">
            <p className="font-semibold text-text-primary">Levels and enforcement</p>
            <p className="mt-2 text-text-muted">
              SIDs <span className="font-mono">100100-100199</span>: level 5 = parent; 7-9 =
              suspicious; 10-11 = autoban threshold; 12+ = active response. High-confidence rules
              trigger <code className="font-mono text-text-secondary">kamcmd_block.sh</code>;{" "}
              <code className="font-mono text-text-secondary">autoban_loop.sh</code> polls
              rule_level &gt;= 10 as a backstop.
            </p>
          </div>
        </div>

        <div>
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
              Rules catalog (100100-100199)
            </p>
            <div className="flex flex-wrap items-center gap-2 text-[10px] text-text-muted">
              <span className="flex items-center gap-1">
                <Badge variant="suspicious">7-9</Badge> suspicious
              </span>
              <span className="flex items-center gap-1">
                <Badge variant="ban">10-11</Badge> autoban
              </span>
              <span className="flex items-center gap-1">
                <Badge variant="attack">12+</Badge> active response
              </span>
            </div>
          </div>
          {RULE_GROUPS.map((group) => (
            <div key={group.heading} className="mb-4 last:mb-0">
              <p className="mb-2 text-xs font-semibold text-text-primary">{group.heading}</p>
              <div className="-mx-1 overflow-x-auto px-1">
                <table className="rules-catalog-table">
                  <thead>
                    <tr>
                      <th className="col-id numeric">Rule ID</th>
                      <th className="col-level numeric">Level</th>
                      <th className="col-name">Name</th>
                      <th className="col-behaviour">SIP abuse behaviour</th>
                      <th className="col-mitre">MITRE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {group.rules.map((rule) => (
                      <tr key={rule.id}>
                        <td className="col-id numeric font-mono text-[11px] text-text-primary">
                          {rule.id}
                        </td>
                        <td className="col-level numeric">
                          {rule.level > 0 ? (
                            <Badge variant={levelVariant(rule.level)}>{rule.level}</Badge>
                          ) : (
                            "varies"
                          )}
                        </td>
                        <td className="col-name text-text-primary">{rule.name}</td>
                        <td className="col-behaviour text-text-muted">{rule.behaviour}</td>
                        <td className="col-mitre">
                          <MitreTag id={rule.mitre} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
          <p className="text-[10px] leading-relaxed text-text-muted">
            Full range through 100134 with Sigma mappings in siem/sigma/mapping.md. Live hit counts
            appear in the Suricata and Wazuh panels below.
          </p>
        </div>
      </div>
    </div>
  );
}
