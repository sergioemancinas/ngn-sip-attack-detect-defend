"use client";

import { Badge } from "@/components/ui/Badge";

const DECODER_BLOCKS = [
  {
    title: "Scanner UA",
    rules: "100107, 100109",
    level: "10-12",
    mitre: "T1595.001",
  },
  {
    title: "PIKE / REGISTER flood",
    rules: "100103, 100108, 100111",
    level: "10-12",
    mitre: "T1499",
  },
  {
    title: "Malformed SIP",
    rules: "100110, 100113-116",
    level: "10",
    mitre: "T1190",
  },
  {
    title: "Auth brute force",
    rules: "100101, 100102, 100105",
    level: "5-12",
    mitre: "T1110",
  },
  {
    title: "BYE / RTP abuse",
    rules: "100112, 100120, 100121",
    level: "10-12",
    mitre: "T1040",
  },
  {
    title: "Transport downgrade",
    rules: "100130",
    level: "14",
    mitre: "T1557",
  },
] as const;

const RULE_CATALOG = [
  {
    id: "100100",
    level: 5,
    name: "NGN-SEC base event",
    mitre: "T1078",
    category: "base",
  },
  {
    id: "100101",
    level: 5,
    name: "Digest auth failure (single)",
    mitre: "T1110",
    category: "brute-force",
  },
  {
    id: "100102",
    level: 12,
    name: "Credential brute force (rapid)",
    mitre: "T1110.001",
    category: "brute-force",
  },
  {
    id: "100103",
    level: 10,
    name: "PIKE rate-limit flood",
    mitre: "T1499",
    category: "flood",
  },
  {
    id: "100107",
    level: 10,
    name: "Scanner User-Agent IOC",
    mitre: "T1595.001",
    category: "scanner-UA",
  },
  {
    id: "100108",
    level: 12,
    name: "REGISTER flood",
    mitre: "T1499.002",
    category: "flood",
  },
  {
    id: "100110",
    level: 10,
    name: "Malformed SIP request",
    mitre: "T1499",
    category: "malformed",
  },
  {
    id: "100112",
    level: 10,
    name: "BYE flood teardown",
    mitre: "T1499",
    category: "flood",
  },
  {
    id: "100130",
    level: 14,
    name: "Transport downgrade",
    mitre: "T1557",
    category: "transport",
  },
] as const;

function levelVariant(level: number): "healthy" | "suspicious" | "attack" | "ban" {
  if (level >= 12) return "attack";
  if (level >= 10) return "ban";
  if (level >= 7) return "suspicious";
  return "healthy";
}

function MitreTag({ id }: { id: string }) {
  return <span className="mitre-tag">{id}</span>;
}

export function WazuhSetupSection() {
  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-5 shadow-card">
      <h3 className="text-sm font-semibold text-text-primary">Wazuh SIEM architecture</h3>
      <p className="mt-1 text-xs text-text-muted">
        Kamailio NGN-SEC relay, custom decoders, rules 100100-100199, and autoban linkage
      </p>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-surface-border bg-surface/50 p-4 text-xs leading-relaxed">
          <p className="font-semibold text-text-primary">Log path</p>
          <p className="mt-2 text-text-muted">
            Kamailio emits NGN-SEC tagged security events.{" "}
            <code className="font-mono text-text-secondary">setup_kamailio_localfile.sh</code> relays
            them to the Wazuh manager. Custom Kamailio and Asterisk decoders normalize fields before
            correlation rules in{" "}
            <code className="font-mono text-text-secondary">sip_rules.xml</code> fire.
          </p>
        </div>
        <div className="rounded-lg border border-surface-border bg-surface/50 p-4 text-xs leading-relaxed">
          <p className="font-semibold text-text-primary">Host agent</p>
          <p className="mt-2 text-text-muted">
            Agent{" "}
            <span className="font-mono text-text-primary">sip-lab-host</span> (id{" "}
            <span className="font-mono">001</span>) collects host telemetry. SIP correlation consumes
            Kamailio/Asterisk logs ingested via localfile on the manager.
          </p>
        </div>
        <div className="rounded-lg border border-surface-border bg-surface/50 p-4 text-xs leading-relaxed">
          <p className="font-semibold text-text-primary">Active response</p>
          <p className="mt-2 text-text-muted">
            High-confidence rules (100102, 100103, 100105, 100108) can trigger{" "}
            <code className="font-mono text-text-secondary">kamcmd_block.sh</code>. The{" "}
            <code className="font-mono text-text-secondary">autoban_loop.sh</code> backstop polls
            ClickHouse for rule_level &gt;= 10, writes ban_audit, and updates ban_table.
          </p>
        </div>
      </div>

      <div className="mt-4">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
          Custom decoder + rule blocks
        </p>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {DECODER_BLOCKS.map((block) => (
            <div
              key={block.title}
              className="rounded-lg border border-surface-border/80 bg-surface/40 px-3 py-2.5 text-xs transition hover:border-accent/30 hover:bg-surface/60"
            >
              <p className="font-semibold text-text-primary">{block.title}</p>
              <p className="mt-1 font-mono text-[10px] text-text-muted">Rules {block.rules}</p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Badge variant="info">Lv {block.level}</Badge>
                <MitreTag id={block.mitre} />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-4">
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
          Rule catalog (100100-100199 subset)
        </p>
        <div className="-mx-1 overflow-x-auto px-1">
          <table className="rules-catalog-table">
            <thead>
              <tr>
                <th className="col-id numeric">Rule ID</th>
                <th className="col-level numeric">Level</th>
                <th className="col-name">Description</th>
                <th className="col-mitre">MITRE</th>
                <th className="col-category">Category</th>
              </tr>
            </thead>
            <tbody>
              {RULE_CATALOG.map((rule) => (
                <tr key={rule.id}>
                  <td className="col-id numeric font-mono text-[11px]">{rule.id}</td>
                  <td className="col-level numeric">
                    <Badge variant={levelVariant(rule.level)}>{rule.level}</Badge>
                  </td>
                  <td className="col-name text-text-primary">{rule.name}</td>
                  <td className="col-mitre">
                    <MitreTag id={rule.mitre} />
                  </td>
                  <td className="col-category capitalize text-text-muted">{rule.category}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-[10px] text-text-muted">
          Full range 100100-100199 covers scanner-UA IOC, PIKE flood, malformed SIP, brute-force
          bursts, BYE/RTP abuse, and transport downgrade. Live hit counts appear in the Wazuh SIP panel
          below.
        </p>
      </div>
    </div>
  );
}
