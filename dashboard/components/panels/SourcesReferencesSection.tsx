const REFERENCE_GROUPS = [
  {
    title: "Standards and RFCs",
    items: [
      {
        name: "RFC 3261",
        description: "Session Initiation Protocol (SIP) semantics for methods, responses, and dialog state used in rule design.",
        href: "https://www.rfc-editor.org/rfc/rfc3261",
      },
      {
        name: "RFC 5390",
        description: "Requirements for SIP denial-of-service protection; informs PIKE, flood, and rate-limit rules.",
        href: "https://www.rfc-editor.org/rfc/rfc5390",
      },
      {
        name: "RFC 6749 / RFC 8252",
        description: "OAuth 2.0 and authorization for native apps; Keycloak OIDC for dashboard SSO.",
        href: "https://www.rfc-editor.org/rfc/rfc6749",
      },
    ],
  },
  {
    title: "Security frameworks",
    items: [
      {
        name: "OWASP LLM Top 10",
        description: "LLM01 prompt injection, LLM05 improper output handling, LLM08 excessive agency; Stage 2 guardrails.",
        href: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
      },
      {
        name: "MITRE ATT&CK",
        description: "Techniques mapped in Wazuh rules: T1110 credential access, T1499 impact, T1595 reconnaissance, T1040 sniffing, T1496 resource hijacking.",
        href: "https://attack.mitre.org/",
      },
    ],
  },
  {
    title: "Detection and SIEM",
    items: [
      {
        name: "Suricata",
        description: "IDS capturing SIP to sip_events; packet signatures stay native, separate from Sigma log rules.",
        href: "https://suricata.io/",
      },
      {
        name: "Wazuh",
        description: "SIEM manager with custom Kamailio decoders and rules 100100-100199 on the campus VM.",
        href: "https://wazuh.com/",
      },
      {
        name: "Sigma",
        description: "Portable detection rules in siem/sigma/rules/; mapped to Wazuh via mapping.md.",
        href: "https://sigmahq.io/",
      },
    ],
  },
  {
    title: "Machine learning",
    items: [
      {
        name: "XGBoost",
        description: "Stage 1 supervised scorer: multi:softprob, 80 trees, depth 3, learning rate 0.08.",
        href: "https://xgboost.readthedocs.io/",
      },
      {
        name: "Isolation Forest",
        description: "Benign-only unsupervised baseline on the same 22-feature contract.",
        href: "https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html",
      },
      {
        name: "StratifiedGroupKFold",
        description: "Leakage-free CV grouped by src_ip; replaces leaky per-window StratifiedKFold.",
        href: "https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html",
      },
      {
        name: "Bootstrap 95% CI",
        description: "2000 resamples on pooled OOF predictions for honest F1 confidence intervals.",
        href: "https://scikit-learn.org/stable/modules/generated/sklearn.utils.resample.html",
      },
    ],
  },
  {
    title: "Telephony and infrastructure",
    items: [
      {
        name: "Kamailio",
        description: "Session border controller with PIKE, scanner-UA IOC, NGN-SEC logging, and ban_table enforcement.",
        href: "https://www.kamailio.org/",
      },
      {
        name: "RTPengine / media",
        description: "RTP media relay; rtpengine and Asterisk handle media-plane paths.",
        href: "https://github.com/sipwise/rtpengine",
      },
      {
        name: "ClickHouse",
        description: "Analytics store for sip_events, alerts, ml_scores, ban_audit, and soar_cases.",
        href: "https://clickhouse.com/",
      },
      {
        name: "Vector",
        description: "Log shipper from Suricata EVE and service logs into ClickHouse.",
        href: "https://vector.dev/",
      },
      {
        name: "Grafana",
        description: "D1-D7 operational dashboards reading ClickHouse datasources.",
        href: "https://grafana.com/",
      },
      {
        name: "Keycloak",
        description: "OIDC identity provider for dashboard authentication.",
        href: "https://www.keycloak.org/",
      },
      {
        name: "Shuffle SOAR",
        description: "Stage 3 orchestration; cases and notifications to analysts via soar_cases.",
        href: "https://shuffler.io/",
      },
      {
        name: "Ollama (qwen2.5)",
        description: "Local LLM runtime for Stage 2 advisory triage with strict JSON output.",
        href: "https://ollama.com/",
      },
    ],
  },
] as const;

export function SourcesReferencesSection() {
  return (
    <div className="section-stack">
      {REFERENCE_GROUPS.map((group) => (
        <div key={group.title} className="panel-card overflow-hidden">
          <div className="border-b border-surface-border/80 px-5 py-3">
            <h3 className="text-sm font-semibold text-text-primary">{group.title}</h3>
          </div>
          <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-3">
            {group.items.map((item) => (
              <a
                key={item.name}
                href={item.href}
                target="_blank"
                rel="noopener noreferrer"
                className="group rounded-lg border border-surface-border bg-surface/50 p-3 transition duration-300 hover:border-accent/40 hover:bg-surface-overlay/40"
              >
                <p className="text-sm font-semibold text-text-primary group-hover:text-accent">
                  {item.name}
                  <span className="ml-1 text-[10px] text-text-muted" aria-hidden>
                    ↗
                  </span>
                </p>
                <p className="mt-1.5 text-xs leading-relaxed text-text-muted">{item.description}</p>
              </a>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
