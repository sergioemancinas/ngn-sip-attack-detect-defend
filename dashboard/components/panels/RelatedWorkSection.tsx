const METHODOLOGY_REFERENCES = [
  {
    name: "Asgharian et al.",
    href: "https://doi.org/10.1002/sec.1106",
    note: "Windowed SIP-header statistical features with SVM; mirrors this project's 5-minute window feature contract.",
  },
  {
    name: "Hybrid CNN-BLSTM for SIP DDoS flooding",
    href: "https://www.sciencedirect.com/science/article/pii/S1389128623005911",
    note: "Deep sequence model for INVITE, REGISTER, and ACK flooding; contextualises multi-method SIP attack shapes.",
  },
  {
    name: "Linear l1-SVM SIP attack classifier",
    href: "https://www.researchgate.net/publication/334973355",
    note: "Fast linear SVM on high-dimensional SIP n-gram features for malformed and flooding attacks.",
  },
  {
    name: "MDPI survey: countering DoS/DDoS on SIP VoIP",
    href: "https://www.mdpi.com/2079-9292/9/11/1827",
    note: "Survey of SIP-specific DoS/DDoS countermeasures and temporal detection trade-offs.",
  },
  {
    name: "SIP flooding detection, temporal characteristics (IIT INFOCOM 2012)",
    href: "https://ieeexplore.ieee.org/document/6195567",
    note: "Tang, Cheng, and Hao use SIP temporal characteristics and session fingerprints for flooding detection.",
  },
  {
    name: "SIP response-code behaviour profiling",
    href: "https://www.researchgate.net/publication/220701421_SIP-based_VoIP_Traffic_Behavior_Profiling_and_Its_Applications",
    note: "Response-code distributions (including 3xx redirects) signal abnormal call setup; validates this project's C1 response-level feature contribution.",
  },
] as const;

const STANDARDS_REFERENCES = [
  {
    name: "RFC 3261",
    href: "https://www.rfc-editor.org/rfc/rfc3261",
    note: "Session Initiation Protocol semantics for methods, responses, and dialog state.",
  },
  {
    name: "RFC 5390",
    href: "https://www.rfc-editor.org/rfc/rfc5390",
    note: "Requirements for SIP denial-of-service protection; informs PIKE and flood rules.",
  },
  {
    name: "OWASP LLM Top 10",
    href: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    note: "Prompt injection and excessive agency guardrails for Stage 2 advisory triage.",
  },
  {
    name: "MITRE ATT&CK",
    href: "https://attack.mitre.org/",
    note: "Techniques mapped in Wazuh rules: T1110, T1499, T1595, T1040, T1496.",
  },
] as const;

function ReferenceGroup({
  title,
  subtitle,
  items,
}: {
  title: string;
  subtitle: string;
  items: ReadonlyArray<{ name: string; href: string; note: string }>;
}) {
  return (
    <div className="panel-card overflow-hidden">
      <div className="border-b border-surface-border/80 px-5 py-4">
        <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
        <p className="mt-1 text-xs text-text-muted">{subtitle}</p>
      </div>
      <ul className="divide-y divide-surface-border/50">
        {items.map((item) => (
          <li key={item.name}>
            <a
              href={item.href}
              target="_blank"
              rel="noopener noreferrer"
              className="group flex flex-col gap-1 px-5 py-3.5 transition hover:bg-surface-overlay/30 sm:flex-row sm:items-start sm:justify-between sm:gap-4"
            >
              <span className="shrink-0 text-sm font-medium text-text-primary group-hover:text-accent">
                {item.name}
                <span className="ml-1 text-[10px] text-text-muted" aria-hidden>
                  ↗
                </span>
              </span>
              <span className="text-xs leading-relaxed text-text-muted sm:max-w-xl sm:text-right">
                {item.note}
              </span>
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RelatedWorkSection() {
  return (
    <section aria-labelledby="related-work-heading" className="space-y-4">
      <div className="panel-card px-5 py-4">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">
          Academic grounding
        </p>
        <h3 id="related-work-heading" className="mt-1 text-base font-semibold text-text-primary">
          Related work and methodology
        </h3>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-text-secondary">
          Prior SIP intrusion-detection research and industry standards that inform the lab&apos;s
          feature engineering, evaluation protocol, and defensive controls.
        </p>
      </div>

      <ReferenceGroup
        title="Methodology grounding"
        subtitle="Peer-reviewed detection approaches aligned with Stage 1 features and C3 evaluation."
        items={METHODOLOGY_REFERENCES}
      />

      <ReferenceGroup
        title="Standards"
        subtitle="Protocol, security framework, and threat-model references used across the stack."
        items={STANDARDS_REFERENCES}
      />
    </section>
  );
}
