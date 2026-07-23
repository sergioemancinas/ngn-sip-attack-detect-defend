export interface StackHealthUiLink {
  url: string;
  tunnelPort: number;
}

/**
 * UI links. Most services are fronted by the Caddy reverse proxy on their own
 * *.ngn-sip.lab hostname (all reached over the single 443 -> 3443 tunnel).
 * Keycloak and Ollama are not proxied and use their own forwarded ports.
 */
export const STACK_HEALTH_UI_LINKS: Record<string, StackHealthUiLink> = {
  grafana: { url: "https://grafana.ngn-sip.lab", tunnelPort: 443 },
  wazuh: { url: "https://wazuh.ngn-sip.lab", tunnelPort: 443 },
  keycloak: { url: "http://localhost:8080", tunnelPort: 8080 },
  shuffle: { url: "https://shuffle.ngn-sip.lab", tunnelPort: 443 },
  prometheus: { url: "https://prometheus.ngn-sip.lab", tunnelPort: 443 },
  clickhouse: { url: "https://clickhouse.ngn-sip.lab/play", tunnelPort: 443 },
  ollama: { url: "http://localhost:11434", tunnelPort: 11434 },
};

export const STACK_HEALTH_NO_UI = new Set([
  "kamailio",
  "asterisk",
  "rtpengine",
  "suricata",
  "vector",
]);

export function stackHealthUiLink(component: string): StackHealthUiLink | null {
  return STACK_HEALTH_UI_LINKS[component] ?? null;
}
