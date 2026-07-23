// Server-side IP enrichment for the live honeypot view. Combines geolocation and
// network attribution (ip-api.com) with exposed-service/vuln intel (Shodan InternetDB).
// Both sources are free and key-less; only validated IP literals are ever sent upstream.

const IPV4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const IPV6 = /^[0-9A-Fa-f:]+$/;

export interface ShodanInfo {
  ports: number[];
  cpes: string[];
  tags: string[];
  vulns: string[]; // CVE ids
  hostnames: string[];
}

export interface IpEnrichment {
  ip: string;
  country: string;
  countryCode: string;
  city: string;
  regionName: string;
  lat: number | null;
  lon: number | null;
  isp: string;
  org: string;
  as: string;
  asname: string;
  reverse: string;
  proxy: boolean;
  hosting: boolean;
  mobile: boolean;
  shodan: ShodanInfo | null;
}

const cache = new Map<string, { value: IpEnrichment | null; expires: number }>();
const TTL_MS = 6 * 60 * 60 * 1000;

/** Strip an IPv4-mapped IPv6 prefix and accept only a bare IP literal (SSRF guard). */
export function normalizeIp(rawIp: string): string | null {
  const ip = rawIp.replace(/^::ffff:/i, "").trim();
  if (IPV4.test(ip) || (IPV6.test(ip) && ip.includes(":"))) return ip;
  return null;
}

// Known SIP attack-tool User-Agents. Fingerprinting the scanner is high-signal intel:
// legitimate endpoints never present these.
const SCANNER_UAS: { re: RegExp; tool: string }[] = [
  { re: /friendly-scanner|sipvicious/i, tool: "SIPVicious (svmap/svwar)" },
  { re: /sipsak/i, tool: "sipsak SIP swiss-army tool" },
  { re: /sipcli/i, tool: "sipcli" },
  { re: /sip-?scan/i, tool: "sip-scan" },
  { re: /sundayddr/i, tool: "sundayddr scanner" },
  { re: /vaxsipuseragent/i, tool: "VaxSIP scanner" },
  { re: /pplsip|sippts/i, tool: "sippts toolkit" },
  { re: /sipptk|smap|iWar|warvox/i, tool: "SIP war-dialer" },
];

export function classifyUserAgent(ua: string): { tool: string; isScanner: boolean } {
  const v = (ua || "").trim();
  for (const s of SCANNER_UAS) if (s.re.test(v)) return { tool: s.tool, isScanner: true };
  return { tool: v || "unknown", isScanner: false };
}

async function fetchIpApi(ip: string): Promise<Partial<IpEnrichment> | null> {
  try {
    const fields =
      "status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting,mobile,query";
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=${fields}`, {
      signal: AbortSignal.timeout(6000),
    });
    const j = (await res.json()) as Record<string, unknown>;
    if (!j || j.status !== "success") return null;
    return {
      country: String(j.country ?? ""),
      countryCode: String(j.countryCode ?? ""),
      city: String(j.city ?? ""),
      regionName: String(j.regionName ?? ""),
      lat: typeof j.lat === "number" ? j.lat : null,
      lon: typeof j.lon === "number" ? j.lon : null,
      isp: String(j.isp ?? ""),
      org: String(j.org ?? ""),
      as: String(j.as ?? ""),
      asname: String(j.asname ?? ""),
      reverse: String(j.reverse ?? ""),
      proxy: Boolean(j.proxy),
      hosting: Boolean(j.hosting),
      mobile: Boolean(j.mobile),
    };
  } catch {
    return null;
  }
}

async function fetchShodan(ip: string): Promise<ShodanInfo | null> {
  try {
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(6000) });
    if (!res.ok) return null;
    const j = (await res.json()) as Record<string, unknown>;
    if (!j || j.detail) return null; // "No information available"
    const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);
    return {
      ports: Array.isArray(j.ports) ? j.ports.map((p) => Number(p)).filter((n) => Number.isFinite(n)) : [],
      cpes: arr(j.cpes),
      tags: arr(j.tags),
      vulns: arr(j.vulns),
      hostnames: arr(j.hostnames),
    };
  } catch {
    return null;
  }
}

export async function enrichIp(rawIp: string): Promise<IpEnrichment | null> {
  const ip = normalizeIp(rawIp);
  if (!ip) return null;

  const now = Date.now();
  const cached = cache.get(ip);
  if (cached && cached.expires > now) return cached.value;

  const [geo, shodan] = await Promise.all([fetchIpApi(ip), fetchShodan(ip)]);
  if (!geo) {
    // No geo: still cache a minimal record if Shodan had data, else null.
    const value = shodan
      ? {
          ip,
          country: "",
          countryCode: "",
          city: "",
          regionName: "",
          lat: null,
          lon: null,
          isp: "",
          org: "",
          as: "",
          asname: "",
          reverse: "",
          proxy: false,
          hosting: false,
          mobile: false,
          shodan,
        }
      : null;
    cache.set(ip, { value, expires: now + TTL_MS });
    return value;
  }

  const value: IpEnrichment = {
    ip,
    country: geo.country ?? "",
    countryCode: geo.countryCode ?? "",
    city: geo.city ?? "",
    regionName: geo.regionName ?? "",
    lat: geo.lat ?? null,
    lon: geo.lon ?? null,
    isp: geo.isp ?? "",
    org: geo.org ?? "",
    as: geo.as ?? "",
    asname: geo.asname ?? "",
    reverse: geo.reverse ?? "",
    proxy: Boolean(geo.proxy),
    hosting: Boolean(geo.hosting),
    mobile: Boolean(geo.mobile),
    shodan,
  };
  cache.set(ip, { value, expires: now + TTL_MS });
  return value;
}

/** Datacenter/proxy sources are not legitimate SIP endpoints; useful as a triage hint. */
export function isLikelyAutomated(e: IpEnrichment): boolean {
  return Boolean(e.hosting || e.proxy);
}
