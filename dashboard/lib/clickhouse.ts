export interface ClickHouseResult<T> {
  data: T[];
  error?: string;
  empty?: boolean;
}

function getConfig() {
  return {
    url: process.env.CLICKHOUSE_URL ?? "http://clickhouse:8123",
    user: process.env.CLICKHOUSE_USER ?? "ngn",
    password: process.env.CLICKHOUSE_PASSWORD ?? "",
    database: process.env.CLICKHOUSE_DATABASE ?? "ngn_sip",
  };
}

export async function clickhouseQuery<T>(
  query: string,
  params: Record<string, string | number> = {},
): Promise<ClickHouseResult<T>> {
  const { url, user, password, database } = getConfig();
  const searchParams = new URLSearchParams({
    database,
    default_format: "JSONEachRow",
  });

  for (const [key, value] of Object.entries(params)) {
    searchParams.set(`param_${key}`, String(value));
  }

  const auth =
    typeof Buffer !== "undefined"
      ? Buffer.from(`${user}:${password}`).toString("base64")
      : btoa(`${user}:${password}`);

  try {
    const response = await fetch(`${url}/?${searchParams.toString()}`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "text/plain",
      },
      body: query,
      cache: "no-store",
      signal: AbortSignal.timeout(15000),
    });

    if (!response.ok) {
      const text = await response.text();
      return { data: [], error: text.slice(0, 500) };
    }

    const text = (await response.text()).trim();
    if (!text) return { data: [], empty: true };

    const data = text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as T);

    return { data, empty: data.length === 0 };
  } catch (err) {
    return { data: [], error: err instanceof Error ? err.message : String(err) };
  }
}

export async function tableExists(tableName: string): Promise<boolean> {
  const { database } = getConfig();
  const result = await clickhouseQuery<{ c: number }>(
    `SELECT count() AS c FROM system.tables
     WHERE database = {db:String} AND name = {tbl:String}`,
    { db: database, tbl: tableName },
  );
  return (result.data[0]?.c ?? 0) > 0;
}

export async function clickhousePing(): Promise<boolean> {
  const { url } = getConfig();
  try {
    const response = await fetch(`${url}/ping`, {
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    const text = await response.text();
    return response.ok && text.trim() === "Ok.";
  } catch {
    return false;
  }
}
