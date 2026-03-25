const CLICKHOUSE_URL = process.env.CLICKHOUSE_URL ?? "http://127.0.0.1:8123";
const CLICKHOUSE_USER = process.env.CLICKHOUSE_USER ?? "default";
const CLICKHOUSE_PASSWORD = process.env.CLICKHOUSE_PASSWORD ?? "";
const CLICKHOUSE_ASYNC_INSERT = process.env.CLICKHOUSE_ASYNC_INSERT ?? "1";
const CLICKHOUSE_WAIT_FOR_ASYNC_INSERT = process.env.CLICKHOUSE_WAIT_FOR_ASYNC_INSERT ?? "0";

export const CLICKHOUSE_DATABASE = process.env.CLICKHOUSE_DB ?? "appdb";

type ClickHouseRequestOptions = {
  query: string;
  body?: string;
  contentType?: string;
  settings?: Record<string, string | number | boolean>;
};

const buildAuthHeader = (): string => {
  const token = Buffer.from(`${CLICKHOUSE_USER}:${CLICKHOUSE_PASSWORD}`).toString("base64");
  return `Basic ${token}`;
};

const runClickHouseRequest = async ({
  query,
  body,
  contentType,
  settings
}: ClickHouseRequestOptions): Promise<string> => {
  const target = new URL(CLICKHOUSE_URL);
  target.searchParams.set("database", CLICKHOUSE_DATABASE);
  target.searchParams.set("query", query);
  if (settings) {
    for (const [key, value] of Object.entries(settings)) {
      target.searchParams.set(key, String(value));
    }
  }

  const headers: Record<string, string> = {
    Authorization: buildAuthHeader()
  };

  if (contentType) {
    headers["Content-Type"] = contentType;
  }

  const response = await fetch(target.toString(), {
    method: "POST",
    headers,
    body
  });

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`ClickHouse request failed with ${response.status}: ${text.slice(0, 500)}`);
  }

  return text;
};

export const executeClickHouseCommand = async (query: string): Promise<void> => {
  await runClickHouseRequest({ query });
};

export const executeClickHouseQuery = async (query: string): Promise<string> => {
  return runClickHouseRequest({ query });
};

export const queryClickHouseJson = async <T>(query: string): Promise<T[]> => {
  const normalizedQuery = query.trim();
  const queryWithFormat = /\bFORMAT\s+JSON\b/i.test(normalizedQuery)
    ? normalizedQuery
    : `${normalizedQuery} FORMAT JSON`;

  const responseText = await runClickHouseRequest({ query: queryWithFormat });

  let payload: { data?: T[] };
  try {
    payload = JSON.parse(responseText) as { data?: T[] };
  } catch {
    throw new Error("ClickHouse returned non-JSON data for a JSON query.");
  }

  if (!Array.isArray(payload.data)) {
    throw new Error("ClickHouse JSON response did not include a data array.");
  }

  return payload.data;
};

export const insertJsonEachRow = async (tableName: string, rows: Record<string, unknown>[]): Promise<void> => {
  if (rows.length === 0) {
    return;
  }

  const body = rows.map((row) => JSON.stringify(row)).join("\n");

  await runClickHouseRequest({
    query: `INSERT INTO ${tableName} FORMAT JSONEachRow`,
    body,
    contentType: "application/x-ndjson",
    settings: {
      async_insert: CLICKHOUSE_ASYNC_INSERT,
      wait_for_async_insert: CLICKHOUSE_WAIT_FOR_ASYNC_INSERT
    }
  });
};
