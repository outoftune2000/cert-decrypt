const LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

type RawLogState = Record<string, unknown>;

type RawCtLog = {
  description: string;
  log_id: string;
  url: string;
  state: RawLogState;
  temporal_interval?: {
    start_inclusive: string;
    end_exclusive: string;
  };
};

type RawCtOperator = {
  name: string;
  logs?: RawCtLog[];
};

type CtLogListPayload = {
  operators: RawCtOperator[];
};

export type CtLogEntry = {
  slug: string;
  logId: string;
  operator: string;
  description: string;
  getEntriesEndpoint: string;
  getSthEndpoint: string;
  temporalStart: string;
  temporalEnd: string;
};

let cachedLogs: CtLogEntry[] | null = null;

const slugifyOperator = (name: string): string =>
  name
    .toLowerCase()
    .replace(/\s*\([^)]*\)/g, "")
    .replace(/[,.]?\s*(inc|llc|ltd|gmbh|co|corp|plc)\.?(\b|$)/gi, "")
    .replace(/'/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

const extractLogName = (description: string): string => {
  const quoted = description.match(/'([^']+)'/)?.[1];
  const source = quoted ?? description;
  return source
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
};

const buildSlug = (operatorName: string, description: string): string =>
  `${slugifyOperator(operatorName)}-${extractLogName(description)}`;

const isUsable = (log: RawCtLog): boolean =>
  typeof log.state === "object" && log.state !== null && "usable" in log.state;

const coversDate = (log: RawCtLog, date: Date): boolean => {
  if (!log.temporal_interval) {
    return false;
  }
  const start = new Date(log.temporal_interval.start_inclusive);
  const end = new Date(log.temporal_interval.end_exclusive);
  return date >= start && date < end;
};

const fetchAllLogs = async (): Promise<CtLogEntry[]> => {
  const response = await fetch(LOG_LIST_URL, {
    headers: { "User-Agent": "yaak", Accept: "*/*" },
    cache: "no-store",
  });

  if (!response.ok) {
    const details = (await response.text()).slice(0, 300);
    throw new Error(`CT log list fetch failed with ${response.status}: ${details}`);
  }

  const payload = (await response.json()) as CtLogListPayload;

  if (!Array.isArray(payload.operators)) {
    throw new Error("CT log list response did not include an operators array.");
  }

  const now = new Date();
  const entries: CtLogEntry[] = [];

  for (const operator of payload.operators) {
    if (!Array.isArray(operator.logs)) {
      continue;
    }

    for (const log of operator.logs) {
      if (!isUsable(log) || !coversDate(log, now) || !log.url || !log.temporal_interval) {
        continue;
      }

      const baseUrl = log.url.endsWith("/") ? log.url : `${log.url}/`;

      entries.push({
        slug: buildSlug(operator.name, log.description),
        logId: log.log_id,
        operator: operator.name,
        description: log.description,
        getEntriesEndpoint: `${baseUrl}ct/v1/get-entries`,
        getSthEndpoint: `${baseUrl}ct/v1/get-sth`,
        temporalStart: log.temporal_interval.start_inclusive,
        temporalEnd: log.temporal_interval.end_exclusive,
      });
    }
  }

  if (entries.length === 0) {
    throw new Error("CT log list contained no usable logs for the current date.");
  }

  return entries;
};

export const resolveAllLogs = async (): Promise<CtLogEntry[]> => {
  if (cachedLogs !== null) {
    return cachedLogs;
  }
  cachedLogs = await fetchAllLogs();
  return cachedLogs;
};

export const resolveLogBySlug = async (slug: string): Promise<CtLogEntry | null> => {
  const logs = await resolveAllLogs();
  return logs.find((l) => l.slug === slug) ?? null;
};
