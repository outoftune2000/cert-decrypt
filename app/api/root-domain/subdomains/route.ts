import { NextRequest, NextResponse } from "next/server";
import { queryClickHouseJson } from "@/lib/clickhouse";

type CtProvider = "cloudflare" | "digicert";
type SourceFilter = CtProvider | "all";

type SubdomainRow = {
  root_domain: string;
  subdomain: string;
  source: string;
  seen_count: number | string;
  first_seen: string;
  last_seen: string;
  latest_log_index: number | string;
  valid_from_text: string;
  valid_to_text: string;
  is_valid_now: number | string;
  validity_seconds_remaining: number | string;
};

const MULTI_LABEL_TLDS = new Set([
  "ac.uk",
  "co.in",
  "co.jp",
  "co.nz",
  "co.uk",
  "com.au",
  "com.br",
  "com.cn",
  "com.mx",
  "com.sg",
  "gov.uk",
  "net.au",
  "net.in",
  "org.au",
  "org.in",
  "org.uk"
]);

const readSourceFilter = (value: string | null): SourceFilter => {
  if (value === null || value.trim().length === 0) {
    return "all";
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "all" || normalized === "cloudflare" || normalized === "digicert") {
    return normalized;
  }

  throw new Error("source must be all, cloudflare, or digicert.");
};

const toSafeNumber = (value: number | string | null | undefined): number => {
  const parsed = typeof value === "number" ? value : Number(value ?? 0);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.trunc(parsed) : 0;
};

const normalizeRootDomain = (input: string): string => {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) {
    throw new Error("domain is required.");
  }

  const withoutProtocol = trimmed.replace(/^https?:\/\//, "");
  const hostOnly = withoutProtocol.split("/")[0].split("?")[0].split("#")[0];
  const wildcardStripped = hostOnly.replace(/^\*\./, "").replace(/\.$/, "");
  const labels = wildcardStripped.split(".").filter(Boolean);

  if (labels.length === 0) {
    throw new Error("domain must include at least one label.");
  }

  if (labels.length === 1) {
    return labels[0];
  }

  const lastTwo = labels.slice(-2).join(".");
  const tldLabelCount = labels.length >= 3 && MULTI_LABEL_TLDS.has(lastTwo) ? 2 : 1;
  if (labels.length <= tldLabelCount) {
    throw new Error("domain could not be normalized to a root domain.");
  }

  return labels[labels.length - tldLabelCount - 1];
};

const assertSafeRootDomain = (rootDomain: string): void => {
  if (!/^[a-z0-9-]+$/.test(rootDomain)) {
    throw new Error("domain contains unsupported characters after normalization.");
  }
};

const formatRemainingDuration = (seconds: number): string => {
  if (seconds <= 0) {
    return "expired";
  }

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  const parts: string[] = [];
  if (days > 0) {
    parts.push(`${days}d`);
  }
  if (hours > 0) {
    parts.push(`${hours}h`);
  }
  if (minutes > 0) {
    parts.push(`${minutes}m`);
  }
  if (parts.length === 0) {
    parts.push(`${secs}s`);
  }

  return parts.join(" ");
};

export async function GET(request: NextRequest) {
  const domainParam = request.nextUrl.searchParams.get("domain") ?? "";
  let rootDomain: string;
  let source: SourceFilter;

  try {
    rootDomain = normalizeRootDomain(domainParam);
    assertSafeRootDomain(rootDomain);
    source = readSourceFilter(request.nextUrl.searchParams.get("source"));
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Invalid query parameters." },
      { status: 400 }
    );
  }

  const sourceFilterSql = source === "all" ? "" : ` AND source = '${source}'`;

  try {
    const rows = await queryClickHouseJson<SubdomainRow>(`
      WITH grouped AS
      (
        SELECT
          root_domain,
          if(subdomain = '', '@apex', subdomain) AS subdomain,
          if(source = '', 'unknown', source) AS source,
          count() AS seen_count,
          min(event_time) AS first_seen,
          max(event_time) AS last_seen,
          argMax(log_index, tuple(event_time, log_index)) AS latest_log_index,
          argMax(valid_from_dt, tuple(event_time, log_index)) AS valid_from,
          argMax(valid_to_dt, tuple(event_time, log_index)) AS valid_to
        FROM
        (
          SELECT
            root_domain,
            subdomain,
            source,
            log_index,
            ifNull(parseDateTimeBestEffortOrNull(timestamp_utc), inserted_at) AS event_time,
            parseDateTimeBestEffortOrNull(not_before) AS valid_from_dt,
            parseDateTimeBestEffortOrNull(not_after) AS valid_to_dt
          FROM organization_only_records
          WHERE root_domain = '${rootDomain}'${sourceFilterSql}
        )
        WHERE root_domain != ''
        GROUP BY root_domain, subdomain, source
      )
      SELECT
        root_domain,
        subdomain,
        source,
        seen_count,
        toString(first_seen) AS first_seen,
        toString(last_seen) AS last_seen,
        latest_log_index,
        if(isNull(valid_from), '', toString(valid_from)) AS valid_from_text,
        if(isNull(valid_to), '', toString(valid_to)) AS valid_to_text,
        if(isNull(valid_to), 0, valid_to >= now()) AS is_valid_now,
        if(isNull(valid_to) OR valid_to < now(), 0, dateDiff('second', now(), valid_to)) AS validity_seconds_remaining
      FROM grouped
      ORDER BY seen_count DESC, subdomain ASC
      LIMIT 5000
    `);

    const uniqueSubdomains = new Set(rows.map((row) => row.subdomain)).size;
    const totalEvents = rows.reduce((sum, row) => sum + toSafeNumber(row.seen_count), 0);
    const firstSeenValues = rows.map((row) => row.first_seen).filter((value) => value.length > 0);
    const lastSeenValues = rows.map((row) => row.last_seen).filter((value) => value.length > 0);
    const firstSeen = firstSeenValues.length > 0 ? firstSeenValues.sort()[0] : null;
    const lastSeen = lastSeenValues.length > 0 ? lastSeenValues.sort().at(-1) ?? null : null;

    return NextResponse.json({
      requestedDomain: domainParam,
      rootDomain,
      source,
      summary: {
        subdomainSourceRows: rows.length,
        uniqueSubdomains,
        totalEvents,
        firstSeen,
        lastSeen
      },
      rows: rows.map((row) => {
        const validitySecondsRemaining = toSafeNumber(row.validity_seconds_remaining);

        return {
          rootDomain: row.root_domain,
          subdomain: row.subdomain,
          source: row.source,
          seenCount: toSafeNumber(row.seen_count),
          firstSeen: row.first_seen,
          lastSeen: row.last_seen,
          latestIndex: toSafeNumber(row.latest_log_index),
          validFrom: row.valid_from_text || null,
          validTo: row.valid_to_text || null,
          isValidNow: toSafeNumber(row.is_valid_now) === 1,
          validitySecondsRemaining,
          validityRemaining: formatRemainingDuration(validitySecondsRemaining)
        };
      })
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("UNKNOWN_TABLE") || message.includes("doesn't exist")) {
      return NextResponse.json({
        requestedDomain: domainParam,
        rootDomain,
        source,
        summary: {
          subdomainSourceRows: 0,
          uniqueSubdomains: 0,
          totalEvents: 0,
          firstSeen: null,
          lastSeen: null
        },
        rows: []
      });
    }

    return NextResponse.json(
      {
        error: "Failed to query root-domain subdomains from ClickHouse.",
        details: message || "Unknown query error."
      },
      { status: 502 }
    );
  }
}
