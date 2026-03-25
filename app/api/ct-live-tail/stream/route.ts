import { NextRequest, NextResponse } from "next/server";
import { parseCtEntry } from "@/lib/ctParser";

export const runtime = "nodejs";

type CtProvider = "cloudflare" | "digicert";

type CtEntry = {
  leaf_input: string;
  extra_data: string;
};

type CtEntriesResponse = {
  entries?: CtEntry[];
};

type CtSthResponse = {
  tree_size?: number;
  timestamp?: number;
};

type ProviderConfig = {
  label: string;
  getEntriesEndpoint: string;
  getSthEndpoint: string;
};

type SourceSummary = {
  source: CtProvider;
  providerLabel: string;
  latestIndex: number;
  treeSize: number;
  rangeStart: number;
  rangeEnd: number;
  fetchedCount: number;
  sthTimestamp: string;
  sthFetchMs: number;
  fetchEntriesMs: number;
};

const PROVIDER_CONFIG: Record<CtProvider, ProviderConfig> = {
  cloudflare: {
    label: "Cloudflare",
    getEntriesEndpoint: "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/get-entries",
    getSthEndpoint: "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/get-sth"
  },
  digicert: {
    label: "DigiCert",
    getEntriesEndpoint: "https://wyvern.ct.digicert.com/2026h1/ct/v1/get-entries",
    getSthEndpoint: "https://wyvern.ct.digicert.com/2026h1/ct/v1/get-sth"
  }
};

const MAX_WINDOW_SIZE = 1024;
const MONITOR_INTERVAL_MS = 10_000;

const readLimitParam = (value: string | null): number => {
  if (!value || value.trim().length === 0) {
    return MAX_WINDOW_SIZE;
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error("limit must be a positive whole number.");
  }

  return Math.min(parsed, MAX_WINDOW_SIZE);
};

const readSourcesParam = (value: string | null): CtProvider[] => {
  if (!value || value.trim().length === 0) {
    return ["cloudflare", "digicert"];
  }

  const sourceSet = new Set<CtProvider>();
  value
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .forEach((item) => {
      if (item === "cloudflare" || item === "digicert") {
        sourceSet.add(item);
      }
    });

  const sources = Array.from(sourceSet);
  if (sources.length === 0) {
    throw new Error("sources must include cloudflare and/or digicert.");
  }

  return sources;
};

const writeEvent = <T,>(
  controller: ReadableStreamDefaultController<Uint8Array>,
  encoder: TextEncoder,
  eventName: string,
  data: T
): void => {
  controller.enqueue(encoder.encode(`event: ${eventName}\n`));
  controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
};

const truncate = (value: string, maxLength: number): string =>
  value.length <= maxLength ? value : `${value.slice(0, maxLength - 3)}...`;

const cleanInline = (value: string): string => value.replace(/\s+/g, " ").trim();

const readCn = (distinguishedName: string): string => {
  const match = distinguishedName.match(/(?:^|,\s*)CN=([^,]+)/i);
  return match ? cleanInline(match[1]) : "";
};

const readOrg = (distinguishedName: string): string => {
  const match = distinguishedName.match(/(?:^|,\s*)O=([^,]+)/i);
  return match ? cleanInline(match[1]) : "";
};

const collectDomainPreview = (
  rows: Array<{
    domain_full: string;
    ip_address: string;
  }>
): string => {
  const unique = new Set<string>();

  rows.forEach((row) => {
    if (row.domain_full.trim().length > 0) {
      unique.add(row.domain_full.trim().toLowerCase());
      return;
    }

    if (row.ip_address.trim().length > 0 && row.ip_address !== "::") {
      unique.add(row.ip_address.trim().toLowerCase());
    }
  });

  const values = Array.from(unique);
  if (values.length === 0) {
    return "-";
  }

  return values.slice(0, 4).join(",");
};

const formatDecodedLine = (
  providerLabel: string,
  logIndex: number,
  parsed: {
    timestampIso: string;
    entryTypeLabel: string;
    leafSubject: string;
    leafIssuer: string;
    domains: Array<{
      domain_full: string;
      ip_address: string;
    }>;
  }
): string => {
  const subjectCn = readCn(parsed.leafSubject);
  const subjectOrg = readOrg(parsed.leafSubject);
  const issuerCn = readCn(parsed.leafIssuer);
  const domainsPreview = collectDomainPreview(parsed.domains);

  return [
    `[${providerLabel}]`,
    `idx=${logIndex}`,
    `ts=${parsed.timestampIso}`,
    `type=${parsed.entryTypeLabel}`,
    `cn="${truncate(subjectCn || "-", 90)}"`,
    `org="${truncate(subjectOrg || "-", 80)}"`,
    `issuer_cn="${truncate(issuerCn || "-", 80)}"`,
    `domains=${domainsPreview}`,
    `domain_rows=${parsed.domains.length}`
  ].join(" ");
};

const sleep = async (ms: number): Promise<void> => {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
};

const buildRanges = (start: number, end: number): Array<{ start: number; end: number }> => {
  if (end < start) {
    return [];
  }

  const ranges: Array<{ start: number; end: number }> = [];
  for (let cursor = start; cursor <= end; cursor += MAX_WINDOW_SIZE) {
    ranges.push({
      start: cursor,
      end: Math.min(end, cursor + MAX_WINDOW_SIZE - 1)
    });
  }

  return ranges;
};

const fetchLatestIndex = async (
  source: CtProvider
): Promise<{ treeSize: number; latestIndex: number; timestamp: number; sthFetchMs: number }> => {
  const started = Date.now();
  const config = PROVIDER_CONFIG[source];

  const response = await fetch(config.getSthEndpoint, {
    headers: {
      "User-Agent": "yaak",
      Accept: "*/*"
    },
    cache: "no-store"
  });

  if (!response.ok) {
    const details = (await response.text()).slice(0, 500);
    throw new Error(`${config.label} get-sth failed with ${response.status}: ${details}`);
  }

  const payload = (await response.json()) as CtSthResponse;
  if (typeof payload.tree_size !== "number" || !Number.isSafeInteger(payload.tree_size) || payload.tree_size <= 0) {
    throw new Error(`${config.label} get-sth did not return a valid tree_size.`);
  }

  if (typeof payload.timestamp !== "number" || !Number.isSafeInteger(payload.timestamp) || payload.timestamp <= 0) {
    throw new Error(`${config.label} get-sth did not return a valid timestamp.`);
  }

  return {
    treeSize: payload.tree_size,
    latestIndex: payload.tree_size - 1,
    timestamp: payload.timestamp,
    sthFetchMs: Date.now() - started
  };
};

const fetchEntriesRange = async (
  source: CtProvider,
  start: number,
  end: number
): Promise<{ entries: CtEntry[]; fetchEntriesMs: number }> => {
  const started = Date.now();
  const config = PROVIDER_CONFIG[source];
  const target = new URL(config.getEntriesEndpoint);
  target.searchParams.set("start", String(start));
  target.searchParams.set("end", String(end));

  const response = await fetch(target.toString(), {
    headers: {
      "User-Agent": "yaak",
      Accept: "*/*"
    },
    cache: "no-store"
  });

  if (!response.ok) {
    const details = (await response.text()).slice(0, 500);
    throw new Error(`${config.label} get-entries failed with ${response.status}: ${details}`);
  }

  const payload = (await response.json()) as CtEntriesResponse;
  if (!Array.isArray(payload.entries)) {
    throw new Error(`${config.label} get-entries did not return entries.`);
  }

  const entries = payload.entries.filter(
    (entry): entry is CtEntry =>
      typeof entry?.leaf_input === "string" && typeof entry?.extra_data === "string"
  );

  return {
    entries,
    fetchEntriesMs: Date.now() - started
  };
};

export async function GET(request: NextRequest) {
  let sources: CtProvider[];
  let limit: number;

  try {
    sources = readSourcesParam(request.nextUrl.searchParams.get("sources"));
    limit = readLimitParam(request.nextUrl.searchParams.get("limit"));
  } catch (error) {
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : "Invalid query parameters."
      },
      { status: 400 }
    );
  }

  const encoder = new TextEncoder();
  let cancelled = false;
  request.signal.addEventListener("abort", () => {
    cancelled = true;
  });

  const stream = new ReadableStream<Uint8Array>({
    start: async (controller) => {
      const emit = <T,>(eventName: string, data: T): void => {
        if (cancelled) {
          return;
        }

        try {
          writeEvent(controller, encoder, eventName, data);
        } catch {
          cancelled = true;
        }
      };

      const streamDecodedRange = async (
        source: CtProvider,
        providerLabel: string,
        start: number,
        end: number,
        phase: "initial" | "diff"
      ): Promise<{ fetchedCount: number; decodedCount: number; decodeErrors: number; fetchEntriesMs: number }> => {
        let fetchedCount = 0;
        let decodedCount = 0;
        let decodeErrors = 0;
        let fetchEntriesMs = 0;

        const ranges = buildRanges(start, end);
        for (const range of ranges) {
          if (cancelled) {
            break;
          }

          const fetched = await fetchEntriesRange(source, range.start, range.end);
          fetchEntriesMs += fetched.fetchEntriesMs;
          fetchedCount += fetched.entries.length;

          fetched.entries.forEach((entry, offset) => {
            if (cancelled) {
              return;
            }

            const logIndex = range.start + offset;

            try {
              const parsed = parseCtEntry(entry.leaf_input, entry.extra_data);
              emit("entry", {
                source,
                logIndex,
                phase,
                line: formatDecodedLine(providerLabel, logIndex, parsed)
              });
              decodedCount += 1;
            } catch (decodeError) {
              decodeErrors += 1;
              const message = decodeError instanceof Error ? decodeError.message : "unknown decode error";
              emit("entry", {
                source,
                logIndex,
                phase,
                line: `[${providerLabel}] idx=${logIndex} decode_error="${truncate(cleanInline(message), 180)}"`
              });
            }
          });
        }

        return {
          fetchedCount,
          decodedCount,
          decodeErrors,
          fetchEntriesMs
        };
      };

      try {
        emit("started", {
          sources,
          limit,
          monitorIntervalMs: MONITOR_INTERVAL_MS,
          startedAt: new Date().toISOString()
        });

        const sourceSummaries: SourceSummary[] = [];
        const treeSizeBySource = new Map<CtProvider, number>();
        const latestIndexBySource = new Map<CtProvider, number>();
        let totalDecodedEntries = 0;
        let totalDecodeErrors = 0;

        for (const source of sources) {
          if (cancelled) {
            break;
          }

          const config = PROVIDER_CONFIG[source];

          try {
            const latest = await fetchLatestIndex(source);
            const rangeEnd = latest.latestIndex;
            const rangeStart = Math.max(0, rangeEnd - (limit - 1));
            treeSizeBySource.set(source, latest.treeSize);
            latestIndexBySource.set(source, latest.latestIndex);

            emit("source_meta", {
              source,
              providerLabel: config.label,
              phase: "initial",
              treeSize: latest.treeSize,
              latestIndex: latest.latestIndex,
              start: rangeStart,
              end: rangeEnd,
              sthTimestamp: new Date(latest.timestamp).toISOString(),
              sthFetchMs: latest.sthFetchMs
            });

            const initialRangeResult = await streamDecodedRange(source, config.label, rangeStart, rangeEnd, "initial");
            totalDecodedEntries += initialRangeResult.decodedCount;
            totalDecodeErrors += initialRangeResult.decodeErrors;

            const summary: SourceSummary = {
              source,
              providerLabel: config.label,
              latestIndex: latest.latestIndex,
              treeSize: latest.treeSize,
              rangeStart,
              rangeEnd,
              fetchedCount: initialRangeResult.fetchedCount,
              sthTimestamp: new Date(latest.timestamp).toISOString(),
              sthFetchMs: latest.sthFetchMs,
              fetchEntriesMs: initialRangeResult.fetchEntriesMs
            };

            sourceSummaries.push(summary);

            emit("range_completed", {
              source,
              providerLabel: config.label,
              phase: "initial",
              start: rangeStart,
              end: rangeEnd,
              fetchedCount: initialRangeResult.fetchedCount,
              decodedCount: initialRangeResult.decodedCount,
              decodeErrors: initialRangeResult.decodeErrors,
              fetchEntriesMs: initialRangeResult.fetchEntriesMs
            });
          } catch (sourceError) {
            emit("source_error", {
              source,
              providerLabel: config.label,
              phase: "initial",
              error: "Failed to process source.",
              details: sourceError instanceof Error ? sourceError.message : "Unknown source error."
            });
          }
        }

        emit("monitor_ready", {
          monitorIntervalMs: MONITOR_INTERVAL_MS,
          trackedSources: Array.from(treeSizeBySource.keys()),
          sourceSummaries,
          totalDecodedEntries,
          totalDecodeErrors
        });

        while (!cancelled) {
          await sleep(MONITOR_INTERVAL_MS);
          if (cancelled) {
            break;
          }

          for (const source of sources) {
            if (cancelled) {
              break;
            }

            const previousTreeSize = treeSizeBySource.get(source);
            if (typeof previousTreeSize !== "number") {
              continue;
            }

            const config = PROVIDER_CONFIG[source];

            try {
              const latest = await fetchLatestIndex(source);
              const diff = latest.treeSize - previousTreeSize;

              emit("monitor_tick", {
                source,
                providerLabel: config.label,
                checkedAt: new Date().toISOString(),
                previousTreeSize,
                currentTreeSize: latest.treeSize,
                previousLatestIndex: latestIndexBySource.get(source) ?? previousTreeSize - 1,
                currentLatestIndex: latest.latestIndex,
                diff
              });

              if (diff > 0) {
                const newStart = previousTreeSize;
                const newEnd = latest.treeSize - 1;

                emit("diff_detected", {
                  source,
                  providerLabel: config.label,
                  previousTreeSize,
                  currentTreeSize: latest.treeSize,
                  diff,
                  start: newStart,
                  end: newEnd
                });

                const diffRangeResult = await streamDecodedRange(source, config.label, newStart, newEnd, "diff");
                totalDecodedEntries += diffRangeResult.decodedCount;
                totalDecodeErrors += diffRangeResult.decodeErrors;

                emit("range_completed", {
                  source,
                  providerLabel: config.label,
                  phase: "diff",
                  start: newStart,
                  end: newEnd,
                  fetchedCount: diffRangeResult.fetchedCount,
                  decodedCount: diffRangeResult.decodedCount,
                  decodeErrors: diffRangeResult.decodeErrors,
                  fetchEntriesMs: diffRangeResult.fetchEntriesMs
                });
              } else if (diff < 0) {
                emit("source_warning", {
                  source,
                  providerLabel: config.label,
                  message:
                    "tree_size moved backwards. local baseline will be reset to current tree_size for continued monitoring.",
                  previousTreeSize,
                  currentTreeSize: latest.treeSize
                });
              }

              treeSizeBySource.set(source, latest.treeSize);
              latestIndexBySource.set(source, latest.latestIndex);
            } catch (sourceError) {
              emit("source_error", {
                source,
                providerLabel: config.label,
                phase: "monitor",
                error: "Failed to monitor source.",
                details: sourceError instanceof Error ? sourceError.message : "Unknown monitor error."
              });
            }
          }
        }
      } catch (error) {
        emit("stream_error", {
          error: "CT tail stream failed.",
          details: error instanceof Error ? error.message : "Unknown stream error."
        });
      } finally {
        try {
          controller.close();
        } catch {}
      }
    },
    cancel() {
      cancelled = true;
    }
  });

  return new NextResponse(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive"
    }
  });
}
