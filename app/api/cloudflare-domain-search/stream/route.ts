import { NextRequest, NextResponse } from "next/server";
import { X509Certificate } from "crypto";

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

type MatchRow = {
  logIndex: number;
  matchedDomain: string;
  domainFull: string;
  domainBase: string;
  rootDomain: string;
  subdomain: string;
  timestampIso: string;
  entryType: string;
  organization: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  serialNumber: string;
};

type BatchSpec = {
  batchNumber: number;
  start: number;
  end: number;
};

type BatchFetchResult = {
  spec: BatchSpec;
  entries: CtEntry[];
  fetchMs: number;
};

type BatchTelemetry = {
  batchNumber: number;
  start: number;
  end: number;
  entriesFetched: number;
  fetchMs: number;
  processMs: number;
  matchCount: number;
  decodeErrors: number;
};

const CLOUDFLARE_GET_ENTRIES = "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/get-entries";
const CLOUDFLARE_GET_STH = "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/get-sth";
const WINDOW_SIZE = 1024;
const DEFAULT_BATCHES = 100;
const FETCH_CONCURRENCY = 10;

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

const normalizeDomain = (input: string): string => {
  const trimmed = input.trim().toLowerCase();
  const withoutProtocol = trimmed.replace(/^https?:\/\//, "");
  const hostOnly = withoutProtocol.split("/")[0].split("?")[0].split("#")[0];
  return hostOnly.replace(/^\*\./, "").replace(/\.$/, "");
};

const readMaxBatches = (value: string | null): number => {
  if (value === null || value.trim().length === 0) {
    return DEFAULT_BATCHES;
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error("maxBatches must be a positive whole number.");
  }

  return parsed;
};

const buildBatchSpecs = (latestIndex: number, maxBatches: number): BatchSpec[] => {
  const specs: BatchSpec[] = [];

  for (let batchNumber = 1; batchNumber <= maxBatches; batchNumber += 1) {
    const end = latestIndex - (batchNumber - 1) * WINDOW_SIZE;
    if (end < 0) {
      break;
    }

    const start = Math.max(0, end - (WINDOW_SIZE - 1));
    specs.push({
      batchNumber,
      start,
      end
    });
  }

  return specs;
};

const readUint24 = (bytes: Buffer, offset: number): number => {
  if (offset + 3 > bytes.length) {
    throw new Error("Unexpected end of data while reading uint24.");
  }

  return (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
};

const decodeBase64 = (value: string): Buffer => {
  const compact = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const missing = compact.length % 4;
  const padded = missing === 0 ? compact : compact + "=".repeat(4 - missing);
  return Buffer.from(padded, "base64");
};

const getCtTimestampIso = (leafBytes: Buffer): string => {
  if (leafBytes.length < 10) {
    return "Invalid timestamp";
  }

  let timestampMs = 0n;
  for (let i = 2; i < 10; i += 1) {
    timestampMs = (timestampMs << 8n) | BigInt(leafBytes[i]);
  }

  const asNumber = Number(timestampMs);
  return Number.isFinite(asNumber) ? new Date(asNumber).toISOString() : "Invalid timestamp";
};

const extractLeafCertDer = (leafBytes: Buffer, extraBytes: Buffer): { der: Buffer; entryTypeLabel: string } => {
  const entryType = (leafBytes[10] << 8) | leafBytes[11];

  if (entryType === 0) {
    const certLength = readUint24(leafBytes, 12);
    const certStart = 15;
    const certEnd = certStart + certLength;
    if (certEnd > leafBytes.length) {
      throw new Error("Leaf certificate length exceeds available bytes.");
    }

    return {
      der: leafBytes.subarray(certStart, certEnd),
      entryTypeLabel: "x509_entry"
    };
  }

  if (entryType === 1) {
    const precertLength = readUint24(extraBytes, 0);
    const certStart = 3;
    const certEnd = certStart + precertLength;
    if (certEnd > extraBytes.length) {
      throw new Error("Precertificate length exceeds available bytes.");
    }

    return {
      der: extraBytes.subarray(certStart, certEnd),
      entryTypeLabel: "precert_entry"
    };
  }

  throw new Error(`Unsupported CT entry type: ${entryType}`);
};

const parseDnsSans = (subjectAltName: string | undefined): string[] => {
  if (!subjectAltName) {
    return [];
  }

  return subjectAltName
    .split(/,\s*/)
    .map((part) => part.trim())
    .filter((part) => part.toUpperCase().startsWith("DNS:"))
    .map((part) => part.slice(4).toLowerCase())
    .filter((part) => part.length > 0);
};

const extractDnValue = (dn: string | undefined, key: string): string => {
  if (typeof dn !== "string" || dn.length === 0) {
    return "";
  }

  const pattern = new RegExp(`(?:^|[\\n,])\\s*${key}=([^,\\n]+)`, "i");
  const match = dn.match(pattern);
  return match ? match[1].trim() : "";
};

const isDomainMatch = (candidate: string, requestedDomain: string): boolean => {
  const normalizedCandidate = candidate.trim().toLowerCase().replace(/^\*\./, "");
  return normalizedCandidate === requestedDomain || normalizedCandidate.endsWith(`.${requestedDomain}`);
};

const extractDomainParts = (matchedDomain: string): { domainBase: string; rootDomain: string; subdomain: string } => {
  const host = matchedDomain.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  const labels = host.split(".").filter(Boolean);

  if (labels.length < 2) {
    return {
      domainBase: host,
      rootDomain: host,
      subdomain: ""
    };
  }

  const lastTwo = labels.slice(-2).join(".");
  const tldLabelCount = labels.length >= 3 && MULTI_LABEL_TLDS.has(lastTwo) ? 2 : 1;

  if (labels.length <= tldLabelCount) {
    return {
      domainBase: host,
      rootDomain: host,
      subdomain: ""
    };
  }

  const tld = labels.slice(-tldLabelCount).join(".");
  const root = labels[labels.length - tldLabelCount - 1];
  const domainBase = `${root}.${tld}`;
  const subdomain = labels.slice(0, labels.length - tldLabelCount - 1).join(".");

  return {
    domainBase,
    rootDomain: root,
    subdomain
  };
};

const formatDateTimeUtc = (date: Date): string => {
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  const iso = date.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)}`;
};

const fetchLatestIndex = async (): Promise<{ treeSize: number; latestIndex: number; timestamp: number; sthMs: number }> => {
  const started = Date.now();

  const response = await fetch(CLOUDFLARE_GET_STH, {
    headers: {
      "User-Agent": "yaak",
      Accept: "*/*"
    },
    cache: "no-store"
  });

  if (!response.ok) {
    const details = (await response.text()).slice(0, 500);
    throw new Error(`Cloudflare get-sth failed with ${response.status}: ${details}`);
  }

  const payload = (await response.json()) as CtSthResponse;
  if (typeof payload.tree_size !== "number" || !Number.isSafeInteger(payload.tree_size) || payload.tree_size <= 0) {
    throw new Error("Cloudflare get-sth response did not include a valid tree_size.");
  }

  if (typeof payload.timestamp !== "number" || !Number.isSafeInteger(payload.timestamp) || payload.timestamp <= 0) {
    throw new Error("Cloudflare get-sth response did not include a valid timestamp.");
  }

  return {
    treeSize: payload.tree_size,
    latestIndex: payload.tree_size - 1,
    timestamp: payload.timestamp,
    sthMs: Date.now() - started
  };
};

const fetchEntriesBatch = async (spec: BatchSpec): Promise<BatchFetchResult> => {
  const fetchStarted = Date.now();
  const target = new URL(CLOUDFLARE_GET_ENTRIES);
  target.searchParams.set("start", String(spec.start));
  target.searchParams.set("end", String(spec.end));

  const response = await fetch(target.toString(), {
    headers: {
      "User-Agent": "yaak",
      Accept: "*/*"
    },
    cache: "no-store"
  });

  if (!response.ok) {
    const details = (await response.text()).slice(0, 500);
    throw new Error(
      `Cloudflare get-entries failed for batch ${spec.batchNumber} (${spec.start}-${spec.end}) with ${response.status}: ${details}`
    );
  }

  const payload = (await response.json()) as CtEntriesResponse;
  if (!Array.isArray(payload.entries)) {
    throw new Error(`Cloudflare get-entries for batch ${spec.batchNumber} did not return entries.`);
  }

  const entries = payload.entries.filter(
    (entry): entry is CtEntry =>
      typeof entry?.leaf_input === "string" && typeof entry?.extra_data === "string"
  );

  return {
    spec,
    entries,
    fetchMs: Date.now() - fetchStarted
  };
};

const writeEvent = <T>(
  controller: ReadableStreamDefaultController<Uint8Array>,
  encoder: TextEncoder,
  eventName: string,
  data: T
): void => {
  controller.enqueue(encoder.encode(`event: ${eventName}\n`));
  controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
};

export async function GET(request: NextRequest) {
  const rawDomain = request.nextUrl.searchParams.get("domain") ?? "";

  let requestedDomain: string;
  let maxBatches: number;

  try {
    requestedDomain = normalizeDomain(rawDomain);
    if (requestedDomain.length === 0) {
      throw new Error("domain is required.");
    }

    maxBatches = readMaxBatches(request.nextUrl.searchParams.get("maxBatches"));
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Invalid query parameters." },
      { status: 400 }
    );
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start: async (controller) => {
      const apiStarted = Date.now();

      try {
        writeEvent(controller, encoder, "started", {
          requestedDomain,
          maxBatchesRequested: maxBatches,
          fetchConcurrency: FETCH_CONCURRENCY,
          windowSize: WINDOW_SIZE
        });

        const sth = await fetchLatestIndex();
        const batchSpecs = buildBatchSpecs(sth.latestIndex, maxBatches);

        writeEvent(controller, encoder, "sth", {
          latestTreeSize: sth.treeSize,
          latestIndex: sth.latestIndex,
          sthTimestamp: new Date(sth.timestamp).toISOString(),
          sthMs: sth.sthMs,
          totalBatchSpecs: batchSpecs.length
        });

        let searchedBatches = 0;
        let searchedEntries = 0;
        let decodeErrors = 0;
        let fetchMsTotal = 0;
        let processingMsTotal = 0;

        const matches: MatchRow[] = [];
        const telemetry: BatchTelemetry[] = [];
        let found = false;

        for (let offset = 0; offset < batchSpecs.length; offset += FETCH_CONCURRENCY) {
          const wave = batchSpecs.slice(offset, offset + FETCH_CONCURRENCY);
          const fetchedWave = await Promise.all(wave.map((spec) => fetchEntriesBatch(spec)));

          searchedBatches += wave.length;

          for (const batch of fetchedWave) {
            fetchMsTotal += batch.fetchMs;

            const processStarted = Date.now();
            let batchMatches = 0;
            let batchDecodeErrors = 0;

            batch.entries.forEach((entry, entryOffset) => {
              const logIndex = batch.spec.start + entryOffset;
              searchedEntries += 1;

              try {
                const leafBytes = decodeBase64(entry.leaf_input);
                const extraBytes = decodeBase64(entry.extra_data);
                const { der: leafCertDer, entryTypeLabel } = extractLeafCertDer(leafBytes, extraBytes);
                const cert = new X509Certificate(leafCertDer);

                const subjectCn = extractDnValue(cert.subject, "CN");
                const candidates = new Set<string>();
                if (subjectCn) {
                  candidates.add(subjectCn.toLowerCase());
                }

                parseDnsSans(cert.subjectAltName).forEach((name) => candidates.add(name));

                const matchedDomain = Array.from(candidates).find((candidate) =>
                  isDomainMatch(candidate, requestedDomain)
                );
                if (!matchedDomain) {
                  return;
                }

                const domainParts = extractDomainParts(matchedDomain);

                matches.push({
                  logIndex,
                  matchedDomain: requestedDomain,
                  domainFull: matchedDomain,
                  domainBase: domainParts.domainBase,
                  rootDomain: domainParts.rootDomain,
                  subdomain: domainParts.subdomain,
                  timestampIso: getCtTimestampIso(leafBytes),
                  entryType: entryTypeLabel,
                  organization: extractDnValue(cert.subject, "O"),
                  issuer: (cert.issuer ?? "").replace(/\n/g, ", "),
                  notBefore: formatDateTimeUtc(new Date(cert.validFrom)),
                  notAfter: formatDateTimeUtc(new Date(cert.validTo)),
                  serialNumber: cert.serialNumber.toLowerCase()
                });
                batchMatches += 1;
              } catch {
                decodeErrors += 1;
                batchDecodeErrors += 1;
              }
            });

            const processMs = Date.now() - processStarted;
            processingMsTotal += processMs;

            const batchTelemetry: BatchTelemetry = {
              batchNumber: batch.spec.batchNumber,
              start: batch.spec.start,
              end: batch.spec.end,
              entriesFetched: batch.entries.length,
              fetchMs: batch.fetchMs,
              processMs,
              matchCount: batchMatches,
              decodeErrors: batchDecodeErrors
            };

            telemetry.push(batchTelemetry);

            writeEvent(controller, encoder, "batch_progress", {
              searchedBatches,
              searchedEntries,
              decodeErrors,
              fetchMsTotal,
              processingMsTotal,
              matchesSoFar: matches.length,
              batch: batchTelemetry
            });
          }

          if (matches.length > 0) {
            found = true;
            break;
          }
        }

        matches.sort((a, b) => b.logIndex - a.logIndex);

        const totalApiMs = Date.now() - apiStarted;
        const avgFetchMsPerBatch = searchedBatches > 0 ? Number((fetchMsTotal / searchedBatches).toFixed(2)) : 0;
        const avgProcessMsPerBatch =
          searchedBatches > 0 ? Number((processingMsTotal / searchedBatches).toFixed(2)) : 0;

        writeEvent(controller, encoder, "completed", {
          requestedDomain,
          provider: "cloudflare",
          latestTreeSize: sth.treeSize,
          latestIndex: sth.latestIndex,
          sthTimestamp: new Date(sth.timestamp).toISOString(),
          maxBatchesRequested: maxBatches,
          searchedBatches,
          searchedEntries,
          decodeErrors,
          found,
          matchCount: matches.length,
          timings: {
            totalApiMs,
            sthMs: sth.sthMs,
            fetchMsTotal,
            processingMsTotal,
            avgFetchMsPerBatch,
            avgProcessMsPerBatch
          },
          batchTelemetry: telemetry,
          matches
        });
      } catch (error) {
        writeEvent(controller, encoder, "search_error", {
          error: "Failed to run descending domain search.",
          details: error instanceof Error ? error.message : "Unknown search error."
        });
      } finally {
        controller.close();
      }
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
