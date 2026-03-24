"use client";

import { FormEvent, useMemo, useState } from "react";
import {
  ParsedCtEntry,
  ParsedDomainRow,
  getLeafCertificateFingerprintSha256,
  parseCtEntry
} from "@/lib/ctParser";

type ApiCtEntry = {
  leaf_input: string;
  extra_data: string;
};

type ApiResponse = {
  start: number;
  end: number;
  count: number;
  entries: ApiCtEntry[];
};

type DecodeResult = {
  logIndex: number;
  parsed: ParsedCtEntry | null;
  error: string | null;
};

type TabMode = "decoder" | "fingerprint";

type SeedRecord = {
  logIndex: number;
  fingerprint: string;
  primaryDomain: string;
  domainCount: number;
  error: string | null;
};

type MatchRecord = {
  logIndex: number;
  fingerprint: string;
  domains: string[];
};

type SearchProgress = {
  completedBatches: number;
  totalBatches: number;
  checkedEntries: number;
  matchedEntries: number;
};

const MAX_CT_WINDOW_OFFSET = 1023;
const SEARCH_BATCHES = 10;
const CHUNK_SIZE = 64;
const SEARCH_FETCH_CONCURRENCY = 3;

const stringifyForUi = (value: unknown): string =>
  JSON.stringify(
    value,
    (_, item) => (typeof item === "bigint" ? item.toString() : item),
    2
  );

const clampEndForStart = (endValue: string, startValue: string): string => {
  const endDigits = endValue.replace(/[^\d]/g, "");
  if (!endDigits) {
    return "";
  }

  const startNumber = Number(startValue);
  if (!Number.isSafeInteger(startNumber) || startNumber < 0) {
    return endDigits;
  }

  const endNumber = Number(endDigits);
  if (!Number.isSafeInteger(endNumber)) {
    return String(startNumber + MAX_CT_WINDOW_OFFSET);
  }

  const maxAllowedEnd = startNumber + MAX_CT_WINDOW_OFFSET;
  return String(Math.min(endNumber, maxAllowedEnd));
};

const fetchCtEntriesRange = async (start: number, end: number): Promise<ApiResponse> => {
  const query = new URLSearchParams({
    start: String(start),
    end: String(end)
  });

  const response = await fetch(`/api/ct-entries?${query.toString()}`);
  const payload = (await response.json()) as Partial<ApiResponse> & { error?: string; details?: string };

  if (!response.ok) {
    const detailSuffix = payload.details ? ` ${payload.details}` : "";
    throw new Error((payload.error ?? `Request failed with status ${response.status}.`) + detailSuffix);
  }

  if (!Array.isArray(payload.entries)) {
    throw new Error("Unexpected response format from CT endpoint.");
  }

  const entries = payload.entries.filter(
    (entry): entry is ApiCtEntry =>
      typeof entry?.leaf_input === "string" && typeof entry?.extra_data === "string"
  );

  return {
    start: typeof payload.start === "number" ? payload.start : start,
    end: typeof payload.end === "number" ? payload.end : end,
    count: typeof payload.count === "number" ? payload.count : entries.length,
    entries
  };
};

const extractDomainLabels = (parsed: ParsedCtEntry): string[] => {
  const labels = parsed.domains
    .map((row) => {
      if (row.domain_full) {
        return row.domain_full;
      }
      if (row.ip_address && row.ip_address !== "::") {
        return row.ip_address;
      }
      return "";
    })
    .filter((value): value is string => value.length > 0);

  return Array.from(new Set(labels));
};

const toErrorMessage = (value: unknown, fallback: string): string =>
  value instanceof Error ? value.message : fallback;

const processInChunks = async <T, R>(
  items: T[],
  chunkSize: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> => {
  const output: R[] = [];

  for (let offset = 0; offset < items.length; offset += chunkSize) {
    const slice = items.slice(offset, offset + chunkSize);
    const chunk = await Promise.all(slice.map((item, index) => worker(item, offset + index)));
    output.push(...chunk);
  }

  return output;
};

function DomainRowsTable({ rows }: { rows: ParsedDomainRow[] }) {
  if (rows.length === 0) {
    return <p>No domain/IP rows found in this certificate.</p>;
  }

  return (
    <div className="rows-scroll">
      <table className="rows-table">
        <thead>
          <tr>
            <th>domain_full</th>
            <th>root_domain</th>
            <th>subdomain</th>
            <th>issuer</th>
            <th>not_before</th>
            <th>not_after</th>
            <th>serial_number</th>
            <th>key_algorithm</th>
            <th>key_size</th>
            <th>signature_algorithm</th>
            <th>ocsp_url</th>
            <th>crl_url</th>
            <th>organization</th>
            <th>location</th>
            <th>ip_address</th>
            <th>domain_base</th>
            <th>tld</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={`${row.domain_full}-${row.root_domain}-${row.subdomain}-${row.issuer}-${row.serial_number}-${row.ip_address}-${index}`}
            >
              <td>{row.domain_full}</td>
              <td>{row.root_domain}</td>
              <td>{row.subdomain}</td>
              <td>{row.issuer}</td>
              <td>{row.not_before}</td>
              <td>{row.not_after}</td>
              <td>{row.serial_number}</td>
              <td>{row.key_algorithm}</td>
              <td>{row.key_size}</td>
              <td>{row.signature_algorithm}</td>
              <td>{row.ocsp_url}</td>
              <td>{row.crl_url}</td>
              <td>{row.organization}</td>
              <td>{row.location}</td>
              <td>{row.ip_address}</td>
              <td>{row.domain_base}</td>
              <td>{row.tld}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EntryOutput({ data, logIndex }: { data: ParsedCtEntry; logIndex: number }) {
  return (
    <article className="card">
      <h3>Entry #{logIndex}</h3>
      <div className="meta-grid">
        <div>
          <label>Version</label>
          <p>{data.version}</p>
        </div>
        <div>
          <label>Leaf Type</label>
          <p>{data.leafType}</p>
        </div>
        <div>
          <label>Entry Type</label>
          <p>
            {data.entryType} ({data.entryTypeLabel})
          </p>
        </div>
        <div>
          <label>Timestamp (ms)</label>
          <p>{data.timestampMs.toString()}</p>
        </div>
        <div>
          <label>Timestamp (UTC)</label>
          <p>{data.timestampIso}</p>
        </div>
        <div>
          <label>Leaf Cert/TBS Length</label>
          <p>{data.certLength} bytes</p>
        </div>
        <div>
          <label>Extensions Length</label>
          <p>{data.extensionsLength} bytes</p>
        </div>
        <div>
          <label>Chain Total Length</label>
          <p>{data.chainTotalLength} bytes</p>
        </div>
      </div>

      <article className="card">
        <h3>Leaf Certificate</h3>
        <p>
          <span>Source:</span> {data.leafCertificateSource}
        </p>
        {data.issuerKeyHashHex && (
          <p>
            <span>Issuer Key Hash:</span> {data.issuerKeyHashHex}
          </p>
        )}
        <p>
          <span>Subject:</span> {data.leafSubject}
        </p>
        <p>
          <span>Issuer:</span> {data.leafIssuer}
        </p>
      </article>

      <article className="card">
        <h3>Chain ({data.chainEntries.length})</h3>
        {data.chainEntries.length === 0 && <p>No chain entries found.</p>}
        {data.chainEntries.map((entry) => (
          <div key={`${entry.index}-${entry.length}`} className="chain-item">
            <h4>Link {entry.index}</h4>
            <p>
              <span>Length:</span> {entry.length} bytes
            </p>
            <p>
              <span>Subject:</span> {entry.subject}
            </p>
            <p>
              <span>Issuer:</span> {entry.issuer}
            </p>
          </div>
        ))}
      </article>

      <article className="card">
        <h3>Normalized Rows ({data.domains.length})</h3>
        <DomainRowsTable rows={data.domains} />
      </article>
    </article>
  );
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<TabMode>("decoder");

  const [start, setStart] = useState("325969000");
  const [end, setEnd] = useState("325969010");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<DecodeResult[]>([]);
  const [rangeMeta, setRangeMeta] = useState<{ start: number; end: number; count: number } | null>(null);

  const [seedStart, setSeedStart] = useState("325969000");
  const [seedMeta, setSeedMeta] = useState<{ start: number; end: number; count: number } | null>(null);
  const [seedRecords, setSeedRecords] = useState<SeedRecord[]>([]);
  const [selectedSeedLogIndex, setSelectedSeedLogIndex] = useState<number | null>(null);
  const [seedLoading, setSeedLoading] = useState(false);
  const [seedError, setSeedError] = useState<string | null>(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searchProgress, setSearchProgress] = useState<SearchProgress | null>(null);
  const [matchRecords, setMatchRecords] = useState<MatchRecord[]>([]);
  const [matchedDomains, setMatchedDomains] = useState<string[]>([]);

  const isDisabled = useMemo(
    () => isLoading || start.trim().length === 0 || end.trim().length === 0,
    [end, isLoading, start]
  );

  const decodedCount = useMemo(
    () => results.filter((item) => item.parsed !== null).length,
    [results]
  );

  const formattedRows = useMemo(
    () => results.flatMap((item) => (item.parsed ? item.parsed.domains : [])),
    [results]
  );

  const rawDecodedValues = useMemo(
    () =>
      results.map((item) => ({
        logIndex: item.logIndex,
        parsed: item.parsed,
        error: item.error
      })),
    [results]
  );

  const rawDecodedValuesJson = useMemo(() => stringifyForUi(rawDecodedValues), [rawDecodedValues]);

  const selectedSeedRecord = useMemo(
    () => seedRecords.find((record) => record.logIndex === selectedSeedLogIndex) ?? null,
    [seedRecords, selectedSeedLogIndex]
  );

  const handleFetchAndDecode = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setResults([]);
    setRangeMeta(null);

    const startNumber = Number(start);
    const endNumber = Number(end);

    if (!Number.isSafeInteger(startNumber) || !Number.isSafeInteger(endNumber)) {
      setError("Start and end must be whole numbers.");
      return;
    }

    if (startNumber < 0 || endNumber < 0) {
      setError("Start and end must be non-negative.");
      return;
    }

    if (endNumber < startNumber) {
      setError("End must be greater than or equal to start.");
      return;
    }

    if (endNumber - startNumber > MAX_CT_WINDOW_OFFSET) {
      setError(`The CT API allows up to 1024 entries per call. End must be <= start + ${MAX_CT_WINDOW_OFFSET}.`);
      return;
    }

    try {
      setIsLoading(true);

      const payload = await fetchCtEntriesRange(startNumber, endNumber);
      const decodeResults: DecodeResult[] = payload.entries.map((entry, index) => {
        const logIndex = startNumber + index;

        try {
          return {
            logIndex,
            parsed: parseCtEntry(entry.leaf_input, entry.extra_data),
            error: null
          };
        } catch (decodeError) {
          return {
            logIndex,
            parsed: null,
            error: toErrorMessage(decodeError, "Failed to decode CT entry.")
          };
        }
      });

      setResults(decodeResults);
      setRangeMeta({
        start: payload.start,
        end: payload.end,
        count: payload.count
      });
    } catch (decodeError) {
      setError(toErrorMessage(decodeError, "Failed to fetch or decode CT entries."));
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadFingerprintSeed = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSeedError(null);
    setSearchError(null);
    setMatchRecords([]);
    setMatchedDomains([]);
    setSearchProgress(null);
    setSelectedSeedLogIndex(null);
    setSeedRecords([]);
    setSeedMeta(null);

    const startNumber = Number(seedStart);
    if (!Number.isSafeInteger(startNumber) || startNumber < 0) {
      setSeedError("Start must be a non-negative whole number.");
      return;
    }

    const endNumber = startNumber + MAX_CT_WINDOW_OFFSET;

    try {
      setSeedLoading(true);
      const payload = await fetchCtEntriesRange(startNumber, endNumber);

      const records = await processInChunks(payload.entries, CHUNK_SIZE, async (entry, index) => {
        const logIndex = startNumber + index;
        let fingerprint = "";
        let primaryDomain = "(no domain)";
        let domainCount = 0;
        let recordError: string | null = null;

        try {
          fingerprint = await getLeafCertificateFingerprintSha256(entry.leaf_input, entry.extra_data);
        } catch (fingerprintError) {
          recordError = toErrorMessage(fingerprintError, "Fingerprint extraction failed.");
        }

        try {
          const parsed = parseCtEntry(entry.leaf_input, entry.extra_data);
          const domains = extractDomainLabels(parsed);
          domainCount = domains.length;
          if (domains.length > 0) {
            primaryDomain = domains[0];
          }
        } catch (parseError) {
          recordError = recordError ?? toErrorMessage(parseError, "Decode failed.");
        }

        return {
          logIndex,
          fingerprint,
          primaryDomain,
          domainCount,
          error: recordError
        } satisfies SeedRecord;
      });

      setSeedRecords(records);
      setSeedMeta({
        start: payload.start,
        end: payload.end,
        count: payload.count
      });

      const firstSelectable = records.find((record) => record.fingerprint.length > 0);
      setSelectedSeedLogIndex(firstSelectable ? firstSelectable.logIndex : null);
    } catch (loadError) {
      setSeedError(toErrorMessage(loadError, "Failed to load seed records."));
    } finally {
      setSeedLoading(false);
    }
  };

  const handleSearchFingerprintMatches = async () => {
    if (!selectedSeedRecord || !seedMeta) {
      setSearchError("Pick a seed record before starting the fingerprint search.");
      return;
    }

    if (!selectedSeedRecord.fingerprint) {
      setSearchError("Selected record has no fingerprint.");
      return;
    }

    setSearchError(null);
    setMatchRecords([]);
    setMatchedDomains([]);
    setSearchProgress({
      completedBatches: 0,
      totalBatches: SEARCH_BATCHES,
      checkedEntries: 0,
      matchedEntries: 0
    });

    try {
      setSearchLoading(true);
      const baseStart = seedMeta.end + 1;
      const nextMatches: MatchRecord[] = [];
      const foundDomains = new Set<string>();
      let checkedEntries = 0;
      let matchedEntries = 0;
      let completedBatches = 0;

      const batchSpecs = Array.from({ length: SEARCH_BATCHES }, (_, batch) => {
        const batchStart = baseStart + batch * (MAX_CT_WINDOW_OFFSET + 1);
        return {
          batch,
          batchStart,
          batchEnd: batchStart + MAX_CT_WINDOW_OFFSET
        };
      });

      const fetchedBatches = await processInChunks(batchSpecs, SEARCH_FETCH_CONCURRENCY, async (spec) => {
        const payload = await fetchCtEntriesRange(spec.batchStart, spec.batchEnd);
        return {
          ...spec,
          payload
        };
      });

      for (const fetchedBatch of fetchedBatches) {
        const { batchStart, payload } = fetchedBatch;

        await processInChunks(payload.entries, CHUNK_SIZE, async (entry, index) => {
          checkedEntries += 1;
          const logIndex = batchStart + index;
          let fingerprint: string;

          try {
            fingerprint = await getLeafCertificateFingerprintSha256(entry.leaf_input, entry.extra_data);
          } catch {
            return null;
          }

          if (fingerprint !== selectedSeedRecord.fingerprint) {
            return null;
          }

          matchedEntries += 1;

          try {
            const parsed = parseCtEntry(entry.leaf_input, entry.extra_data);
            const domains = extractDomainLabels(parsed);
            domains.forEach((domain) => foundDomains.add(domain));
            nextMatches.push({
              logIndex,
              fingerprint,
              domains
            });
          } catch {
            nextMatches.push({
              logIndex,
              fingerprint,
              domains: []
            });
          }

          return null;
        });

        completedBatches += 1;

        setSearchProgress({
          completedBatches,
          totalBatches: SEARCH_BATCHES,
          checkedEntries,
          matchedEntries
        });
      }

      setMatchRecords(nextMatches);
      setMatchedDomains(Array.from(foundDomains).sort((a, b) => a.localeCompare(b)));
    } catch (scanError) {
      setSearchError(toErrorMessage(scanError, "Fingerprint scan failed."));
    } finally {
      setSearchLoading(false);
    }
  };

  return (
    <main className="page">
      <section className="hero">
        <p className="eyebrow">Certificate Transparency Utility</p>
        <h1>CT Entry Decoder</h1>
        <p>
          Decode CT records, or run a fingerprint-based domain search over rolling windows from Nimbus 2026.
        </p>
        <p className="form-note" style={{ marginTop: "0.8rem" }}>
          Organization-only view: <a href="/organization-only">/organization-only</a>
        </p>
      </section>

      <section className="tab-switcher" aria-label="View mode">
        <button
          type="button"
          className={`tab-button ${activeTab === "decoder" ? "active" : ""}`}
          onClick={() => setActiveTab("decoder")}
        >
          Decoder
        </button>
        <button
          type="button"
          className={`tab-button ${activeTab === "fingerprint" ? "active" : ""}`}
          onClick={() => setActiveTab("fingerprint")}
        >
          Fingerprint Search
        </button>
      </section>

      {activeTab === "decoder" && (
        <>
          <form className="decoder-form" onSubmit={handleFetchAndDecode}>
            <div className="range-grid">
              <div>
                <label htmlFor="start">Start Index</label>
                <input
                  id="start"
                  type="text"
                  inputMode="numeric"
                  value={start}
                  onChange={(event) => {
                    const nextStart = event.target.value.replace(/[^\d]/g, "");
                    setStart(nextStart);
                    setEnd((currentEnd) => clampEndForStart(currentEnd, nextStart));
                  }}
                  placeholder="325969000"
                />
              </div>
              <div>
                <label htmlFor="end">End Index</label>
                <input
                  id="end"
                  type="text"
                  inputMode="numeric"
                  value={end}
                  onChange={(event) => setEnd(clampEndForStart(event.target.value, start))}
                  placeholder="325969010"
                />
              </div>
            </div>
            <p className="form-note">Max range per request is 1024 entries (`end &lt;= start + 1023`).</p>

            <div className="actions">
              <button type="submit" disabled={isDisabled}>
                {isLoading ? "Fetching..." : "Fetch and Decode"}
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => {
                  setStart("");
                  setEnd("");
                  setError(null);
                  setResults([]);
                  setRangeMeta(null);
                }}
              >
                Clear
              </button>
            </div>
          </form>

          {error && (
            <section className="error-box" role="alert">
              <h2>Decode Error</h2>
              <p>{error}</p>
            </section>
          )}

          {rangeMeta && (
            <section className="results">
              <h2>Decoded Results</h2>
              <div className="meta-grid">
                <div>
                  <label>Requested Start</label>
                  <p>{rangeMeta.start}</p>
                </div>
                <div>
                  <label>Requested End</label>
                  <p>{rangeMeta.end}</p>
                </div>
                <div>
                  <label>Entries Returned</label>
                  <p>{rangeMeta.count}</p>
                </div>
                <div>
                  <label>Decoded Successfully</label>
                  <p>{decodedCount}</p>
                </div>
                <div>
                  <label>Formatted Rows</label>
                  <p>{formattedRows.length}</p>
                </div>
              </div>

              {results.length === 0 && <p>No entries were returned for the selected range.</p>}

              <details className="collapsible" open>
                <summary>Formatted Table</summary>
                <div className="collapsible-body">
                  {formattedRows.length > 0 ? (
                    <DomainRowsTable rows={formattedRows} />
                  ) : (
                    <p>No formatted rows available.</p>
                  )}
                </div>
              </details>

              <details className="collapsible">
                <summary>Raw Decoded Values</summary>
                <div className="collapsible-body">
                  <pre className="json-output">{rawDecodedValuesJson}</pre>
                </div>
              </details>

              <details className="collapsible">
                <summary>Individual Results</summary>
                <div className="collapsible-body">
                  {results.map((result) =>
                    result.parsed ? (
                      <EntryOutput key={result.logIndex} data={result.parsed} logIndex={result.logIndex} />
                    ) : (
                      <article key={result.logIndex} className="card">
                        <h3>Entry #{result.logIndex}</h3>
                        <p>Decode failed: {result.error}</p>
                      </article>
                    )
                  )}
                </div>
              </details>
            </section>
          )}
        </>
      )}

      {activeTab === "fingerprint" && (
        <>
          <form className="decoder-form" onSubmit={handleLoadFingerprintSeed}>
            <div className="range-grid">
              <div>
                <label htmlFor="seed-start">Seed Start Index</label>
                <input
                  id="seed-start"
                  type="text"
                  inputMode="numeric"
                  value={seedStart}
                  onChange={(event) => setSeedStart(event.target.value.replace(/[^\d]/g, ""))}
                  placeholder="325969000"
                />
              </div>
            </div>
            <p className="form-note">
              Loads 1024 records from `start` to `start + 1023`, lets you pick one fingerprint, then scans the next
              10,240 records in 10 API calls.
            </p>
            <div className="actions">
              <button type="submit" disabled={seedLoading || searchLoading || seedStart.trim().length === 0}>
                {seedLoading ? "Loading 1024..." : "Load 1024 Records"}
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => {
                  setSeedMeta(null);
                  setSeedRecords([]);
                  setSelectedSeedLogIndex(null);
                  setSeedError(null);
                  setSearchError(null);
                  setMatchRecords([]);
                  setMatchedDomains([]);
                  setSearchProgress(null);
                }}
              >
                Clear
              </button>
            </div>
          </form>

          {seedError && (
            <section className="error-box" role="alert">
              <h2>Seed Load Error</h2>
              <p>{seedError}</p>
            </section>
          )}

          {seedMeta && (
            <section className="results">
              <h2>Seed Records</h2>
              <div className="meta-grid">
                <div>
                  <label>Loaded Start</label>
                  <p>{seedMeta.start}</p>
                </div>
                <div>
                  <label>Loaded End</label>
                  <p>{seedMeta.end}</p>
                </div>
                <div>
                  <label>Entries Loaded</label>
                  <p>{seedMeta.count}</p>
                </div>
                <div>
                  <label>Selectable Fingerprints</label>
                  <p>{seedRecords.filter((record) => record.fingerprint.length > 0).length}</p>
                </div>
              </div>

              <div className="rows-scroll">
                <table className="seed-table">
                  <thead>
                    <tr>
                      <th>Pick</th>
                      <th>log_index</th>
                      <th>domain</th>
                      <th>domain_count</th>
                      <th>fingerprint_sha256</th>
                      <th>status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {seedRecords.map((record) => (
                      <tr key={record.logIndex}>
                        <td>
                          <input
                            type="radio"
                            name="seed-record"
                            checked={selectedSeedLogIndex === record.logIndex}
                            onChange={() => setSelectedSeedLogIndex(record.logIndex)}
                            disabled={record.fingerprint.length === 0}
                          />
                        </td>
                        <td>{record.logIndex}</td>
                        <td>{record.primaryDomain}</td>
                        <td>{record.domainCount}</td>
                        <td>{record.fingerprint}</td>
                        <td>{record.error ? `Warning: ${record.error}` : "OK"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="actions">
                <button
                  type="button"
                  onClick={handleSearchFingerprintMatches}
                  disabled={searchLoading || !selectedSeedRecord || selectedSeedRecord.fingerprint.length === 0}
                >
                  {searchLoading ? "Scanning Next 10,240..." : "Search Next 10,240 Records"}
                </button>
              </div>
            </section>
          )}

          {searchError && (
            <section className="error-box" role="alert">
              <h2>Fingerprint Search Error</h2>
              <p>{searchError}</p>
            </section>
          )}

          {searchProgress && (
            <section className="results">
              <h2>Search Progress</h2>
              <div className="meta-grid">
                <div>
                  <label>Batches Completed</label>
                  <p>
                    {searchProgress.completedBatches} / {searchProgress.totalBatches}
                  </p>
                </div>
                <div>
                  <label>Entries Checked</label>
                  <p>{searchProgress.checkedEntries}</p>
                </div>
                <div>
                  <label>Fingerprint Matches</label>
                  <p>{searchProgress.matchedEntries}</p>
                </div>
                <div>
                  <label>Unique Domains Found</label>
                  <p>{matchedDomains.length}</p>
                </div>
              </div>
            </section>
          )}

          {matchRecords.length > 0 && (
            <section className="results">
              <h2>Fingerprint Matches</h2>
              <details className="collapsible" open>
                <summary>Matched Domains ({matchedDomains.length})</summary>
                <div className="collapsible-body">
                  <pre className="json-output">{stringifyForUi(matchedDomains)}</pre>
                </div>
              </details>
              <details className="collapsible">
                <summary>Matched Records ({matchRecords.length})</summary>
                <div className="collapsible-body">
                  <pre className="json-output">{stringifyForUi(matchRecords)}</pre>
                </div>
              </details>
            </section>
          )}
        </>
      )}
    </main>
  );
}
