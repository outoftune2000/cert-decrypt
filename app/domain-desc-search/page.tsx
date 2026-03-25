"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

type SearchMatch = {
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

type SearchTimings = {
  totalApiMs: number;
  sthMs: number;
  fetchMsTotal: number;
  processingMsTotal: number;
  avgFetchMsPerBatch: number;
  avgProcessMsPerBatch: number;
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

type SearchResponse = {
  requestedDomain: string;
  provider: "cloudflare";
  latestTreeSize: number;
  latestIndex: number;
  sthTimestamp: string;
  maxBatchesRequested: number;
  searchedBatches: number;
  searchedEntries: number;
  decodeErrors: number;
  found: boolean;
  matchCount: number;
  timings: SearchTimings;
  batchTelemetry: BatchTelemetry[];
  matches: SearchMatch[];
  error?: string;
  details?: string;
};

type StartedEvent = {
  requestedDomain: string;
  maxBatchesRequested: number;
  fetchConcurrency: number;
  windowSize: number;
};

type SthEvent = {
  latestTreeSize: number;
  latestIndex: number;
  sthTimestamp: string;
  sthMs: number;
  totalBatchSpecs: number;
};

type BatchProgressEvent = {
  searchedBatches: number;
  searchedEntries: number;
  decodeErrors: number;
  fetchMsTotal: number;
  processingMsTotal: number;
  matchesSoFar: number;
  batch: BatchTelemetry;
};

type SearchErrorEvent = {
  error: string;
  details?: string;
};

type LiveProgress = {
  requestedDomain: string;
  maxBatchesRequested: number;
  latestTreeSize: number | null;
  latestIndex: number | null;
  sthTimestamp: string | null;
  searchedBatches: number;
  searchedEntries: number;
  decodeErrors: number;
  fetchMsTotal: number;
  processingMsTotal: number;
  matchesSoFar: number;
};

const clampDigits = (value: string): string => value.replace(/[^\d]/g, "");

const toErrorMessage = (value: unknown, fallback: string): string =>
  value instanceof Error ? value.message : fallback;

const parseEventData = <T,>(event: Event): T => {
  const payload = (event as MessageEvent<string>).data;
  return JSON.parse(payload) as T;
};

export default function DomainDescSearchPage() {
  const [domain, setDomain] = useState("amazonaws.com");
  const [maxBatches, setMaxBatches] = useState("100");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SearchResponse | null>(null);
  const [liveProgress, setLiveProgress] = useState<LiveProgress | null>(null);
  const [liveBatchTelemetry, setLiveBatchTelemetry] = useState<BatchTelemetry[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);

  const closeStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  };

  useEffect(() => () => closeStream(), []);

  const isDisabled = useMemo(
    () => isLoading || domain.trim().length === 0 || maxBatches.trim().length === 0,
    [isLoading, domain, maxBatches]
  );

  const handleSearch = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    closeStream();
    setError(null);
    setResult(null);
    setLiveProgress(null);
    setLiveBatchTelemetry([]);

    if (domain.trim().length === 0) {
      setError("Domain is required.");
      return;
    }

    const maxBatchesNumber = Number(maxBatches);
    if (!Number.isSafeInteger(maxBatchesNumber) || maxBatchesNumber <= 0) {
      setError("Max batches must be a positive whole number.");
      return;
    }

    setIsLoading(true);

    const query = new URLSearchParams({
      domain: domain.trim(),
      maxBatches: String(maxBatchesNumber)
    });

    const eventSource = new EventSource(`/api/cloudflare-domain-search/stream?${query.toString()}`);
    eventSourceRef.current = eventSource;

    let streamFinished = false;

    eventSource.addEventListener("started", (streamEvent) => {
      const payload = parseEventData<StartedEvent>(streamEvent);
      setLiveProgress({
        requestedDomain: payload.requestedDomain,
        maxBatchesRequested: payload.maxBatchesRequested,
        latestTreeSize: null,
        latestIndex: null,
        sthTimestamp: null,
        searchedBatches: 0,
        searchedEntries: 0,
        decodeErrors: 0,
        fetchMsTotal: 0,
        processingMsTotal: 0,
        matchesSoFar: 0
      });
    });

    eventSource.addEventListener("sth", (streamEvent) => {
      const payload = parseEventData<SthEvent>(streamEvent);
      setLiveProgress((current) =>
        current
          ? {
              ...current,
              latestTreeSize: payload.latestTreeSize,
              latestIndex: payload.latestIndex,
              sthTimestamp: payload.sthTimestamp
            }
          : current
      );
    });

    eventSource.addEventListener("batch_progress", (streamEvent) => {
      const payload = parseEventData<BatchProgressEvent>(streamEvent);
      setLiveProgress((current) =>
        current
          ? {
              ...current,
              searchedBatches: payload.searchedBatches,
              searchedEntries: payload.searchedEntries,
              decodeErrors: payload.decodeErrors,
              fetchMsTotal: payload.fetchMsTotal,
              processingMsTotal: payload.processingMsTotal,
              matchesSoFar: payload.matchesSoFar
            }
          : current
      );
      setLiveBatchTelemetry((current) => [...current, payload.batch]);
    });

    eventSource.addEventListener("completed", (streamEvent) => {
      const payload = parseEventData<SearchResponse>(streamEvent);
      streamFinished = true;
      setResult(payload);
      setLiveBatchTelemetry(payload.batchTelemetry);
      setIsLoading(false);
      closeStream();
    });

    eventSource.addEventListener("search_error", (streamEvent) => {
      const payload = parseEventData<SearchErrorEvent>(streamEvent);
      streamFinished = true;
      const detailSuffix = payload.details ? ` ${payload.details}` : "";
      setError(payload.error + detailSuffix);
      setIsLoading(false);
      closeStream();
    });

    eventSource.onerror = () => {
      if (streamFinished) {
        return;
      }

      setError("Live stream disconnected before completion.");
      setIsLoading(false);
      closeStream();
    };
  };

  return (
    <main className="page">
      <section className="hero">
        <p className="eyebrow">Descending CT Search</p>
        <h1>Cloudflare Domain Backward Search</h1>
        <p>
          Uses `get-sth` to find the latest index, then scans backwards in 1024-entry batches (10 parallel fetches)
          until a match is found or the batch limit is reached.
        </p>
      </section>

      <form className="decoder-form" onSubmit={handleSearch}>
        <div className="range-grid">
          <div>
            <label htmlFor="desc-domain">Domain</label>
            <input
              id="desc-domain"
              type="text"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="amazonaws.com"
            />
          </div>
          <div>
            <label htmlFor="desc-max-batches">Max Batches</label>
            <input
              id="desc-max-batches"
              type="text"
              inputMode="numeric"
              value={maxBatches}
              onChange={(event) => setMaxBatches(clampDigits(event.target.value))}
              placeholder="100"
            />
          </div>
        </div>

        <p className="form-note">
          Batch size is fixed at 1024 and fetch concurrency is fixed at 10. No hard cap is enforced on max batches.
        </p>

        <div className="actions">
          <button type="submit" disabled={isDisabled}>
            {isLoading ? "Searching Live..." : "Run Descending Search"}
          </button>
          {isLoading && (
            <button
              type="button"
              className="ghost"
              onClick={() => {
                closeStream();
                setIsLoading(false);
                setError("Search cancelled.");
              }}
            >
              Cancel
            </button>
          )}
          <button
            type="button"
            className="ghost"
            onClick={() => {
              closeStream();
              setDomain("");
              setMaxBatches("100");
              setError(null);
              setResult(null);
              setLiveProgress(null);
              setLiveBatchTelemetry([]);
            }}
          >
            Clear
          </button>
        </div>
      </form>

      {error && (
        <section className="error-box" role="alert">
          <h2>Search Error</h2>
          <p>{error}</p>
        </section>
      )}

      {liveProgress && (
        <section className="results">
          <h2>Live Progress</h2>
          <div className="meta-grid">
            <div>
              <label>Domain</label>
              <p>{liveProgress.requestedDomain}</p>
            </div>
            <div>
              <label>Batches Completed</label>
              <p>
                {liveProgress.searchedBatches} / {liveProgress.maxBatchesRequested}
              </p>
            </div>
            <div>
              <label>Entries Searched</label>
              <p>{liveProgress.searchedEntries}</p>
            </div>
            <div>
              <label>Matches So Far</label>
              <p>{liveProgress.matchesSoFar}</p>
            </div>
            <div>
              <label>Decode Errors</label>
              <p>{liveProgress.decodeErrors}</p>
            </div>
            <div>
              <label>Fetch Time Total</label>
              <p>{liveProgress.fetchMsTotal} ms</p>
            </div>
            <div>
              <label>Process Time Total</label>
              <p>{liveProgress.processingMsTotal} ms</p>
            </div>
            <div>
              <label>Latest Index</label>
              <p>{liveProgress.latestIndex ?? "-"}</p>
            </div>
            <div>
              <label>STH Timestamp</label>
              <p>{liveProgress.sthTimestamp ?? "-"}</p>
            </div>
          </div>

          {liveBatchTelemetry.length > 0 && (
            <details className="collapsible">
              <summary>Live Batch Telemetry</summary>
              <div className="collapsible-body">
                <pre className="json-output">{JSON.stringify(liveBatchTelemetry, null, 2)}</pre>
              </div>
            </details>
          )}
        </section>
      )}

      {result && (
        <section className="results">
          <h2>Search Results</h2>
          <div className="meta-grid">
            <div>
              <label>Domain</label>
              <p>{result.requestedDomain}</p>
            </div>
            <div>
              <label>Found</label>
              <p>{result.found ? "yes" : "no"}</p>
            </div>
            <div>
              <label>Match Count</label>
              <p>{result.matchCount}</p>
            </div>
            <div>
              <label>Latest Tree Size</label>
              <p>{result.latestTreeSize}</p>
            </div>
            <div>
              <label>Latest Index</label>
              <p>{result.latestIndex}</p>
            </div>
            <div>
              <label>STH Timestamp</label>
              <p>{result.sthTimestamp}</p>
            </div>
            <div>
              <label>Batches Searched</label>
              <p>
                {result.searchedBatches} / {result.maxBatchesRequested}
              </p>
            </div>
            <div>
              <label>Entries Searched</label>
              <p>{result.searchedEntries}</p>
            </div>
            <div>
              <label>Decode Errors</label>
              <p>{result.decodeErrors}</p>
            </div>
            <div>
              <label>Total API Time</label>
              <p>{result.timings.totalApiMs} ms</p>
            </div>
            <div>
              <label>get-sth Time</label>
              <p>{result.timings.sthMs} ms</p>
            </div>
            <div>
              <label>Fetch Time (Batches Total)</label>
              <p>{result.timings.fetchMsTotal} ms</p>
            </div>
            <div>
              <label>Log Processing Time</label>
              <p>{result.timings.processingMsTotal} ms</p>
            </div>
            <div>
              <label>Avg Fetch/Batch</label>
              <p>{result.timings.avgFetchMsPerBatch} ms</p>
            </div>
            <div>
              <label>Avg Process/Batch</label>
              <p>{result.timings.avgProcessMsPerBatch} ms</p>
            </div>
          </div>

          {result.matches.length === 0 ? (
            <p>No matching entries were found in the searched window.</p>
          ) : (
            <div className="rows-scroll">
              <table className="rows-table">
                <thead>
                  <tr>
                    <th>log_index</th>
                    <th>timestamp_utc</th>
                    <th>domain_full</th>
                    <th>domain_base</th>
                    <th>root_domain</th>
                    <th>subdomain</th>
                    <th>entry_type</th>
                    <th>organization</th>
                    <th>issuer</th>
                    <th>not_before</th>
                    <th>not_after</th>
                    <th>serial_number</th>
                  </tr>
                </thead>
                <tbody>
                  {result.matches.map((row, index) => (
                    <tr key={`${row.logIndex}-${row.serialNumber}-${index}`}>
                      <td>{row.logIndex}</td>
                      <td>{row.timestampIso}</td>
                      <td>{row.domainFull}</td>
                      <td>{row.domainBase}</td>
                      <td>{row.rootDomain}</td>
                      <td>{row.subdomain}</td>
                      <td>{row.entryType}</td>
                      <td>{row.organization || "-"}</td>
                      <td>{row.issuer}</td>
                      <td>{row.notBefore}</td>
                      <td>{row.notAfter}</td>
                      <td>{row.serialNumber}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.batchTelemetry.length > 0 && (
            <details className="collapsible">
              <summary>Batch Telemetry</summary>
              <div className="collapsible-body">
                <pre className="json-output">{JSON.stringify(result.batchTelemetry, null, 2)}</pre>
              </div>
            </details>
          )}
        </section>
      )}
    </main>
  );
}
