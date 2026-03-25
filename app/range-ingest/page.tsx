"use client";

import { FormEvent, useMemo, useState } from "react";
import { ParsedDomainRow, parseCtEntry } from "@/lib/ctParser";

type CtProvider = "cloudflare" | "digicert";

type ApiCtEntry = {
  leaf_input: string;
  extra_data: string;
};

type CtEntriesResponse = {
  start: number;
  end: number;
  provider?: CtProvider;
  count: number;
  entries: ApiCtEntry[];
  error?: string;
  details?: string;
};

type ExistingIndexesResponse = {
  source: CtProvider;
  start: number;
  end: number;
  count: number;
  indexes: number[];
  error?: string;
  details?: string;
};

type StoreRowsResponse = {
  insertedRows: number;
  table: string;
  primaryKey: string;
  error?: string;
  details?: string;
};

type RangeChunk = {
  chunkNumber: number;
  chunkStart: number;
  chunkEnd: number;
  chunkLength: number;
};

type StoreableRow = ParsedDomainRow & {
  logIndex: number;
  sourcePage: number;
  source: CtProvider;
  timestampIso: string;
  entryTypeLabel: string;
  leafSubject: string;
  leafIssuer: string;
};

type IngestProgress = {
  totalChunks: number;
  pendingChunks: number;
  skippedChunks: number;
  completedChunkFetches: number;
  existingIndexes: number;
  entriesFetched: number;
  newEntriesChecked: number;
  rowsPrepared: number;
  rowsInserted: number;
  decodeErrors: number;
};

type IngestSummary = {
  source: CtProvider;
  start: number;
  end: number;
  totalChunks: number;
  pendingChunks: number;
  skippedChunks: number;
  existingIndexes: number;
  entriesFetched: number;
  newEntriesChecked: number;
  rowsPrepared: number;
  rowsInserted: number;
  decodeErrors: number;
};

const WINDOW_SIZE = 1024;
const MAX_CT_WINDOW_OFFSET = WINDOW_SIZE - 1;
const FETCH_CONCURRENCY = 10;
const STORE_BATCH_SIZE = 1500;
const STORE_CONCURRENCY = 3;

const toErrorMessage = (value: unknown, fallback: string): string =>
  value instanceof Error ? value.message : fallback;

const readProviderValue = (value: unknown, fallback: CtProvider): CtProvider =>
  value === "cloudflare" || value === "digicert" ? value : fallback;

const clampDigits = (value: string): string => value.replace(/[^\d]/g, "");

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

const fetchCtEntriesRange = async (
  start: number,
  end: number,
  provider: CtProvider
): Promise<CtEntriesResponse> => {
  const query = new URLSearchParams({
    start: String(start),
    end: String(end),
    provider
  });

  const response = await fetch(`/api/ct-entries?${query.toString()}`);
  const payload = (await response.json()) as CtEntriesResponse;

  if (!response.ok) {
    const detailSuffix = payload.details ? ` ${payload.details}` : "";
    throw new Error((payload.error ?? `CT fetch failed with status ${response.status}.`) + detailSuffix);
  }

  if (!Array.isArray(payload.entries)) {
    throw new Error("Unexpected CT response format.");
  }

  return {
    ...payload,
    provider: readProviderValue(payload.provider, provider)
  };
};

const fetchExistingIndexes = async (
  source: CtProvider,
  start: number,
  end: number
): Promise<number[]> => {
  const query = new URLSearchParams({
    source,
    start: String(start),
    end: String(end)
  });

  const response = await fetch(`/api/organization-only/existing-indexes?${query.toString()}`);
  const payload = (await response.json()) as ExistingIndexesResponse;

  if (!response.ok) {
    const detailSuffix = payload.details ? ` ${payload.details}` : "";
    throw new Error((payload.error ?? `Existing-index lookup failed with status ${response.status}.`) + detailSuffix);
  }

  if (!Array.isArray(payload.indexes)) {
    throw new Error("Unexpected existing-index response format.");
  }

  return payload.indexes.filter((value) => Number.isSafeInteger(value) && value >= 0);
};

const storeRowsChunk = async (rows: StoreableRow[]): Promise<number> => {
  const response = await fetch("/api/organization-only/store", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ rows })
  });

  const payload = (await response.json()) as StoreRowsResponse;

  if (!response.ok) {
    const detailSuffix = payload.details ? ` ${payload.details}` : "";
    throw new Error((payload.error ?? "Store request failed.") + detailSuffix);
  }

  if (typeof payload.insertedRows !== "number") {
    throw new Error("Unexpected store response format.");
  }

  return payload.insertedRows;
};

const buildRangeChunks = (start: number, end: number): RangeChunk[] => {
  const chunks: RangeChunk[] = [];
  let chunkNumber = 1;

  for (let chunkStart = start; chunkStart <= end; chunkStart += WINDOW_SIZE) {
    const chunkEnd = Math.min(chunkStart + MAX_CT_WINDOW_OFFSET, end);
    chunks.push({
      chunkNumber,
      chunkStart,
      chunkEnd,
      chunkLength: chunkEnd - chunkStart + 1
    });
    chunkNumber += 1;
  }

  return chunks;
};

const buildExistingCountByChunk = (
  existingIndexes: number[],
  rangeStart: number,
  rangeEnd: number
): Map<number, number> => {
  const counts = new Map<number, number>();

  for (const index of existingIndexes) {
    if (index < rangeStart || index > rangeEnd) {
      continue;
    }

    const relativeOffset = index - rangeStart;
    const chunkStart = rangeStart + Math.floor(relativeOffset / WINDOW_SIZE) * WINDOW_SIZE;
    counts.set(chunkStart, (counts.get(chunkStart) ?? 0) + 1);
  }

  return counts;
};

export default function RangeIngestPage() {
  const [start, setStart] = useState("325969000");
  const [end, setEnd] = useState("325979239");
  const [source, setSource] = useState<CtProvider>("cloudflare");
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<IngestProgress | null>(null);
  const [summary, setSummary] = useState<IngestSummary | null>(null);

  const isDisabled = useMemo(
    () => isRunning || start.trim().length === 0 || end.trim().length === 0,
    [isRunning, start, end]
  );

  const handleIngest = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setSummary(null);
    setProgress(null);

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

    try {
      setIsRunning(true);

      const chunks = buildRangeChunks(startNumber, endNumber);
      const existingIndexes = await fetchExistingIndexes(source, startNumber, endNumber);
      const existingIndexSet = new Set(existingIndexes);
      const existingCountByChunk = buildExistingCountByChunk(existingIndexes, startNumber, endNumber);

      const pendingChunks = chunks.filter((chunk) => {
        const existingCount = existingCountByChunk.get(chunk.chunkStart) ?? 0;
        return existingCount < chunk.chunkLength;
      });

      const skippedChunks = chunks.length - pendingChunks.length;

      setProgress({
        totalChunks: chunks.length,
        pendingChunks: pendingChunks.length,
        skippedChunks,
        completedChunkFetches: 0,
        existingIndexes: existingIndexes.length,
        entriesFetched: 0,
        newEntriesChecked: 0,
        rowsPrepared: 0,
        rowsInserted: 0,
        decodeErrors: 0
      });

      const chunkOutputs = await processInChunks(pendingChunks, FETCH_CONCURRENCY, async (chunk) => {
        const payload = await fetchCtEntriesRange(chunk.chunkStart, chunk.chunkEnd, source);
        const rowsToStore: StoreableRow[] = [];
        let chunkNewEntriesChecked = 0;
        let chunkRowsPrepared = 0;
        let chunkDecodeErrors = 0;

        payload.entries.forEach((entry, entryOffset) => {
          const logIndex = chunk.chunkStart + entryOffset;

          if (logIndex > chunk.chunkEnd || existingIndexSet.has(logIndex)) {
            return;
          }

          chunkNewEntriesChecked += 1;

          try {
            const parsed = parseCtEntry(entry.leaf_input, entry.extra_data);
            const relevantRows = parsed.domains.filter((row) => row.root_domain.trim().length > 0);

            relevantRows.forEach((row) => {
              rowsToStore.push({
                ...row,
                logIndex,
                sourcePage: chunk.chunkNumber,
                source,
                timestampIso: parsed.timestampIso,
                entryTypeLabel: parsed.entryTypeLabel,
                leafSubject: parsed.leafSubject,
                leafIssuer: parsed.leafIssuer
              });
            });

            chunkRowsPrepared += relevantRows.length;
          } catch {
            chunkDecodeErrors += 1;
          }
        });

        setProgress((current) =>
          current
            ? {
                ...current,
                completedChunkFetches: current.completedChunkFetches + 1,
                entriesFetched: current.entriesFetched + payload.entries.length,
                newEntriesChecked: current.newEntriesChecked + chunkNewEntriesChecked,
                rowsPrepared: current.rowsPrepared + chunkRowsPrepared,
                decodeErrors: current.decodeErrors + chunkDecodeErrors
              }
            : current
        );

        return {
          rowsToStore,
          entriesFetched: payload.entries.length,
          newEntriesChecked: chunkNewEntriesChecked,
          rowsPrepared: chunkRowsPrepared,
          decodeErrors: chunkDecodeErrors
        };
      });

      const totals = chunkOutputs.reduce(
        (acc, current) => ({
          entriesFetched: acc.entriesFetched + current.entriesFetched,
          newEntriesChecked: acc.newEntriesChecked + current.newEntriesChecked,
          rowsPrepared: acc.rowsPrepared + current.rowsPrepared,
          decodeErrors: acc.decodeErrors + current.decodeErrors
        }),
        {
          entriesFetched: 0,
          newEntriesChecked: 0,
          rowsPrepared: 0,
          decodeErrors: 0
        }
      );

      const rowsToStore = chunkOutputs.flatMap((chunkOutput) => chunkOutput.rowsToStore);
      const storeBatches: StoreableRow[][] = [];
      for (let offset = 0; offset < rowsToStore.length; offset += STORE_BATCH_SIZE) {
        storeBatches.push(rowsToStore.slice(offset, offset + STORE_BATCH_SIZE));
      }

      const insertedCounts = await processInChunks(storeBatches, STORE_CONCURRENCY, async (batch) => {
        const insertedRows = await storeRowsChunk(batch);
        setProgress((current) =>
          current
            ? {
                ...current,
                rowsInserted: current.rowsInserted + insertedRows
              }
            : current
        );

        return insertedRows;
      });
      const insertedRowsTotal = insertedCounts.reduce((sum, value) => sum + value, 0);

      setSummary({
        source,
        start: startNumber,
        end: endNumber,
        totalChunks: chunks.length,
        pendingChunks: pendingChunks.length,
        skippedChunks,
        existingIndexes: existingIndexes.length,
        entriesFetched: totals.entriesFetched,
        newEntriesChecked: totals.newEntriesChecked,
        rowsPrepared: totals.rowsPrepared,
        rowsInserted: insertedRowsTotal,
        decodeErrors: totals.decodeErrors
      });
    } catch (ingestError) {
      setError(toErrorMessage(ingestError, "Range ingest failed."));
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <main className="page">
      <section className="hero">
        <p className="eyebrow">Bulk CT Ingest</p>
        <h1>Range Ingestion</h1>
        <p>
          Splits the range into 1024-entry chunks, checks existing indexes for the selected source first, fetches
          missing chunks with 10-way parallel CT calls, and inserts parsed rows in bulk.
        </p>
      </section>

      <form className="decoder-form" onSubmit={handleIngest}>
        <div className="range-grid">
          <div>
            <label htmlFor="ingest-start">Start Index</label>
            <input
              id="ingest-start"
              type="text"
              inputMode="numeric"
              value={start}
              onChange={(event) => setStart(clampDigits(event.target.value))}
              placeholder="325969000"
            />
          </div>
          <div>
            <label htmlFor="ingest-end">End Index</label>
            <input
              id="ingest-end"
              type="text"
              inputMode="numeric"
              value={end}
              onChange={(event) => setEnd(clampDigits(event.target.value))}
              placeholder="325979239"
            />
          </div>
          <div>
            <label htmlFor="ingest-source">CT Source</label>
            <select
              id="ingest-source"
              value={source}
              onChange={(event) => setSource(event.target.value as CtProvider)}
            >
              <option value="cloudflare">Cloudflare</option>
              <option value="digicert">DigiCert</option>
            </select>
          </div>
        </div>
        <p className="form-note">
          Chunk size is fixed to 1024 entries (CT API max). Existing log indexes for the selected source are skipped
          before fetch/insert.
        </p>

        <div className="actions">
          <button type="submit" disabled={isDisabled}>
            {isRunning ? "Ingesting..." : "Run Range Ingest"}
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => {
              setStart("");
              setEnd("");
              setProgress(null);
              setSummary(null);
              setError(null);
            }}
          >
            Clear
          </button>
        </div>
      </form>

      {error && (
        <section className="error-box" role="alert">
          <h2>Ingest Error</h2>
          <p>{error}</p>
        </section>
      )}

      {progress && (
        <section className="results">
          <h2>Ingest Progress</h2>
          <div className="meta-grid">
            <div>
              <label>Fetched Chunks</label>
              <p>
                {progress.completedChunkFetches} / {progress.pendingChunks}
              </p>
            </div>
            <div>
              <label>Total Chunks</label>
              <p>{progress.totalChunks}</p>
            </div>
            <div>
              <label>Skipped Chunks (Already Present)</label>
              <p>{progress.skippedChunks}</p>
            </div>
            <div>
              <label>Existing Indexes</label>
              <p>{progress.existingIndexes}</p>
            </div>
            <div>
              <label>Entries Fetched</label>
              <p>{progress.entriesFetched}</p>
            </div>
            <div>
              <label>New Entries Checked</label>
              <p>{progress.newEntriesChecked}</p>
            </div>
            <div>
              <label>Rows Prepared</label>
              <p>{progress.rowsPrepared}</p>
            </div>
            <div>
              <label>Rows Inserted</label>
              <p>{progress.rowsInserted}</p>
            </div>
            <div>
              <label>Decode Errors</label>
              <p>{progress.decodeErrors}</p>
            </div>
          </div>
        </section>
      )}

      {summary && (
        <section className="results">
          <h2>Ingest Summary</h2>
          <div className="meta-grid">
            <div>
              <label>Source</label>
              <p>{summary.source === "digicert" ? "DigiCert" : "Cloudflare"}</p>
            </div>
            <div>
              <label>Range</label>
              <p>
                {summary.start} - {summary.end}
              </p>
            </div>
            <div>
              <label>Total Chunks</label>
              <p>{summary.totalChunks}</p>
            </div>
            <div>
              <label>Chunks Fetched</label>
              <p>{summary.pendingChunks}</p>
            </div>
            <div>
              <label>Chunks Skipped</label>
              <p>{summary.skippedChunks}</p>
            </div>
            <div>
              <label>Existing Indexes</label>
              <p>{summary.existingIndexes}</p>
            </div>
            <div>
              <label>Entries Fetched</label>
              <p>{summary.entriesFetched}</p>
            </div>
            <div>
              <label>New Entries Checked</label>
              <p>{summary.newEntriesChecked}</p>
            </div>
            <div>
              <label>Rows Prepared</label>
              <p>{summary.rowsPrepared}</p>
            </div>
            <div>
              <label>Rows Inserted</label>
              <p>{summary.rowsInserted}</p>
            </div>
            <div>
              <label>Decode Errors</label>
              <p>{summary.decodeErrors}</p>
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
