"use client";

import { FormEvent, useMemo, useState } from "react";
import { ParsedDomainRow, parseCtEntry } from "@/lib/ctParser";

type ApiCtEntry = {
  leaf_input: string;
  extra_data: string;
};

type CtProvider = "cloudflare" | "digicert";

type ApiResponse = {
  start: number;
  end: number;
  provider?: CtProvider;
  count: number;
  entries: ApiCtEntry[];
};

type SearchProgress = {
  provider: CtProvider;
  completedPages: number;
  totalPages: number;
  checkedEntries: number;
  matchedRows: number;
  insertedRows: number;
  decodeErrors: number;
};

type OrganizationRow = ParsedDomainRow & {
  logIndex: number;
  sourcePage: number;
  source: CtProvider;
  timestampIso: string;
  entryTypeLabel: string;
  leafSubject: string;
  leafIssuer: string;
};

type OrganizationRowsByName = Record<string, OrganizationRow[]>;

type StoreRowsResponse = {
  insertedRows: number;
  table: string;
  primaryKey: string;
};

const MAX_CT_WINDOW_OFFSET = 1023;
const WINDOW_SIZE = MAX_CT_WINDOW_OFFSET + 1;
const PAGE_COUNT = 10;
const PAGE_FETCH_CONCURRENCY = 3;
const STORE_BATCH_SIZE = 1500;
const STORE_CONCURRENCY = 2;

const clampDigits = (value: string): string => value.replace(/[^\d]/g, "");

const toErrorMessage = (value: unknown, fallback: string): string =>
  value instanceof Error ? value.message : fallback;

const readProviderValue = (value: unknown, fallback: CtProvider): CtProvider =>
  value === "cloudflare" || value === "digicert" ? value : fallback;

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
): Promise<ApiResponse> => {
  const query = new URLSearchParams({
    start: String(start),
    end: String(end),
    provider
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
    provider: readProviderValue(payload.provider, provider),
    count: typeof payload.count === "number" ? payload.count : entries.length,
    entries
  };
};

const storeOrganizationRowsChunk = async (rows: OrganizationRow[]): Promise<number> => {
  const response = await fetch("/api/organization-only/store", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ rows })
  });

  const payload = (await response.json()) as Partial<StoreRowsResponse> & { error?: string; details?: string };

  if (!response.ok) {
    const detailSuffix = payload.details ? ` ${payload.details}` : "";
    throw new Error((payload.error ?? "Failed to store organization rows.") + detailSuffix);
  }

  if (typeof payload.insertedRows !== "number") {
    throw new Error("Unexpected response format from storage endpoint.");
  }

  return payload.insertedRows;
};

const storeOrganizationRows = async (rows: OrganizationRow[]): Promise<number> => {
  if (rows.length === 0) {
    return 0;
  }

  const chunks: OrganizationRow[][] = [];
  for (let offset = 0; offset < rows.length; offset += STORE_BATCH_SIZE) {
    chunks.push(rows.slice(offset, offset + STORE_BATCH_SIZE));
  }

  const insertedCounts = await processInChunks(chunks, STORE_CONCURRENCY, async (chunk) =>
    storeOrganizationRowsChunk(chunk)
  );

  return insertedCounts.reduce((total, count) => total + count, 0);
};

function OrganizationRowsTable({ rows }: { rows: OrganizationRow[] }) {
  if (rows.length === 0) {
    return <p>No rows with organization values were found in the scanned pages.</p>;
  }

  return (
    <div className="rows-scroll">
      <table className="rows-table">
        <thead>
          <tr>
            <th>log_index</th>
            <th>source_page</th>
            <th>source</th>
            <th>timestamp_utc</th>
            <th>entry_type</th>
            <th>leaf_subject</th>
            <th>leaf_issuer</th>
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
              key={`${row.logIndex}-${row.domain_full}-${row.ip_address}-${row.serial_number}-${index}`}
            >
              <td>{row.logIndex}</td>
              <td>{row.sourcePage}</td>
              <td>{row.source}</td>
              <td>{row.timestampIso}</td>
              <td>{row.entryTypeLabel}</td>
              <td>{row.leafSubject}</td>
              <td>{row.leafIssuer}</td>
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

export default function OrganizationOnlyPage() {
  const [start, setStart] = useState("325969000");
  const [ctProvider, setCtProvider] = useState<CtProvider>("cloudflare");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<SearchProgress | null>(null);
  const [rowsByOrganization, setRowsByOrganization] = useState<OrganizationRowsByName>({});

  const isDisabled = useMemo(() => isLoading || start.trim().length === 0, [isLoading, start]);
  const rows = useMemo(() => Object.values(rowsByOrganization).flat(), [rowsByOrganization]);
  const organizationCount = useMemo(() => Object.keys(rowsByOrganization).length, [rowsByOrganization]);

  const handleScan = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setRowsByOrganization({});

    const startNumber = Number(start);
    if (!Number.isSafeInteger(startNumber) || startNumber < 0) {
      setError("Start must be a non-negative whole number.");
      return;
    }

    setProgress({
      provider: ctProvider,
      completedPages: 0,
      totalPages: PAGE_COUNT,
      checkedEntries: 0,
      matchedRows: 0,
      insertedRows: 0,
      decodeErrors: 0
    });

    try {
      setIsLoading(true);
      const nextRowsByOrganization: OrganizationRowsByName = {};
      const allRowsToStore: OrganizationRow[] = [];
      let checkedEntries = 0;
      let matchedRows = 0;
      let insertedRows = 0;
      let decodeErrors = 0;
      let completedPages = 0;

      const pageSpecs = Array.from({ length: PAGE_COUNT }, (_, page) => {
        const batchStart = startNumber + page * WINDOW_SIZE;
        return {
          page,
          batchStart,
          batchEnd: batchStart + MAX_CT_WINDOW_OFFSET
        };
      });

      const fetchedPages = await processInChunks(pageSpecs, PAGE_FETCH_CONCURRENCY, async (spec) => {
        const payload = await fetchCtEntriesRange(spec.batchStart, spec.batchEnd, ctProvider);
        return {
          ...spec,
          payload
        };
      });

      for (const fetchedPage of fetchedPages) {
        const { page, batchStart, payload } = fetchedPage;

        payload.entries.forEach((entry, index) => {
          const logIndex = batchStart + index;
          checkedEntries += 1;

          try {
            const parsed = parseCtEntry(entry.leaf_input, entry.extra_data);
            const organizationRows = parsed.domains.filter((row) => row.organization.trim().length > 0);

            organizationRows.forEach((row) => {
              const organizationKey = row.organization.trim();
              const nextRow: OrganizationRow = {
                ...row,
                logIndex,
                sourcePage: page + 1,
                source: payload.provider ?? ctProvider,
                timestampIso: parsed.timestampIso,
                entryTypeLabel: parsed.entryTypeLabel,
                leafSubject: parsed.leafSubject,
                leafIssuer: parsed.leafIssuer
              };

              if (!nextRowsByOrganization[organizationKey]) {
                nextRowsByOrganization[organizationKey] = [];
              }

              nextRowsByOrganization[organizationKey].push(nextRow);
              allRowsToStore.push(nextRow);
            });

            matchedRows += organizationRows.length;
          } catch {
            decodeErrors += 1;
          }
        });

        completedPages += 1;

        setProgress({
          provider: ctProvider,
          completedPages,
          totalPages: PAGE_COUNT,
          checkedEntries,
          matchedRows,
          insertedRows,
          decodeErrors
        });
      }

      insertedRows = await storeOrganizationRows(allRowsToStore);
      setRowsByOrganization(nextRowsByOrganization);
      setProgress({
        provider: ctProvider,
        completedPages: PAGE_COUNT,
        totalPages: PAGE_COUNT,
        checkedEntries,
        matchedRows,
        insertedRows,
        decodeErrors
      });
    } catch (scanError) {
      setError(toErrorMessage(scanError, "Failed to scan CT records."));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="page">
      <section className="hero">
        <p className="eyebrow">Certificate Transparency Utility</p>
        <h1>Organization-Only Records</h1>
        <p>
          Fetches 10 pages of 1024 CT entries (10,240 total), filters out rows with empty organization values, and
          shows all remaining row fields.
        </p>
      </section>

      <form className="decoder-form" onSubmit={handleScan}>
        <div className="range-grid">
          <div>
            <label htmlFor="start">Start Index</label>
            <input
              id="start"
              type="text"
              inputMode="numeric"
              value={start}
              onChange={(event) => setStart(clampDigits(event.target.value))}
              placeholder="325969000"
            />
          </div>
          <div>
            <label htmlFor="organization-provider">CT Provider</label>
            <select
              id="organization-provider"
              value={ctProvider}
              onChange={(event) => setCtProvider(event.target.value as CtProvider)}
            >
              <option value="cloudflare">Cloudflare</option>
              <option value="digicert">DigiCert</option>
            </select>
          </div>
        </div>
        <p className="form-note">
          Page size is fixed at 1024 entries. This scan will call the API 10 times: page 1 is `start..start+1023`,
          then it continues for the next 9 pages.
        </p>

        <div className="actions">
          <button type="submit" disabled={isDisabled}>
            {isLoading ? "Scanning 10 pages..." : "Scan 10 Pages"}
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => {
              setStart("");
              setRowsByOrganization({});
              setError(null);
              setProgress(null);
            }}
          >
            Clear
          </button>
        </div>
      </form>

      {error && (
        <section className="error-box" role="alert">
          <h2>Scan Error</h2>
          <p>{error}</p>
        </section>
      )}

      {progress && (
        <section className="results">
          <h2>Scan Progress</h2>
          <div className="meta-grid">
            <div>
              <label>Pages Completed</label>
              <p>
                {progress.completedPages} / {progress.totalPages}
              </p>
            </div>
            <div>
              <label>Provider</label>
              <p>{progress.provider === "digicert" ? "DigiCert" : "Cloudflare"}</p>
            </div>
            <div>
              <label>Entries Checked</label>
              <p>{progress.checkedEntries}</p>
            </div>
            <div>
              <label>Rows With Organization</label>
              <p>{progress.matchedRows}</p>
            </div>
            <div>
              <label>Rows Stored</label>
              <p>{progress.insertedRows}</p>
            </div>
            <div>
              <label>Organizations Found</label>
              <p>{organizationCount}</p>
            </div>
            <div>
              <label>Decode Errors</label>
              <p>{progress.decodeErrors}</p>
            </div>
          </div>
        </section>
      )}

      {progress && progress.completedPages === PAGE_COUNT && (
        <section className="results">
          <h2>Filtered Records</h2>
          <OrganizationRowsTable rows={rows} />
        </section>
      )}
    </main>
  );
}
