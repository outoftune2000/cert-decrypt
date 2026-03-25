"use client";

import { FormEvent, useMemo, useState } from "react";

type SourceFilter = "all" | "cloudflare" | "digicert";

type DomainLookupRow = {
  rootDomain: string;
  subdomain: string;
  source: string;
  seenCount: number;
  firstSeen: string;
  lastSeen: string;
  latestIndex: number;
  validFrom: string | null;
  validTo: string | null;
  isValidNow: boolean;
  validitySecondsRemaining: number;
  validityRemaining: string;
};

type DomainLookupSummary = {
  subdomainSourceRows: number;
  uniqueSubdomains: number;
  totalEvents: number;
  firstSeen: string | null;
  lastSeen: string | null;
};

type DomainLookupResponse = {
  requestedDomain: string;
  rootDomain: string;
  source: SourceFilter;
  summary: DomainLookupSummary;
  rows: DomainLookupRow[];
  error?: string;
  details?: string;
};

const toErrorMessage = (value: unknown, fallback: string): string =>
  value instanceof Error ? value.message : fallback;

export default function DomainLookupPage() {
  const [domain, setDomain] = useState("ford.com");
  const [source, setSource] = useState<SourceFilter>("all");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DomainLookupResponse | null>(null);

  const isDisabled = useMemo(() => isLoading || domain.trim().length === 0, [isLoading, domain]);

  const handleLookup = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setResult(null);

    if (domain.trim().length === 0) {
      setError("Domain is required.");
      return;
    }

    try {
      setIsLoading(true);
      const query = new URLSearchParams({
        domain: domain.trim(),
        source
      });

      const response = await fetch(`/api/root-domain/subdomains?${query.toString()}`);
      const payload = (await response.json()) as DomainLookupResponse;

      if (!response.ok) {
        const detailSuffix = payload.details ? ` ${payload.details}` : "";
        throw new Error((payload.error ?? `Domain lookup failed with status ${response.status}.`) + detailSuffix);
      }

      if (!Array.isArray(payload.rows) || typeof payload.rootDomain !== "string") {
        throw new Error("Unexpected domain lookup response format.");
      }

      setResult(payload);
    } catch (lookupError) {
      setError(toErrorMessage(lookupError, "Domain lookup failed."));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="page">
      <section className="hero">
        <p className="eyebrow">Root Domain Search</p>
        <h1>Domain Subdomain Lookup</h1>
        <p>
          Enter a domain, normalize it to a root domain, and list all matching subdomains with source, seen count,
          latest index, and certificate validity details.
        </p>
      </section>

      <form className="decoder-form" onSubmit={handleLookup}>
        <div className="range-grid">
          <div>
            <label htmlFor="lookup-domain">Domain</label>
            <input
              id="lookup-domain"
              type="text"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="ford.com"
            />
          </div>
          <div>
            <label htmlFor="lookup-source">Source</label>
            <select
              id="lookup-source"
              value={source}
              onChange={(event) => setSource(event.target.value as SourceFilter)}
            >
              <option value="all">All Sources</option>
              <option value="cloudflare">Cloudflare</option>
              <option value="digicert">DigiCert</option>
            </select>
          </div>
        </div>

        <div className="actions">
          <button type="submit" disabled={isDisabled}>
            {isLoading ? "Looking Up..." : "Lookup Subdomains"}
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => {
              setDomain("");
              setResult(null);
              setError(null);
            }}
          >
            Clear
          </button>
        </div>
      </form>

      {error && (
        <section className="error-box" role="alert">
          <h2>Lookup Error</h2>
          <p>{error}</p>
        </section>
      )}

      {result && (
        <section className="results">
          <h2>Lookup Results</h2>
          <div className="meta-grid">
            <div>
              <label>Requested Domain</label>
              <p>{result.requestedDomain}</p>
            </div>
            <div>
              <label>Normalized Root Domain</label>
              <p>{result.rootDomain}</p>
            </div>
            <div>
              <label>Source Filter</label>
              <p>{result.source === "all" ? "All Sources" : result.source}</p>
            </div>
            <div>
              <label>Subdomain Rows</label>
              <p>{result.summary.subdomainSourceRows}</p>
            </div>
            <div>
              <label>Unique Subdomains</label>
              <p>{result.summary.uniqueSubdomains}</p>
            </div>
            <div>
              <label>Total Events</label>
              <p>{result.summary.totalEvents}</p>
            </div>
            <div>
              <label>First Seen</label>
              <p>{result.summary.firstSeen ?? "-"}</p>
            </div>
            <div>
              <label>Last Seen</label>
              <p>{result.summary.lastSeen ?? "-"}</p>
            </div>
          </div>

          {result.rows.length === 0 ? (
            <p>No subdomains found for this root domain/source combination.</p>
          ) : (
            <div className="rows-scroll">
              <table className="rows-table">
                <thead>
                  <tr>
                    <th>root_domain</th>
                    <th>subdomain</th>
                    <th>source</th>
                    <th>seen_count</th>
                    <th>latest_index</th>
                    <th>valid_from</th>
                    <th>valid_to</th>
                    <th>is_valid_now</th>
                    <th>validity_remaining</th>
                    <th>first_seen</th>
                    <th>last_seen</th>
                  </tr>
                </thead>
                <tbody>
                  {result.rows.map((row, index) => (
                    <tr key={`${row.rootDomain}-${row.subdomain}-${row.source}-${index}`}>
                      <td>{row.rootDomain}</td>
                      <td>{row.subdomain}</td>
                      <td>{row.source}</td>
                      <td>{row.seenCount}</td>
                      <td>{row.latestIndex}</td>
                      <td>{row.validFrom ?? "-"}</td>
                      <td>{row.validTo ?? "-"}</td>
                      <td>{row.isValidNow ? "yes" : "no"}</td>
                      <td>{row.validityRemaining}</td>
                      <td>{row.firstSeen}</td>
                      <td>{row.lastSeen}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </main>
  );
}
