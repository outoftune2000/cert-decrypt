"use client";

import { FormEvent, useMemo, useState } from "react";

type CtProvider = "cloudflare" | "digicert";

type ParsedChainCert = {
  subject: string;
  issuer: string;
  fingerprintSha256: string;
  serialNumber: string;
};

type ParsedEntry = {
  index: number;
  provider: CtProvider;
  providerLabel: string;
  entryType: number;
  entryTypeLabel: string;
  ctTimestampIso: string;
  leafInputSha256: string;
  extraDataSha256: string;
  issuerKeyHashHex: string;
  certFingerprintSha256: string;
  serialNumber: string;
  subject: string;
  issuer: string;
  subjectCommonName: string;
  subjectOrganization: string;
  issuerOrganization: string;
  rootFromCommonName: string;
  dnsSansCount: number;
  dnsSansSample: string[];
  keyType: string;
  keySizeBits: number | null;
  validFromIso: string;
  validToIso: string;
  validityDays: number;
  infoAccess: string;
  chainCount: number;
  chainRootSubject: string;
  chainRootFingerprintSha256: string;
  chainCertificates: ParsedChainCert[];
};

type Assessment = {
  verdict: "likely_related" | "possibly_related" | "low_evidence_of_relation";
  confidence: number;
  reasons: string[];
  counterpoints: string[];
  summary: string;
};

type Comparison = {
  sameEntryType: boolean;
  sameCertFingerprint: boolean;
  sameSerialNumber: boolean;
  sameIssuerDn: boolean;
  sameIssuerOrganization: boolean;
  sameChainRootFingerprint: boolean;
  sameKeyProfile: boolean;
  sameValidityWindow: boolean;
  timestampDeltaSeconds: number;
};

type CompareApiResponse = {
  provider: CtProvider;
  providerLabel: string;
  indexA: number;
  indexB: number;
  entryA: ParsedEntry;
  entryB: ParsedEntry;
  comparison: Comparison;
  assessment: Assessment;
  error?: string;
  details?: string;
};

const clampDigits = (value: string): string => value.replace(/[^\d]/g, "");

const toErrorMessage = (value: unknown, fallback: string): string =>
  value instanceof Error ? value.message : fallback;

const verdictLabel = (verdict: Assessment["verdict"]): string => {
  if (verdict === "likely_related") {
    return "Likely Related";
  }

  if (verdict === "possibly_related") {
    return "Possibly Related";
  }

  return "Low Evidence of Relation";
};

function ComparisonRow({
  label,
  left,
  right
}: {
  label: string;
  left: string | number | boolean | null;
  right: string | number | boolean | null;
}) {
  const leftText = left === null ? "-" : String(left);
  const rightText = right === null ? "-" : String(right);

  return (
    <tr>
      <td>{label}</td>
      <td>{leftText}</td>
      <td>{rightText}</td>
    </tr>
  );
}

export default function IndexComparePage() {
  const [provider, setProvider] = useState<CtProvider>("cloudflare");
  const [indexA, setIndexA] = useState("3291212699");
  const [indexB, setIndexB] = useState("3291211869");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CompareApiResponse | null>(null);

  const isDisabled = useMemo(
    () => isLoading || indexA.trim().length === 0 || indexB.trim().length === 0,
    [isLoading, indexA, indexB]
  );

  const handleCompare = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setResult(null);

    const a = Number(indexA);
    const b = Number(indexB);
    if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b) || a < 0 || b < 0) {
      setError("Both index values must be non-negative whole numbers.");
      return;
    }

    try {
      setIsLoading(true);
      const query = new URLSearchParams({
        provider,
        indexA: String(a),
        indexB: String(b)
      });

      const response = await fetch(`/api/index-compare?${query.toString()}`);
      const payload = (await response.json()) as CompareApiResponse;

      if (!response.ok) {
        const detailSuffix = payload.details ? ` ${payload.details}` : "";
        throw new Error((payload.error ?? `Compare request failed with status ${response.status}.`) + detailSuffix);
      }

      setResult(payload);
    } catch (compareError) {
      setError(toErrorMessage(compareError, "Failed to compare indexes."));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="page">
      <section className="hero">
        <p className="eyebrow">Raw CT Comparator</p>
        <h1>Index Relationship Check</h1>
        <p>
          Compares two CT log indexes using raw `leaf_input` and `extra_data`, then scores relationship confidence
          based on certificate and chain evidence.
        </p>
      </section>

      <form className="decoder-form" onSubmit={handleCompare}>
        <div className="range-grid">
          <div>
            <label htmlFor="compare-provider">Provider</label>
            <select
              id="compare-provider"
              value={provider}
              onChange={(event) => setProvider(event.target.value as CtProvider)}
            >
              <option value="cloudflare">Cloudflare</option>
              <option value="digicert">DigiCert</option>
            </select>
          </div>
          <div>
            <label htmlFor="compare-index-a">Index A</label>
            <input
              id="compare-index-a"
              type="text"
              inputMode="numeric"
              value={indexA}
              onChange={(event) => setIndexA(clampDigits(event.target.value))}
              placeholder="3291212699"
            />
          </div>
          <div>
            <label htmlFor="compare-index-b">Index B</label>
            <input
              id="compare-index-b"
              type="text"
              inputMode="numeric"
              value={indexB}
              onChange={(event) => setIndexB(clampDigits(event.target.value))}
              placeholder="3291211869"
            />
          </div>
        </div>
        <div className="actions">
          <button type="submit" disabled={isDisabled}>
            {isLoading ? "Comparing..." : "Compare Indexes"}
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => {
              setIndexA("");
              setIndexB("");
              setError(null);
              setResult(null);
            }}
          >
            Clear
          </button>
        </div>
      </form>

      {error && (
        <section className="error-box" role="alert">
          <h2>Compare Error</h2>
          <p>{error}</p>
        </section>
      )}

      {result && (
        <>
          <section className="results">
            <h2>Assessment</h2>
            <div className="meta-grid">
              <div>
                <label>Provider</label>
                <p>{result.providerLabel}</p>
              </div>
              <div>
                <label>Index Pair</label>
                <p>
                  {result.indexA} vs {result.indexB}
                </p>
              </div>
              <div>
                <label>Verdict</label>
                <p>{verdictLabel(result.assessment.verdict)}</p>
              </div>
              <div>
                <label>Confidence</label>
                <p>{result.assessment.confidence} / 100</p>
              </div>
              <div>
                <label>CT Timestamp Gap</label>
                <p>{result.comparison.timestampDeltaSeconds.toFixed(3)}s</p>
              </div>
            </div>
            <p>{result.assessment.summary}</p>
          </section>

          <section className="results">
            <h2>Reasons</h2>
            <div className="meta-grid">
              <div>
                <label>Positive Signals</label>
                {result.assessment.reasons.length === 0 ? (
                  <p>None</p>
                ) : (
                  <ul>
                    {result.assessment.reasons.map((reason, index) => (
                      <li key={`reason-${index}`}>{reason}</li>
                    ))}
                  </ul>
                )}
              </div>
              <div>
                <label>Counterpoints</label>
                {result.assessment.counterpoints.length === 0 ? (
                  <p>None</p>
                ) : (
                  <ul>
                    {result.assessment.counterpoints.map((counterpoint, index) => (
                      <li key={`counter-${index}`}>{counterpoint}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </section>

          <section className="results">
            <h2>Side-by-Side Core Fields</h2>
            <div className="rows-scroll">
              <table className="rows-table">
                <thead>
                  <tr>
                    <th>Field</th>
                    <th>Index A ({result.indexA})</th>
                    <th>Index B ({result.indexB})</th>
                  </tr>
                </thead>
                <tbody>
                  <ComparisonRow label="entry_type" left={result.entryA.entryTypeLabel} right={result.entryB.entryTypeLabel} />
                  <ComparisonRow label="ct_timestamp_iso" left={result.entryA.ctTimestampIso} right={result.entryB.ctTimestampIso} />
                  <ComparisonRow label="subject_cn" left={result.entryA.subjectCommonName} right={result.entryB.subjectCommonName} />
                  <ComparisonRow label="root_from_cn" left={result.entryA.rootFromCommonName} right={result.entryB.rootFromCommonName} />
                  <ComparisonRow label="issuer" left={result.entryA.issuer} right={result.entryB.issuer} />
                  <ComparisonRow label="issuer_org" left={result.entryA.issuerOrganization} right={result.entryB.issuerOrganization} />
                  <ComparisonRow label="key_profile" left={`${result.entryA.keyType}/${result.entryA.keySizeBits ?? "?"}`} right={`${result.entryB.keyType}/${result.entryB.keySizeBits ?? "?"}`} />
                  <ComparisonRow label="valid_from_iso" left={result.entryA.validFromIso} right={result.entryB.validFromIso} />
                  <ComparisonRow label="valid_to_iso" left={result.entryA.validToIso} right={result.entryB.validToIso} />
                  <ComparisonRow label="serial_number" left={result.entryA.serialNumber} right={result.entryB.serialNumber} />
                  <ComparisonRow label="cert_fingerprint_sha256" left={result.entryA.certFingerprintSha256} right={result.entryB.certFingerprintSha256} />
                  <ComparisonRow label="chain_root_fingerprint_sha256" left={result.entryA.chainRootFingerprintSha256} right={result.entryB.chainRootFingerprintSha256} />
                  <ComparisonRow label="dns_sans_count" left={result.entryA.dnsSansCount} right={result.entryB.dnsSansCount} />
                </tbody>
              </table>
            </div>
          </section>

          <section className="results">
            <h2>Raw Compare Flags</h2>
            <pre className="json-output">{JSON.stringify(result.comparison, null, 2)}</pre>
          </section>
        </>
      )}
    </main>
  );
}
