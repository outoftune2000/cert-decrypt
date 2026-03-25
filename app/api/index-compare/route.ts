import { NextRequest, NextResponse } from "next/server";
import { createHash, X509Certificate } from "crypto";

type CtProvider = "cloudflare" | "digicert";

type ProviderConfig = {
  endpoint: string;
  label: string;
};

type CtApiEntry = {
  leaf_input: string;
  extra_data: string;
};

type CtApiResponse = {
  entries?: CtApiEntry[];
};

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

const CT_PROVIDER_CONFIG: Record<CtProvider, ProviderConfig> = {
  cloudflare: {
    endpoint: "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/get-entries",
    label: "Cloudflare"
  },
  digicert: {
    endpoint: "https://wyvern.ct.digicert.com/2026h1/ct/v1/get-entries",
    label: "DigiCert"
  }
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

const readUintParam = (value: string | null, label: string): number => {
  if (!value || value.trim().length === 0) {
    throw new Error(`${label} is required.`);
  }

  if (!/^\d+$/.test(value)) {
    throw new Error(`${label} must contain digits only.`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative safe integer.`);
  }

  return parsed;
};

const readProviderParam = (value: string | null): CtProvider => {
  if (!value || value.trim().length === 0) {
    return "cloudflare";
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "cloudflare" || normalized === "digicert") {
    return normalized;
  }

  throw new Error("provider must be either cloudflare or digicert.");
};

const sanitizeBase64 = (value: string): string => {
  const compact = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const missingPad = compact.length % 4;
  return missingPad === 0 ? compact : compact + "=".repeat(4 - missingPad);
};

const decodeBase64 = (value: string): Buffer => Buffer.from(sanitizeBase64(value), "base64");

const readUint24 = (bytes: Buffer, offset: number): number => {
  if (offset + 3 > bytes.length) {
    throw new Error("Unexpected end of data while reading uint24.");
  }

  return (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
};

const extractDnValue = (dn: string, key: string): string => {
  const pattern = new RegExp(`(?:^|[\\n,])\\s*${key}=([^,\\n]+)`, "i");
  const match = dn.match(pattern);
  return match ? match[1].trim() : "";
};

const parseDnsNames = (subjectAltName: string | undefined): string[] => {
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

const normalizeHost = (value: string): string => value.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");

const rootFromHost = (host: string): string => {
  const normalized = normalizeHost(host);
  const labels = normalized.split(".").filter(Boolean);
  if (labels.length < 2) {
    return normalized;
  }

  const lastTwo = labels.slice(-2).join(".");
  const tldLabelCount = labels.length >= 3 && MULTI_LABEL_TLDS.has(lastTwo) ? 2 : 1;
  if (labels.length <= tldLabelCount) {
    return normalized;
  }

  const registrable = labels[labels.length - tldLabelCount - 1];
  const tld = labels.slice(-tldLabelCount).join(".");
  return `${registrable}.${tld}`;
};

const sha256Hex = (bytes: Buffer): string => createHash("sha256").update(bytes).digest("hex");

const computeTimestampIso = (leafBytes: Buffer): string => {
  if (leafBytes.length < 10) {
    return "Invalid timestamp";
  }

  let timestampMs = 0n;
  for (let offset = 2; offset < 10; offset += 1) {
    timestampMs = (timestampMs << 8n) | BigInt(leafBytes[offset]);
  }

  const asNumber = Number(timestampMs);
  return Number.isFinite(asNumber) ? new Date(asNumber).toISOString() : "Invalid timestamp";
};

const parseChainCertificates = (
  entryType: number,
  extraDataBytes: Buffer
): ParsedChainCert[] => {
  let chainStart = 0;
  let chainLength = 0;

  if (entryType === 0) {
    chainLength = readUint24(extraDataBytes, 0);
    chainStart = 3;
  } else if (entryType === 1) {
    const precertLength = readUint24(extraDataBytes, 0);
    const chainLengthOffset = 3 + precertLength;
    chainLength = readUint24(extraDataBytes, chainLengthOffset);
    chainStart = chainLengthOffset + 3;
  } else {
    return [];
  }

  const chainEnd = chainStart + chainLength;
  if (chainEnd > extraDataBytes.length) {
    throw new Error("Certificate chain extends beyond available extra_data bytes.");
  }

  const certificates: ParsedChainCert[] = [];
  let cursor = chainStart;

  while (cursor < chainEnd) {
    const certLength = readUint24(extraDataBytes, cursor);
    cursor += 3;
    const certEnd = cursor + certLength;

    if (certEnd > chainEnd) {
      throw new Error("Chain certificate length exceeds chain boundary.");
    }

    const certDer = extraDataBytes.subarray(cursor, certEnd);
    const cert = new X509Certificate(certDer);

    certificates.push({
      subject: cert.subject,
      issuer: cert.issuer,
      fingerprintSha256: cert.fingerprint256.replace(/:/g, "").toLowerCase(),
      serialNumber: cert.serialNumber.toLowerCase()
    });

    cursor = certEnd;
  }

  return certificates;
};

const extractLeafCertDer = (entryType: number, leafBytes: Buffer, extraBytes: Buffer): Buffer => {
  if (entryType === 0) {
    const certLength = readUint24(leafBytes, 12);
    const certStart = 15;
    const certEnd = certStart + certLength;

    if (certEnd > leafBytes.length) {
      throw new Error("Leaf certificate length exceeds available leaf_input bytes.");
    }

    return leafBytes.subarray(certStart, certEnd);
  }

  if (entryType === 1) {
    const precertLength = readUint24(extraBytes, 0);
    const precertStart = 3;
    const precertEnd = precertStart + precertLength;

    if (precertEnd > extraBytes.length) {
      throw new Error("Precertificate length exceeds available extra_data bytes.");
    }

    return extraBytes.subarray(precertStart, precertEnd);
  }

  throw new Error(`Unsupported entry type: ${entryType}.`);
};

const fetchRawCtEntry = async (index: number, provider: CtProvider): Promise<CtApiEntry> => {
  const config = CT_PROVIDER_CONFIG[provider];
  const target = new URL(config.endpoint);
  target.searchParams.set("start", String(index));
  target.searchParams.set("end", String(index));

  const response = await fetch(target.toString(), {
    headers: {
      "User-Agent": "yaak",
      Accept: "*/*"
    },
    cache: "no-store"
  });

  if (!response.ok) {
    const details = (await response.text()).slice(0, 500);
    throw new Error(`${config.label} CT endpoint returned ${response.status}: ${details}`);
  }

  const payload = (await response.json()) as CtApiResponse;
  const entry = payload.entries?.[0];

  if (!entry || typeof entry.leaf_input !== "string" || typeof entry.extra_data !== "string") {
    throw new Error(`${config.label} CT response did not include a valid entry at index ${index}.`);
  }

  return entry;
};

const parseEntry = async (index: number, provider: CtProvider): Promise<ParsedEntry> => {
  const providerConfig = CT_PROVIDER_CONFIG[provider];
  const rawEntry = await fetchRawCtEntry(index, provider);
  const leafBytes = decodeBase64(rawEntry.leaf_input);
  const extraBytes = decodeBase64(rawEntry.extra_data);

  if (leafBytes.length < 12) {
    throw new Error("leaf_input is too short to contain CT metadata.");
  }

  const entryType = (leafBytes[10] << 8) | leafBytes[11];
  const entryTypeLabel = entryType === 0 ? "x509_entry" : entryType === 1 ? "precert_entry" : `unknown_${entryType}`;
  const issuerKeyHashHex = entryType === 1 ? leafBytes.subarray(12, 44).toString("hex") : "";
  const leafCertDer = extractLeafCertDer(entryType, leafBytes, extraBytes);
  const leafCert = new X509Certificate(leafCertDer);
  const keyDetails = (leafCert.publicKey.asymmetricKeyDetails ?? {}) as { modulusLength?: number };
  const keySizeBits = typeof keyDetails.modulusLength === "number" ? keyDetails.modulusLength : null;
  const dnsSans = parseDnsNames(leafCert.subjectAltName);
  const subjectCommonName = extractDnValue(leafCert.subject, "CN");
  const chainCertificates = parseChainCertificates(entryType, extraBytes);
  const chainRoot = chainCertificates.length > 0 ? chainCertificates[chainCertificates.length - 1] : null;

  const validFromDate = new Date(leafCert.validFrom);
  const validToDate = new Date(leafCert.validTo);
  const validityDays = Math.round((validToDate.getTime() - validFromDate.getTime()) / 86_400_000);

  return {
    index,
    provider,
    providerLabel: providerConfig.label,
    entryType,
    entryTypeLabel,
    ctTimestampIso: computeTimestampIso(leafBytes),
    leafInputSha256: sha256Hex(leafBytes),
    extraDataSha256: sha256Hex(extraBytes),
    issuerKeyHashHex,
    certFingerprintSha256: leafCert.fingerprint256.replace(/:/g, "").toLowerCase(),
    serialNumber: leafCert.serialNumber.toLowerCase(),
    subject: leafCert.subject,
    issuer: leafCert.issuer,
    subjectCommonName,
    subjectOrganization: extractDnValue(leafCert.subject, "O"),
    issuerOrganization: extractDnValue(leafCert.issuer, "O"),
    rootFromCommonName: rootFromHost(subjectCommonName),
    dnsSansCount: dnsSans.length,
    dnsSansSample: dnsSans.slice(0, 10),
    keyType: leafCert.publicKey.asymmetricKeyType ?? "unknown",
    keySizeBits,
    validFromIso: validFromDate.toISOString(),
    validToIso: validToDate.toISOString(),
    validityDays,
    infoAccess: leafCert.infoAccess ?? "",
    chainCount: chainCertificates.length,
    chainRootSubject: chainRoot?.subject ?? "",
    chainRootFingerprintSha256: chainRoot?.fingerprintSha256 ?? "",
    chainCertificates
  };
};

type Assessment = {
  verdict: "likely_related" | "possibly_related" | "low_evidence_of_relation";
  confidence: number;
  reasons: string[];
  counterpoints: string[];
  summary: string;
};

const buildAssessment = (left: ParsedEntry, right: ParsedEntry): Assessment => {
  const reasons: string[] = [];
  const counterpoints: string[] = [];
  let score = 20;

  const sameFingerprint = left.certFingerprintSha256 === right.certFingerprintSha256;
  const sameSerial = left.serialNumber === right.serialNumber;
  const sameChainRoot =
    left.chainRootFingerprintSha256.length > 0 &&
    right.chainRootFingerprintSha256.length > 0 &&
    left.chainRootFingerprintSha256 === right.chainRootFingerprintSha256;
  const sameIssuerOrg =
    left.issuerOrganization.length > 0 &&
    right.issuerOrganization.length > 0 &&
    left.issuerOrganization === right.issuerOrganization;
  const sameIssuer = left.issuer === right.issuer;
  const sameEntryType = left.entryType === right.entryType;
  const sameKeyProfile = left.keyType === right.keyType && left.keySizeBits === right.keySizeBits;
  const sameValidityWindow = left.validFromIso === right.validFromIso && left.validToIso === right.validToIso;

  const timestampDeltaSeconds =
    Math.abs(new Date(left.ctTimestampIso).getTime() - new Date(right.ctTimestampIso).getTime()) / 1000;

  if (sameFingerprint) {
    score += 45;
    reasons.push("Leaf certificate fingerprint is identical.");
  } else {
    counterpoints.push("Leaf certificate fingerprints are different.");
  }

  if (sameSerial) {
    score += 25;
    reasons.push("Certificate serial number is identical.");
  } else {
    counterpoints.push("Certificate serial numbers are different.");
  }

  if (sameChainRoot) {
    score += 18;
    reasons.push("Both chains terminate at the same root certificate fingerprint.");
  } else {
    counterpoints.push("Root certificate fingerprints differ or are unavailable.");
  }

  if (sameIssuerOrg) {
    score += 12;
    reasons.push(`Issuer organization matches (${left.issuerOrganization}).`);
  } else if (left.issuerOrganization && right.issuerOrganization) {
    score -= 10;
    counterpoints.push(`Issuer organizations differ (${left.issuerOrganization} vs ${right.issuerOrganization}).`);
  }

  if (sameIssuer) {
    score += 8;
    reasons.push("Issuer distinguished name is identical.");
  } else {
    counterpoints.push("Issuer distinguished names differ.");
  }

  if (sameEntryType) {
    score += 4;
    reasons.push(`Both entries are ${left.entryTypeLabel}.`);
  } else {
    score -= 4;
    counterpoints.push("Entry types differ.");
  }

  if (sameKeyProfile) {
    score += 6;
    reasons.push(`Both use ${left.keyType.toUpperCase()} ${left.keySizeBits ?? "?"}-bit keys.`);
  } else {
    score -= 6;
    counterpoints.push("Key profile differs.");
  }

  if (sameValidityWindow) {
    score += 10;
    reasons.push("Validity windows are identical.");
  } else {
    counterpoints.push("Validity windows are different.");
  }

  if (Number.isFinite(timestampDeltaSeconds)) {
    if (timestampDeltaSeconds <= 60) {
      score += 6;
      reasons.push(`CT timestamps are very close (${timestampDeltaSeconds.toFixed(3)}s apart).`);
    } else if (timestampDeltaSeconds <= 600) {
      score += 3;
      reasons.push(`CT timestamps are moderately close (${timestampDeltaSeconds.toFixed(3)}s apart).`);
    }
  }

  if (
    left.rootFromCommonName.length > 0 &&
    right.rootFromCommonName.length > 0 &&
    left.rootFromCommonName !== right.rootFromCommonName
  ) {
    score -= 6;
    counterpoints.push(
      `Subject CN roots differ (${left.rootFromCommonName} vs ${right.rootFromCommonName}).`
    );
  }

  const confidence = Math.max(0, Math.min(100, Math.round(score)));

  const verdict: Assessment["verdict"] =
    confidence >= 70 ? "likely_related" : confidence >= 40 ? "possibly_related" : "low_evidence_of_relation";

  const summary =
    verdict === "likely_related"
      ? "There is strong technical overlap in certificate-chain and issuance characteristics."
      : verdict === "possibly_related"
        ? "There are some shared signals, but not enough to claim a strong relationship."
        : "The overlap is weak; these entries likely represent distinct issuance contexts.";

  return {
    verdict,
    confidence,
    reasons,
    counterpoints,
    summary
  };
};

export async function GET(request: NextRequest) {
  let indexA: number;
  let indexB: number;
  let provider: CtProvider;

  try {
    indexA = readUintParam(request.nextUrl.searchParams.get("indexA"), "indexA");
    indexB = readUintParam(request.nextUrl.searchParams.get("indexB"), "indexB");
    provider = readProviderParam(request.nextUrl.searchParams.get("provider"));
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Invalid query parameters." },
      { status: 400 }
    );
  }

  try {
    const [entryA, entryB] = await Promise.all([parseEntry(indexA, provider), parseEntry(indexB, provider)]);
    const assessment = buildAssessment(entryA, entryB);

    const comparison = {
      sameEntryType: entryA.entryType === entryB.entryType,
      sameCertFingerprint: entryA.certFingerprintSha256 === entryB.certFingerprintSha256,
      sameSerialNumber: entryA.serialNumber === entryB.serialNumber,
      sameIssuerDn: entryA.issuer === entryB.issuer,
      sameIssuerOrganization:
        entryA.issuerOrganization.length > 0 &&
        entryB.issuerOrganization.length > 0 &&
        entryA.issuerOrganization === entryB.issuerOrganization,
      sameChainRootFingerprint:
        entryA.chainRootFingerprintSha256.length > 0 &&
        entryB.chainRootFingerprintSha256.length > 0 &&
        entryA.chainRootFingerprintSha256 === entryB.chainRootFingerprintSha256,
      sameKeyProfile: entryA.keyType === entryB.keyType && entryA.keySizeBits === entryB.keySizeBits,
      sameValidityWindow: entryA.validFromIso === entryB.validFromIso && entryA.validToIso === entryB.validToIso,
      timestampDeltaSeconds:
        Math.abs(new Date(entryA.ctTimestampIso).getTime() - new Date(entryB.ctTimestampIso).getTime()) / 1000
    };

    return NextResponse.json({
      provider,
      providerLabel: CT_PROVIDER_CONFIG[provider].label,
      indexA,
      indexB,
      entryA,
      entryB,
      comparison,
      assessment
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: "Failed to compare CT entries.",
        details: error instanceof Error ? error.message : "Unknown comparison error."
      },
      { status: 502 }
    );
  }
}
