import {
  AuthorityInfoAccessExtension,
  CRLDistributionPointsExtension,
  SubjectAlternativeNameExtension,
  X509Certificate
} from "@peculiar/x509";

type ChainEntry = {
  index: number;
  length: number;
  subject: string;
  issuer: string;
};

type CertRowMeta = {
  issuer: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  key_algorithm: string;
  key_size: number;
  signature_algorithm: string;
  ocsp_url: string;
  crl_url: string;
  location: string;
  organization: string;
};

export type ParsedDomainRow = {
  ip_address: string;
  domain_full: string;
  domain_base: string;
  root_domain: string;
  tld: string;
  subdomain: string;
  issuer: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  key_algorithm: string;
  key_size: number;
  signature_algorithm: string;
  ocsp_url: string;
  crl_url: string;
  location: string;
  organization: string;
};

export type ParsedCtEntry = {
  version: number;
  leafType: number;
  entryType: number;
  entryTypeLabel: string;
  timestampMs: bigint;
  timestampIso: string;
  certLength: number;
  extensionsLength: number;
  leafCertificateSource: string;
  issuerKeyHashHex?: string;
  leafSubject: string;
  leafIssuer: string;
  domains: ParsedDomainRow[];
  chainTotalLength: number;
  chainEntries: ChainEntry[];
};

type LeafCertificateSummary = {
  subject: string;
  issuer: string;
  domains: ParsedDomainRow[];
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

const CURVE_SIZE_MAP: Record<string, number> = {
  "P-256": 256,
  "P-384": 384,
  "P-521": 521,
  secp256k1: 256,
  Ed25519: 256,
  Ed448: 456,
  X25519: 256,
  X448: 448
};

const sanitizeBase64 = (value: string): string =>
  value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");

const decodeBase64ToBytes = (input: string): Uint8Array => {
  const normalized = sanitizeBase64(input);

  if (!normalized) {
    throw new Error("Input is empty.");
  }

  const padded =
    normalized.length % 4 === 0
      ? normalized
      : normalized + "=".repeat(4 - (normalized.length % 4));

  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("Invalid Base64 input.");
  }

  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
};

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

const readUint24 = (bytes: Uint8Array, offset: number): number => {
  if (offset + 3 > bytes.length) {
    throw new Error("Unexpected end of data while reading 3-byte length.");
  }
  return (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
};

const readUint16 = (bytes: Uint8Array, offset: number): number => {
  if (offset + 2 > bytes.length) {
    throw new Error("Unexpected end of data while reading 2-byte length.");
  }
  return (bytes[offset] << 8) | bytes[offset + 1];
};

export const extractLeafCertificateDer = (leafInputB64: string, extraDataB64: string): Uint8Array => {
  const leafBytes = decodeBase64ToBytes(leafInputB64);
  const extraBytes = decodeBase64ToBytes(extraDataB64);

  if (leafBytes.length < 12) {
    throw new Error("Leaf input is too short to contain CT metadata.");
  }

  const entryType = readUint16(leafBytes, 10);

  if (entryType === 0) {
    const certLength = readUint24(leafBytes, 12);
    const certStart = 15;
    const certEnd = certStart + certLength;

    if (certEnd > leafBytes.length) {
      throw new Error("Leaf certificate length exceeds available leaf input bytes.");
    }

    return leafBytes.slice(certStart, certEnd);
  }

  if (entryType === 1) {
    if (extraBytes.length < 3) {
      throw new Error("Extra data is too short to contain precertificate length.");
    }

    const precertLength = readUint24(extraBytes, 0);
    const precertStart = 3;
    const precertEnd = precertStart + precertLength;

    if (precertEnd > extraBytes.length) {
      throw new Error("Precertificate length exceeds available extra data bytes.");
    }

    return extraBytes.slice(precertStart, precertEnd);
  }

  throw new Error(`Unsupported entry type: ${entryType}.`);
};

export const getLeafCertificateFingerprintSha256 = async (
  leafInputB64: string,
  extraDataB64: string
): Promise<string> => {
  const leafDer = extractLeafCertificateDer(leafInputB64, extraDataB64);

  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is unavailable in this environment.");
  }

  const leafDerBuffer = leafDer.buffer.slice(
    leafDer.byteOffset,
    leafDer.byteOffset + leafDer.byteLength
  ) as ArrayBuffer;
  const digest = await globalThis.crypto.subtle.digest("SHA-256", leafDerBuffer);
  return toHex(new Uint8Array(digest));
};

const isIpv4 = (value: string): boolean =>
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value);

const isIpv6 = (value: string): boolean => /^[0-9a-f:]+$/i.test(value) && value.includes(":");

const clampUint16 = (value: number): number => {
  if (!Number.isFinite(value) || value < 0) {
    return 0;
  }

  return Math.min(65535, Math.round(value));
};

const normalizeIpToIpv6 = (value: string): string => {
  const normalized = value.trim().toLowerCase();

  if (isIpv6(normalized)) {
    return normalized;
  }

  if (isIpv4(normalized)) {
    return `::ffff:${normalized}`;
  }

  return "::";
};

const formatDateTimeUtc = (date: Date): string => {
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  const iso = date.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)}`;
};

const firstHttpUrl = (value: string): string => {
  const match = value.match(/https?:\/\/[^\s,")\]]+/i);
  return match ? match[0] : "";
};

const extractDnValue = (subject: string, key: string): string => {
  const expression = new RegExp(`(?:^|,\\s*)${key}=((?:\\\\.|[^,])+)`, "i");
  const match = subject.match(expression);
  if (!match) {
    return "";
  }

  return match[1].replace(/\\,/g, ",").replace(/\\\\/g, "\\").trim();
};

const extractCommonNames = (subject: string): string[] => {
  const matches = subject.match(/(?:^|,\s*)CN=([^,]+)/g);
  if (!matches) {
    return [];
  }

  return matches.map((match) => match.replace(/(?:^|,\s*)CN=/, "").trim()).filter(Boolean);
};

const getPublicKeyInfo = (cert: X509Certificate): { keyAlgorithm: string; keySize: number } => {
  const algorithm = cert.publicKey.algorithm as Algorithm & {
    name?: string;
    modulusLength?: number;
    namedCurve?: string;
  };

  const keyAlgorithm = typeof algorithm?.name === "string" ? algorithm.name : "unknown";

  if (typeof algorithm?.modulusLength === "number") {
    return {
      keyAlgorithm,
      keySize: clampUint16(algorithm.modulusLength)
    };
  }

  if (typeof algorithm?.namedCurve === "string") {
    return {
      keyAlgorithm,
      keySize: clampUint16(CURVE_SIZE_MAP[algorithm.namedCurve] ?? 0)
    };
  }

  return {
    keyAlgorithm,
    keySize: 0
  };
};

const getSignatureAlgorithm = (cert: X509Certificate): string => {
  const signature = cert.signatureAlgorithm as Algorithm & {
    hash?: {
      name?: string;
    };
  };

  const algorithmName = typeof signature?.name === "string" ? signature.name : "unknown";
  const hashName = signature?.hash?.name;

  return typeof hashName === "string" ? `${algorithmName} with ${hashName}` : algorithmName;
};

const getOcspUrl = (cert: X509Certificate): string => {
  const aia = cert.getExtension(AuthorityInfoAccessExtension);
  if (!aia) {
    return "";
  }

  const directUrl = aia.ocsp.map((item) => item.value).find((value) => /^https?:\/\//i.test(value));
  if (directUrl) {
    return directUrl;
  }

  try {
    return firstHttpUrl(aia.toString("text"));
  } catch {
    return "";
  }
};

const getCrlUrl = (cert: X509Certificate): string => {
  const crl = cert.getExtension(CRLDistributionPointsExtension);
  if (!crl) {
    return "";
  }

  try {
    return firstHttpUrl(crl.toString("text"));
  } catch {
    return "";
  }
};

const toDomainRow = (value: string, meta: CertRowMeta): ParsedDomainRow | null => {
  const normalizedFull = value.trim().toLowerCase().replace(/\.$/, "");

  if (!normalizedFull) {
    return null;
  }

  if (isIpv4(normalizedFull) || isIpv6(normalizedFull)) {
    return {
      ip_address: normalizeIpToIpv6(normalizedFull),
      domain_full: "",
      domain_base: "",
      root_domain: "",
      tld: "",
      subdomain: "",
      ...meta
    };
  }

  const hostLike = normalizedFull.startsWith("*.") ? normalizedFull.slice(2) : normalizedFull;
  const labels = hostLike.split(".").filter(Boolean);

  if (labels.length < 2) {
    return null;
  }

  const lastTwo = labels.slice(-2).join(".");
  const tldLabelCount = labels.length >= 3 && MULTI_LABEL_TLDS.has(lastTwo) ? 2 : 1;

  if (labels.length <= tldLabelCount) {
    return null;
  }

  const tld = labels.slice(-tldLabelCount).join(".");
  const root = labels[labels.length - tldLabelCount - 1];
  const domainBase = `${root}.${tld}`;
  const subdomain =
    labels.length > tldLabelCount + 1 ? labels.slice(0, labels.length - tldLabelCount - 1).join(".") : "";

  return {
    ip_address: "::",
    domain_full: normalizedFull,
    domain_base: domainBase,
    root_domain: root,
    tld,
    subdomain,
    ...meta
  };
};

const buildDomainRows = (
  dnsNames: string[],
  ipNames: string[],
  commonNames: string[],
  certMeta: CertRowMeta
): ParsedDomainRow[] => {
  const seen = new Set<string>();
  const rows: ParsedDomainRow[] = [];

  const pushRow = (candidate: string) => {
    const row = toDomainRow(candidate, certMeta);
    if (!row) {
      return;
    }

    const key = [
      row.ip_address,
      row.domain_full,
      row.domain_base,
      row.root_domain,
      row.tld,
      row.subdomain,
      row.issuer,
      row.not_before,
      row.not_after,
      row.serial_number,
      row.key_algorithm,
      String(row.key_size),
      row.signature_algorithm,
      row.ocsp_url,
      row.crl_url,
      row.location,
      row.organization
    ].join("|");

    if (seen.has(key)) {
      return;
    }

    seen.add(key);
    rows.push(row);
  };

  dnsNames.forEach(pushRow);
  ipNames.forEach(pushRow);
  commonNames.forEach(pushRow);

  return rows;
};

const readCertSummary = (der: Uint8Array): LeafCertificateSummary => {
  try {
    const cert = new X509Certificate(new Uint8Array(der));
    const san = cert.getExtension(SubjectAlternativeNameExtension);
    const dnsNames: string[] = [];
    const ipNames: string[] = [];

    if (san) {
      san.names.items.forEach((item) => {
        if (item.type === "dns") {
          dnsNames.push(item.value);
        } else if (item.type === "ip") {
          ipNames.push(item.value);
        }
      });
    }

    const commonNames = extractCommonNames(cert.subject);
    const organization = extractDnValue(cert.subject, "O");
    const locality = extractDnValue(cert.subject, "L");
    const state = extractDnValue(cert.subject, "ST");
    const country = extractDnValue(cert.subject, "C");
    const location = [locality, state, country].filter(Boolean).join(", ");
    const keyInfo = getPublicKeyInfo(cert);
    const certMeta: CertRowMeta = {
      issuer: cert.issuer,
      not_before: formatDateTimeUtc(cert.notBefore),
      not_after: formatDateTimeUtc(cert.notAfter),
      serial_number: cert.serialNumber,
      key_algorithm: keyInfo.keyAlgorithm,
      key_size: keyInfo.keySize,
      signature_algorithm: getSignatureAlgorithm(cert),
      ocsp_url: getOcspUrl(cert),
      crl_url: getCrlUrl(cert),
      location,
      organization
    };

    return {
      subject: cert.subject,
      issuer: cert.issuer,
      domains: buildDomainRows(dnsNames, ipNames, commonNames, certMeta)
    };
  } catch {
    throw new Error("Failed to parse DER certificate.");
  }
};

const parseChainCertificates = (
  bytes: Uint8Array,
  startOffset: number,
  totalLength: number
): ChainEntry[] => {
  const chainEnd = startOffset + totalLength;
  if (chainEnd > bytes.length) {
    throw new Error("Certificate chain length exceeds available extra data bytes.");
  }

  const chainEntries: ChainEntry[] = [];
  let cursor = startOffset;
  let index = 1;

  while (cursor < chainEnd) {
    const certLen = readUint24(bytes, cursor);
    cursor += 3;

    const certEndOffset = cursor + certLen;
    if (certEndOffset > chainEnd) {
      throw new Error(`Chain certificate #${index} length exceeds declared chain bytes.`);
    }

    const certDer = bytes.slice(cursor, certEndOffset);
    const summary = readCertSummary(certDer);
    chainEntries.push({
      index,
      length: certLen,
      subject: summary.subject,
      issuer: summary.issuer
    });

    cursor = certEndOffset;
    index += 1;
  }

  return chainEntries;
};

export const parseCtEntry = (leafInputB64: string, extraDataB64: string): ParsedCtEntry => {
  const leafBytes = decodeBase64ToBytes(leafInputB64);
  const extraBytes = decodeBase64ToBytes(extraDataB64);

  if (leafBytes.length < 12) {
    throw new Error("Leaf input is too short to contain CT metadata.");
  }

  const version = leafBytes[0];
  const leafType = leafBytes[1];
  const entryType = readUint16(leafBytes, 10);
  const timestampMs = leafBytes
    .slice(2, 10)
    .reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);

  let certLength = 0;
  let extensionsLength = 0;
  let leafCertificateSource = "leaf_input";
  let issuerKeyHashHex: string | undefined;
  let leafSummary: LeafCertificateSummary | null = null;
  let chainTotalLength = 0;
  let chainEntries: ChainEntry[] = [];

  if (entryType === 0) {
    certLength = readUint24(leafBytes, 12);
    const certStart = 15;
    const certEnd = certStart + certLength;

    if (certEnd > leafBytes.length) {
      throw new Error("Leaf certificate length exceeds available leaf input bytes.");
    }

    const leafCertDer = leafBytes.slice(certStart, certEnd);
    leafSummary = readCertSummary(leafCertDer);

    extensionsLength = readUint16(leafBytes, certEnd);

    if (extraBytes.length < 3) {
      throw new Error("Extra data is too short to contain chain length.");
    }

    chainTotalLength = readUint24(extraBytes, 0);
    chainEntries = parseChainCertificates(extraBytes, 3, chainTotalLength);
  } else if (entryType === 1) {
    if (leafBytes.length < 49) {
      throw new Error("Leaf input is too short for a precertificate entry.");
    }

    const issuerKeyHash = leafBytes.slice(12, 44);
    issuerKeyHashHex = Array.from(issuerKeyHash)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    certLength = readUint24(leafBytes, 44);
    const tbsStart = 47;
    const tbsEnd = tbsStart + certLength;
    if (tbsEnd > leafBytes.length) {
      throw new Error("Precertificate TBS length exceeds available leaf input bytes.");
    }

    extensionsLength = readUint16(leafBytes, tbsEnd);

    if (extraBytes.length < 6) {
      throw new Error("Extra data is too short for a precertificate chain entry.");
    }

    const precertLength = readUint24(extraBytes, 0);
    const precertStart = 3;
    const precertEnd = precertStart + precertLength;
    if (precertEnd > extraBytes.length) {
      throw new Error("Precertificate length exceeds available extra data bytes.");
    }

    leafSummary = readCertSummary(extraBytes.slice(precertStart, precertEnd));
    leafCertificateSource = "extra_data (precertificate)";

    chainTotalLength = readUint24(extraBytes, precertEnd);
    chainEntries = parseChainCertificates(extraBytes, precertEnd + 3, chainTotalLength);
  } else {
    throw new Error(`Unsupported entry type: ${entryType}.`);
  }

  if (!leafSummary) {
    throw new Error("Failed to extract leaf certificate details.");
  }

  const entryTypeLabel =
    entryType === 0 ? "x509_entry" : entryType === 1 ? "precert_entry" : "unknown";

  const timestampNumber = Number(timestampMs);
  const timestampIso = Number.isFinite(timestampNumber)
    ? new Date(timestampNumber).toISOString()
    : "Invalid timestamp range";

  return {
    version,
    leafType,
    entryType,
    entryTypeLabel,
    timestampMs,
    timestampIso,
    certLength,
    extensionsLength,
    leafCertificateSource,
    issuerKeyHashHex,
    leafSubject: leafSummary.subject,
    leafIssuer: leafSummary.issuer,
    domains: leafSummary.domains,
    chainTotalLength,
    chainEntries
  };
};
