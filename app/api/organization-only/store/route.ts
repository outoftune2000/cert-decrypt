import { NextRequest, NextResponse } from "next/server";
import { CLICKHOUSE_DATABASE, executeClickHouseCommand, insertJsonEachRow } from "@/lib/clickhouse";

type StoreRequestPayload = {
  rows?: unknown;
};

type StoreableOrganizationRow = {
  organization: string;
  log_index: number;
  source_page: number;
  timestamp_utc: string;
  entry_type: string;
  leaf_subject: string;
  leaf_issuer: string;
  domain_full: string;
  root_domain: string;
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
  ip_address: string;
  domain_base: string;
  tld: string;
};

const TABLE_NAME = "organization_only_records";
let ensureTablePromise: Promise<void> | null = null;

const toStringValue = (value: unknown): string => (typeof value === "string" ? value : "");

const toUInt = (value: unknown): number => {
  const parsed = typeof value === "number" ? value : Number(value);

  if (!Number.isFinite(parsed) || parsed < 0) {
    return 0;
  }

  return Math.trunc(parsed);
};

const normalizeRow = (value: unknown): StoreableOrganizationRow | null => {
  if (typeof value !== "object" || value === null) {
    return null;
  }

  const row = value as Record<string, unknown>;
  const organization = toStringValue(row.organization).trim();

  if (organization.length === 0) {
    return null;
  }

  return {
    organization,
    log_index: toUInt(row.logIndex),
    source_page: toUInt(row.sourcePage),
    timestamp_utc: toStringValue(row.timestampIso),
    entry_type: toStringValue(row.entryTypeLabel),
    leaf_subject: toStringValue(row.leafSubject),
    leaf_issuer: toStringValue(row.leafIssuer),
    domain_full: toStringValue(row.domain_full),
    root_domain: toStringValue(row.root_domain),
    subdomain: toStringValue(row.subdomain),
    issuer: toStringValue(row.issuer),
    not_before: toStringValue(row.not_before),
    not_after: toStringValue(row.not_after),
    serial_number: toStringValue(row.serial_number),
    key_algorithm: toStringValue(row.key_algorithm),
    key_size: toUInt(row.key_size),
    signature_algorithm: toStringValue(row.signature_algorithm),
    ocsp_url: toStringValue(row.ocsp_url),
    crl_url: toStringValue(row.crl_url),
    location: toStringValue(row.location),
    ip_address: toStringValue(row.ip_address),
    domain_base: toStringValue(row.domain_base),
    tld: toStringValue(row.tld)
  };
};

const ensureOrganizationOnlyTable = async (): Promise<void> => {
  if (!ensureTablePromise) {
    ensureTablePromise = (async () => {
      await executeClickHouseCommand(`CREATE DATABASE IF NOT EXISTS ${CLICKHOUSE_DATABASE}`);
      await executeClickHouseCommand(`
        CREATE TABLE IF NOT EXISTS ${TABLE_NAME}
        (
          organization String,
          log_index UInt64,
          source_page UInt16,
          timestamp_utc String,
          entry_type String,
          leaf_subject String,
          leaf_issuer String,
          domain_full String,
          root_domain String,
          subdomain String,
          issuer String,
          not_before String,
          not_after String,
          serial_number String,
          key_algorithm String,
          key_size UInt16,
          signature_algorithm String,
          ocsp_url String,
          crl_url String,
          location String,
          ip_address String,
          domain_base String,
          tld String,
          inserted_at DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        PRIMARY KEY organization
        ORDER BY (organization, log_index, domain_full, serial_number, ip_address)
      `);
    })().catch((error) => {
      ensureTablePromise = null;
      throw error;
    });
  }

  await ensureTablePromise;
};

export async function POST(request: NextRequest) {
  let payload: StoreRequestPayload;

  try {
    payload = (await request.json()) as StoreRequestPayload;
  } catch {
    return NextResponse.json({ error: "Body must be valid JSON." }, { status: 400 });
  }

  if (!Array.isArray(payload.rows)) {
    return NextResponse.json({ error: "rows must be an array." }, { status: 400 });
  }

  const normalizedRows = payload.rows
    .map((row) => normalizeRow(row))
    .filter((row): row is StoreableOrganizationRow => row !== null);

  if (normalizedRows.length === 0) {
    return NextResponse.json({
      insertedRows: 0,
      table: TABLE_NAME,
      primaryKey: "organization"
    });
  }

  try {
    await ensureOrganizationOnlyTable();
    await insertJsonEachRow(TABLE_NAME, normalizedRows);

    return NextResponse.json({
      insertedRows: normalizedRows.length,
      table: TABLE_NAME,
      primaryKey: "organization"
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: "Failed to store rows in ClickHouse.",
        details: error instanceof Error ? error.message : "Unknown storage error."
      },
      { status: 502 }
    );
  }
}
