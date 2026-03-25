import { NextRequest, NextResponse } from "next/server";
import { queryClickHouseJson } from "@/lib/clickhouse";

type CtProvider = "cloudflare" | "digicert";

type ExistingIndexRow = {
  log_index: number | string;
};

const readUintParam = (value: string | null, label: string): number => {
  if (value === null || value.trim().length === 0) {
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
  if (value === null || value.trim().length === 0) {
    throw new Error("source is required.");
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "cloudflare" || normalized === "digicert") {
    return normalized;
  }

  throw new Error("source must be either cloudflare or digicert.");
};

const toSafeNumber = (value: number | string): number | null => {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    return null;
  }

  return parsed;
};

export async function GET(request: NextRequest) {
  let start: number;
  let end: number;
  let source: CtProvider;

  try {
    start = readUintParam(request.nextUrl.searchParams.get("start"), "start");
    end = readUintParam(request.nextUrl.searchParams.get("end"), "end");
    source = readProviderParam(request.nextUrl.searchParams.get("source"));
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Invalid query parameters." },
      { status: 400 }
    );
  }

  if (end < start) {
    return NextResponse.json({ error: "end must be greater than or equal to start." }, { status: 400 });
  }

  try {
    const rows = await queryClickHouseJson<ExistingIndexRow>(`
      SELECT log_index
      FROM organization_only_records
      WHERE source = '${source}'
        AND log_index BETWEEN ${start} AND ${end}
      GROUP BY log_index
      ORDER BY log_index
    `);

    const indexes = rows
      .map((row) => toSafeNumber(row.log_index))
      .filter((value): value is number => value !== null);

    return NextResponse.json({
      source,
      start,
      end,
      count: indexes.length,
      indexes
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("UNKNOWN_TABLE") || message.includes("doesn't exist")) {
      return NextResponse.json({
        source,
        start,
        end,
        count: 0,
        indexes: []
      });
    }

    return NextResponse.json(
      {
        error: "Failed to query existing indexes from ClickHouse.",
        details: message || "Unknown query error."
      },
      { status: 502 }
    );
  }
}
