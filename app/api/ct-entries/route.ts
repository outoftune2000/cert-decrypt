import { NextRequest, NextResponse } from "next/server";
import { resolveAllLogs, resolveLogBySlug } from "@/lib/ctLogList";

type CtApiEntry = {
  leaf_input: string;
  extra_data: string;
};

type CtApiResponse = {
  entries: CtApiEntry[];
};

const MAX_CT_WINDOW_OFFSET = 1023;

const readUintParam = (value: string | null, label: string): number => {
  if (value === null || value.trim().length === 0) {
    throw new Error(`${label} is required.`);
  }

  if (!/^\d+$/.test(value)) {
    throw new Error(`${label} must contain digits only.`);
  }

  const parsed = Number(value);

  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label} must be a safe integer.`);
  }

  return parsed;
};

const readSlugParam = (value: string | null): string | null => {
  if (value === null || value.trim().length === 0) {
    return null;
  }
  return value.trim().toLowerCase();
};

export async function GET(request: NextRequest) {
  let start: number;
  let end: number;
  let slugParam: string | null;

  try {
    start = readUintParam(request.nextUrl.searchParams.get("start"), "start");
    end = readUintParam(request.nextUrl.searchParams.get("end"), "end");
    slugParam = readSlugParam(request.nextUrl.searchParams.get("provider"));
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Invalid query parameters." },
      { status: 400 }
    );
  }

  if (end < start) {
    return NextResponse.json({ error: "end must be greater than or equal to start." }, { status: 400 });
  }

  if (end - start > MAX_CT_WINDOW_OFFSET) {
    return NextResponse.json(
      {
        error: `Range too large. The CT API allows up to 1024 entries, so end must be <= start + ${MAX_CT_WINDOW_OFFSET}.`
      },
      { status: 400 }
    );
  }

  let getEntriesEndpoint: string;
  let providerLabel: string;
  let resolvedSlug: string;

  try {
    if (slugParam === null) {
      const logs = await resolveAllLogs();
      const log = logs[0];
      getEntriesEndpoint = log.getEntriesEndpoint;
      providerLabel = log.operator;
      resolvedSlug = log.slug;
    } else {
      const log = await resolveLogBySlug(slugParam);
      if (!log) {
        return NextResponse.json(
          { error: `Unknown CT log slug: "${slugParam}". Call /api/ct-log-list for available slugs.` },
          { status: 400 }
        );
      }
      getEntriesEndpoint = log.getEntriesEndpoint;
      providerLabel = log.operator;
      resolvedSlug = log.slug;
    }
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to resolve CT log endpoints.", details: error instanceof Error ? error.message : "Unknown error." },
      { status: 502 }
    );
  }

  const target = new URL(getEntriesEndpoint);
  target.searchParams.set("start", String(start));
  target.searchParams.set("end", String(end));

  try {
    const response = await fetch(target.toString(), {
      headers: {
        "User-Agent": "yaak",
        Accept: "*/*"
      },
      cache: "no-store"
    });

    if (!response.ok) {
      const details = await response.text();
      return NextResponse.json(
        {
          error: `${providerLabel} CT endpoint returned ${response.status}.`,
          details: details.slice(0, 500)
        },
        { status: response.status }
      );
    }

    const payload = (await response.json()) as Partial<CtApiResponse>;

    if (!Array.isArray(payload.entries)) {
      return NextResponse.json(
        { error: `${providerLabel} CT response did not include a valid entries array.` },
        { status: 502 }
      );
    }

    const entries = payload.entries
      .filter(
        (entry): entry is CtApiEntry =>
          typeof entry?.leaf_input === "string" && typeof entry?.extra_data === "string"
      )
      .map((entry) => ({
        leaf_input: entry.leaf_input,
        extra_data: entry.extra_data
      }));

    return NextResponse.json({
      start,
      end,
      provider: resolvedSlug,
      count: entries.length,
      entries
    });
  } catch {
    return NextResponse.json({ error: `Failed to reach ${providerLabel} CT endpoint.` }, { status: 502 });
  }
}
