import { NextRequest, NextResponse } from "next/server";

type CtApiEntry = {
  leaf_input: string;
  extra_data: string;
};

type CtApiResponse = {
  entries: CtApiEntry[];
};

type CtProvider = "cloudflare" | "digicert";

type ProviderConfig = {
  endpoint: string;
  label: string;
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

const readProviderParam = (value: string | null): CtProvider => {
  if (value === null || value.trim().length === 0) {
    return "cloudflare";
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "cloudflare" || normalized === "digicert") {
    return normalized;
  }

  throw new Error("provider must be either cloudflare or digicert.");
};

export async function GET(request: NextRequest) {
  let start: number;
  let end: number;
  let provider: CtProvider;

  try {
    start = readUintParam(request.nextUrl.searchParams.get("start"), "start");
    end = readUintParam(request.nextUrl.searchParams.get("end"), "end");
    provider = readProviderParam(request.nextUrl.searchParams.get("provider"));
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

  const providerConfig = CT_PROVIDER_CONFIG[provider];
  const target = new URL(providerConfig.endpoint);
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
          error: `${providerConfig.label} CT endpoint returned ${response.status}.`,
          details: details.slice(0, 500)
        },
        { status: response.status }
      );
    }

    const payload = (await response.json()) as Partial<CtApiResponse>;

    if (!Array.isArray(payload.entries)) {
      return NextResponse.json(
        {
          error: `${providerConfig.label} CT response did not include a valid entries array.`
        },
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
      provider,
      count: entries.length,
      entries
    });
  } catch {
    return NextResponse.json({ error: `Failed to reach ${providerConfig.label} CT endpoint.` }, { status: 502 });
  }
}
