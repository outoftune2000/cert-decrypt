import { NextResponse } from "next/server";
import { resolveAllLogs } from "@/lib/ctLogList";

export async function GET() {
  try {
    const logs = await resolveAllLogs();

    return NextResponse.json({
      count: logs.length,
      logs: logs.map((l) => ({
        slug: l.slug,
        operator: l.operator,
        description: l.description,
        logId: l.logId,
        temporalStart: l.temporalStart,
        temporalEnd: l.temporalEnd
      }))
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: "Failed to fetch CT log list.",
        details: error instanceof Error ? error.message : "Unknown error."
      },
      { status: 502 }
    );
  }
}
