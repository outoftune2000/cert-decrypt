"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import styles from "./page.module.css";

type CtProvider = "cloudflare" | "digicert";

type StartedEvent = {
  sources: CtProvider[];
  limit: number;
  monitorIntervalMs: number;
  startedAt: string;
};

type SourceMetaEvent = {
  source: CtProvider;
  providerLabel: string;
  phase: "initial";
  treeSize: number;
  latestIndex: number;
  start: number;
  end: number;
  sthTimestamp: string;
  sthFetchMs: number;
};

type EntryEvent = {
  source: CtProvider;
  logIndex: number;
  phase: "initial" | "diff";
  line: string;
};

type RangeCompletedEvent = {
  source: CtProvider;
  providerLabel: string;
  phase: "initial" | "diff";
  start: number;
  end: number;
  fetchedCount: number;
  decodedCount: number;
  decodeErrors: number;
  fetchEntriesMs: number;
};

type SourceErrorEvent = {
  source: CtProvider;
  providerLabel: string;
  error: string;
  details?: string;
};

type SourceSummary = {
  source: CtProvider;
  providerLabel: string;
  latestIndex: number;
  treeSize: number;
  rangeStart: number;
  rangeEnd: number;
  fetchedCount: number;
  sthTimestamp: string;
  sthFetchMs: number;
  fetchEntriesMs: number;
};

type MonitorReadyEvent = {
  monitorIntervalMs: number;
  trackedSources: CtProvider[];
  sourceSummaries: SourceSummary[];
  totalDecodedEntries: number;
  totalDecodeErrors: number;
};

type MonitorTickEvent = {
  source: CtProvider;
  providerLabel: string;
  checkedAt: string;
  previousTreeSize: number;
  currentTreeSize: number;
  previousLatestIndex: number;
  currentLatestIndex: number;
  diff: number;
};

type DiffDetectedEvent = {
  source: CtProvider;
  providerLabel: string;
  previousTreeSize: number;
  currentTreeSize: number;
  diff: number;
  start: number;
  end: number;
};

type SourceWarningEvent = {
  source: CtProvider;
  providerLabel: string;
  message: string;
  previousTreeSize: number;
  currentTreeSize: number;
};

type MonitorStats = {
  startedAt: string | null;
  monitorIntervalMs: number;
  totalDecodedEntries: number;
  totalDecodeErrors: number;
  totalDiffEntries: number;
  totalRangeCalls: number;
  lastTickAt: string | null;
};

type StreamErrorEvent = {
  error: string;
  details?: string;
};

const PROVIDERS: CtProvider[] = ["cloudflare", "digicert"];
const WINDOW_LIMIT = 1024;

const parseEventData = <T,>(event: Event): T => {
  const payload = (event as MessageEvent<string>).data;
  return JSON.parse(payload) as T;
};

const getProviderLabel = (provider: CtProvider): string => (provider === "digicert" ? "DigiCert" : "Cloudflare");

export default function CtLiveTailPage() {
  const [selectedSources, setSelectedSources] = useState<CtProvider[]>(["cloudflare", "digicert"]);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [terminalLines, setTerminalLines] = useState<string[]>([
    "[BOOT] CT LIVE TAIL READY. SELECT SOURCES, THEN PRESS START."
  ]);
  const [stats, setStats] = useState<MonitorStats>({
    startedAt: null,
    monitorIntervalMs: 10_000,
    totalDecodedEntries: 0,
    totalDecodeErrors: 0,
    totalDiffEntries: 0,
    totalRangeCalls: 0,
    lastTickAt: null
  });

  const terminalBodyRef = useRef<HTMLDivElement | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const stopRequestedRef = useRef(false);

  const addLine = (line: string) => {
    setTerminalLines((current) => {
      const next = [...current, line];
      return next.length > 8000 ? next.slice(next.length - 8000) : next;
    });
  };

  const closeStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  };

  useEffect(() => {
    return () => closeStream();
  }, []);

  useEffect(() => {
    if (terminalBodyRef.current) {
      terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
    }
  }, [terminalLines]);

  const isDisabled = useMemo(() => isRunning || selectedSources.length === 0, [isRunning, selectedSources.length]);

  const toggleSource = (provider: CtProvider) => {
    setSelectedSources((current) =>
      current.includes(provider) ? current.filter((source) => source !== provider) : [...current, provider]
    );
  };

  const handleStart = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    closeStream();
    stopRequestedRef.current = false;
    setError(null);
    setTerminalLines([]);
    setStats({
      startedAt: null,
      monitorIntervalMs: 10_000,
      totalDecodedEntries: 0,
      totalDecodeErrors: 0,
      totalDiffEntries: 0,
      totalRangeCalls: 0,
      lastTickAt: null
    });

    if (selectedSources.length === 0) {
      setError("Pick at least one source.");
      setTerminalLines(["[ERROR] NO SOURCE SELECTED."]);
      return;
    }

    setIsRunning(true);
    addLine("[BOOT] INITIALIZING LIVE STREAM...");

    const query = new URLSearchParams({
      sources: selectedSources.join(","),
      limit: String(WINDOW_LIMIT)
    });

    const eventSource = new EventSource(`/api/ct-live-tail/stream?${query.toString()}`);
    eventSourceRef.current = eventSource;

    eventSource.addEventListener("started", (streamEvent) => {
      const payload = parseEventData<StartedEvent>(streamEvent);
      setStats((current) => ({
        ...current,
        startedAt: payload.startedAt,
        monitorIntervalMs: payload.monitorIntervalMs
      }));
      addLine(
        `[SYSTEM] STARTED AT ${payload.startedAt} | SOURCES=${payload.sources.join(",")} | LIMIT=${payload.limit} | CHECK_EVERY=${payload.monitorIntervalMs}ms`
      );
    });

    eventSource.addEventListener("source_meta", (streamEvent) => {
      const payload = parseEventData<SourceMetaEvent>(streamEvent);
      addLine(
        `[META:${payload.providerLabel}] latest_index=${payload.latestIndex} tree_size=${payload.treeSize} range=${payload.start}-${payload.end} sth_ts=${payload.sthTimestamp}`
      );
    });

    eventSource.addEventListener("entry", (streamEvent) => {
      const payload = parseEventData<EntryEvent>(streamEvent);
      addLine(payload.line);
      setStats((current) => ({
        ...current,
        totalDecodedEntries: current.totalDecodedEntries + 1
      }));
    });

    eventSource.addEventListener("range_completed", (streamEvent) => {
      const payload = parseEventData<RangeCompletedEvent>(streamEvent);
      addLine(
        `[RANGE:${payload.providerLabel}] phase=${payload.phase} range=${payload.start}-${payload.end} fetched=${payload.fetchedCount} decoded=${payload.decodedCount} decode_errors=${payload.decodeErrors} fetch_ms=${payload.fetchEntriesMs}`
      );
      setStats((current) => ({
        ...current,
        totalDecodeErrors: current.totalDecodeErrors + payload.decodeErrors,
        totalDiffEntries: current.totalDiffEntries + (payload.phase === "diff" ? payload.fetchedCount : 0),
        totalRangeCalls: current.totalRangeCalls + 1
      }));
    });

    eventSource.addEventListener("source_error", (streamEvent) => {
      const payload = parseEventData<SourceErrorEvent>(streamEvent);
      const detailsSuffix = payload.details ? ` ${payload.details}` : "";
      addLine(`[ERR:${payload.providerLabel}] ${payload.error}${detailsSuffix}`);
    });

    eventSource.addEventListener("monitor_ready", (streamEvent) => {
      const payload = parseEventData<MonitorReadyEvent>(streamEvent);
      addLine(
        `[SYSTEM] MONITOR READY tracked=${payload.trackedSources.join(",")} initial_decoded=${payload.totalDecodedEntries} initial_decode_errors=${payload.totalDecodeErrors}`
      );
      setStats((current) => ({
        ...current,
        monitorIntervalMs: payload.monitorIntervalMs
      }));
    });

    eventSource.addEventListener("monitor_tick", (streamEvent) => {
      const payload = parseEventData<MonitorTickEvent>(streamEvent);
      addLine(
        `[TICK:${payload.providerLabel}] prev_tree_size=${payload.previousTreeSize} current_tree_size=${payload.currentTreeSize} diff=${payload.diff} checked_at=${payload.checkedAt}`
      );
      setStats((current) => ({
        ...current,
        lastTickAt: payload.checkedAt
      }));
    });

    eventSource.addEventListener("diff_detected", (streamEvent) => {
      const payload = parseEventData<DiffDetectedEvent>(streamEvent);
      addLine(
        `[DIFF:${payload.providerLabel}] new_entries=${payload.diff} range=${payload.start}-${payload.end} (current=${payload.currentTreeSize} prev=${payload.previousTreeSize})`
      );
    });

    eventSource.addEventListener("source_warning", (streamEvent) => {
      const payload = parseEventData<SourceWarningEvent>(streamEvent);
      addLine(
        `[WARN:${payload.providerLabel}] ${payload.message} prev_tree_size=${payload.previousTreeSize} current_tree_size=${payload.currentTreeSize}`
      );
    });

    eventSource.addEventListener("stream_error", (streamEvent) => {
      const payload = parseEventData<StreamErrorEvent>(streamEvent);
      const detailsSuffix = payload.details ? ` ${payload.details}` : "";
      setError(payload.error + detailsSuffix);
      addLine(`[FATAL] ${payload.error}${detailsSuffix}`);
      setIsRunning(false);
      closeStream();
    });

    eventSource.onerror = () => {
      if (stopRequestedRef.current) {
        return;
      }

      setError("Live stream disconnected before completion.");
      addLine("[FATAL] STREAM DISCONNECTED BEFORE COMPLETION.");
      setIsRunning(false);
      closeStream();
    };
  };

  return (
    <main className={styles.page}>
      <section className={styles.headerBlock}>
        <p className={styles.badge}>CT Monitor Mode</p>
        <h1>Live Tail - Latest 1024 Entries</h1>
        <p>
          Select one or more sources. The page grabs each source&apos;s latest index, fetches the last 1024 entries,
          prints decoded values in the terminal, and keeps monitoring every 10 seconds for new tree-size deltas.
        </p>
      </section>

      <form className={styles.controls} onSubmit={handleStart}>
        <div className={styles.sourceGrid}>
          {PROVIDERS.map((provider) => (
            <label
              key={provider}
              className={`${styles.sourceOption} ${selectedSources.includes(provider) ? styles.sourceOptionSelected : ""}`}
            >
              <input
                type="checkbox"
                checked={selectedSources.includes(provider)}
                onChange={() => toggleSource(provider)}
                disabled={isRunning}
              />
              <span>{getProviderLabel(provider)}</span>
            </label>
          ))}
        </div>

        <p className={styles.formNote}>
          Fixed initial window: latest {WINDOW_LIMIT} entries per selected source. Then tree size is checked every 10
          seconds and only the diff entries are fetched/printed.
        </p>

        <div className={styles.actions}>
          <button type="submit" disabled={isDisabled} className={styles.primaryButton}>
            {isRunning ? "Streaming..." : "Start Live Tail"}
          </button>
          {isRunning && (
            <button
              type="button"
              className={styles.ghostButton}
              onClick={() => {
                stopRequestedRef.current = true;
                closeStream();
                setIsRunning(false);
                addLine("[SYSTEM] STREAM STOPPED BY USER.");
              }}
            >
              Stop
            </button>
          )}
          <button
            type="button"
            className={styles.ghostButton}
            onClick={() => {
              setError(null);
              setTerminalLines([
                isRunning
                  ? "[SYSTEM] SCREEN CLEARED. MONITORING CONTINUES..."
                  : "[BOOT] SCREEN CLEARED. READY FOR NEXT RUN."
              ]);
            }}
          >
            Clear Screen
          </button>
        </div>
      </form>

      {error && <section className={styles.errorBox}>{error}</section>}

      <section className={styles.monitorFrame}>
        <div className={styles.monitorShell}>
          <div className={styles.monitorTopBar}>
            <div className={styles.ledRow}>
              <span className={styles.ledPower} />
              <span className={styles.ledIdle} />
              <span className={styles.ledWarn} />
            </div>
            <p>CRT-CT-9000 TERMINAL</p>
          </div>

          <div className={styles.screen}>
            <div className={styles.scanlineLayer} />
            <div className={styles.glowLayer} />
            <div className={styles.terminalBody} ref={terminalBodyRef}>
              {terminalLines.map((line, index) => (
                <p key={`${index}-${line.slice(0, 20)}`} className={styles.terminalLine}>
                  {line}
                </p>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className={styles.summary}>
        <h2>Monitor Stats</h2>
        <div className={styles.summaryGrid}>
          <div>
            <label>Status</label>
            <p>{isRunning ? "monitoring" : "idle"}</p>
          </div>
          <div>
            <label>Started At</label>
            <p>{stats.startedAt ?? "-"}</p>
          </div>
          <div>
            <label>Check Interval</label>
            <p>{stats.monitorIntervalMs} ms</p>
          </div>
          <div>
            <label>Last Tick</label>
            <p>{stats.lastTickAt ?? "-"}</p>
          </div>
          <div>
            <label>Decoded Lines Printed</label>
            <p>{stats.totalDecodedEntries}</p>
          </div>
          <div>
            <label>Decode Errors</label>
            <p>{stats.totalDecodeErrors}</p>
          </div>
          <div>
            <label>New Entries (Diff Total)</label>
            <p>{stats.totalDiffEntries}</p>
          </div>
          <div>
            <label>Fetched Ranges</label>
            <p>{stats.totalRangeCalls}</p>
          </div>
        </div>
      </section>
    </main>
  );
}
