import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Bar,
  ComposedChart,
} from "recharts";
import { fetchStats } from "../api";
import { EmptyState, StatusMessage } from "../components/EmptyState";
import { formatProbability, pct } from "../format";
import type { ScanStats } from "../types";
import { badgeClass, VERDICT_ORDER, verdictLabel } from "../verdict";

const DAY_OPTIONS = [7, 30, 90] as const;

export function Stats() {
  const [days, setDays] = useState<(typeof DAY_OPTIONS)[number]>(30);
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (window: number) => {
    setLoading(true);
    setError(null);
    try {
      setStats(await fetchStats(window));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load stats.");
      setStats(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(days);
  }, [days, load]);

  const mix = useMemo(() => orderedVerdicts(stats?.verdicts ?? {}), [stats]);
  const chartData = useMemo(
    () =>
      [...(stats?.daily ?? [])].reverse().map((row) => ({
        ...row,
        meanPct: row.mean_probability * 100,
      })),
    [stats],
  );

  return (
    <>
      <p className="hero-kicker">Telemetry</p>
      <h2 className="page-title">Stats</h2>
      <div className="toolbar">
        <p>
          Verdict mix and daily mean score. Mean probability only includes live-site
          verdicts, so unreachable hosts do not drag the drift line toward zero.
        </p>
        <div className="toolbar-actions">
          <div className="segmented" role="group" aria-label="Stats window">
            {DAY_OPTIONS.map((option) => (
              <button
                key={option}
                type="button"
                className={option === days ? "is-active" : undefined}
                onClick={() => setDays(option)}
              >
                {option}d
              </button>
            ))}
          </div>
          <button
            type="button"
            className="ghost-button"
            onClick={() => void load(days)}
            disabled={loading}
          >
            Refresh
          </button>
        </div>
      </div>

      {error ? <StatusMessage message={error} error /> : null}
      {loading ? <StatusMessage message="Loading stats…" /> : null}
      {!loading && stats && stats.total_scans === 0 ? (
        <EmptyState title="No telemetry yet">
          Scan a few URLs first. This view is empty until the API has something to
          aggregate.
        </EmptyState>
      ) : null}
      {!loading && stats && stats.total_scans > 0 ? (
        <>
          <div className="stat-row">
            <div className="stat">
              <strong>{stats.total_scans}</strong>
              <span>
                scans in the last {stats.days} days
                {stats.total_scans_all_time > stats.total_scans
                  ? ` (${stats.total_scans_all_time} all time)`
                  : ""}
              </span>
            </div>
            {mix.slice(0, 4).map((row) => (
              <div className="stat" key={row.verdict}>
                <strong>{row.count}</strong>
                <span>{verdictLabel(row.verdict)}</span>
              </div>
            ))}
          </div>

          <section className="finding">
            <h3>Verdict mix</h3>
            <p className="lede">
              Share of scans in the last {stats.days} days, including reachability
              failures.
            </p>
            <div className="mix">
              {mix.map((row) => (
                <div className="mix-row" key={row.verdict}>
                  <span>{verdictLabel(row.verdict)}</span>
                  <div className="mix-track">
                    <span
                      className={`mix-fill ${badgeClass(row.verdict)}`}
                      style={{ width: `${row.share * 100}%` }}
                    />
                  </div>
                  <span className="mix-count">{pct(row.share, 0)}</span>
                </div>
              ))}
            </div>
          </section>

          <div className="chart-card">
            <h3>Score drift</h3>
            <p>
              Daily volume (bars) and mean live-site phishing probability (line) over the
              last {days} days.
            </p>
            {chartData.length === 0 ? (
              <EmptyState title="No daily series yet">
                Stats will appear here after the first scan lands on a calendar day.
              </EmptyState>
            ) : (
              <div style={{ width: "100%", height: 280 }}>
                <ResponsiveContainer>
                  <ComposedChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                    <CartesianGrid stroke="var(--line)" strokeDasharray="3 3" />
                    <XAxis dataKey="date" stroke="var(--muted)" tick={{ fontSize: 12 }} />
                    <YAxis
                      yAxisId="left"
                      stroke="var(--muted)"
                      tick={{ fontSize: 12 }}
                      allowDecimals={false}
                    />
                    <YAxis
                      yAxisId="right"
                      orientation="right"
                      stroke="var(--muted)"
                      tick={{ fontSize: 12 }}
                      domain={[0, 100]}
                      tickFormatter={(value: number) => `${value}%`}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "var(--surface-raised)",
                        border: "1px solid var(--line)",
                        borderRadius: 4,
                        color: "var(--text)",
                      }}
                      labelStyle={{ color: "var(--muted)" }}
                      itemStyle={{ color: "var(--text)" }}
                      formatter={(value, name) => {
                        if (name === "meanPct") {
                          return [formatProbability(Number(value) / 100), "Mean probability"];
                        }
                        return [value, "Scans"];
                      }}
                    />
                    <Legend
                      formatter={(value) => (value === "meanPct" ? "Mean probability" : "Scans")}
                    />
                    <Bar yAxisId="left" dataKey="scans" fill="var(--accent)" radius={0} />
                    <Line
                      yAxisId="right"
                      type="monotone"
                      dataKey="meanPct"
                      stroke="var(--warn)"
                      strokeWidth={2}
                      dot={{ r: 3 }}
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        </>
      ) : null}
    </>
  );
}

function orderedVerdicts(verdicts: Record<string, number>) {
  const total = Object.values(verdicts).reduce((sum, n) => sum + n, 0) || 1;
  const seen = new Set<string>();
  const rows: Array<{ verdict: string; count: number; share: number }> = [];
  for (const verdict of VERDICT_ORDER) {
    if (verdict in verdicts) {
      rows.push({
        verdict,
        count: verdicts[verdict],
        share: verdicts[verdict] / total,
      });
      seen.add(verdict);
    }
  }
  for (const [verdict, count] of Object.entries(verdicts)) {
    if (!seen.has(verdict)) {
      rows.push({ verdict, count, share: count / total });
    }
  }
  return rows;
}
