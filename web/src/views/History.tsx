import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchScans } from "../api";
import { EmptyState, StatusMessage } from "../components/EmptyState";
import { VerdictBadge } from "../components/VerdictBadge";
import { formatDuration, formatProbability, formatTimestamp, yesNo } from "../format";
import type { ScanRecord } from "../types";

const PAGE_SIZE = 50;

export function History() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(false);

  const load = useCallback(async (offset: number, append: boolean) => {
    if (append) setLoadingMore(true);
    else setLoading(true);
    setError(null);
    try {
      const payload = await fetchScans(PAGE_SIZE, offset);
      setScans((current) => (append ? [...current, ...payload.scans] : payload.scans));
      setHasMore(payload.scans.length === PAGE_SIZE);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load history.");
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }, []);

  useEffect(() => {
    void load(0, false);
  }, [load]);

  return (
    <>
      <p className="hero-kicker">Logged scans</p>
      <h2 className="page-title">Scan history</h2>
      <div className="toolbar">
        <p>
          Recent scans stored by the API. Query strings are stripped before they are
          written, so session tokens never sit in the history table.
        </p>
        <div className="toolbar-actions">
          <button
            type="button"
            className="ghost-button"
            onClick={() => void load(0, false)}
            disabled={loading}
          >
            Refresh
          </button>
        </div>
      </div>

      {error ? <StatusMessage message={error} error /> : null}
      {loading ? <StatusMessage message="Loading scan history…" /> : null}
      {!loading && !error && scans.length === 0 ? (
        <EmptyState title="No scans yet">
          Ask Sphinx to score a URL. Each result is logged here automatically.
        </EmptyState>
      ) : null}
      {!loading && scans.length > 0 ? (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Host</th>
                  <th>URL</th>
                  <th>Verdict</th>
                  <th>Score</th>
                  <th>Duration</th>
                  <th>Page</th>
                  <th>TLS</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((row) => (
                  <tr key={row.id}>
                    <td>{formatTimestamp(row.created_at)}</td>
                    <td>{row.host || "—"}</td>
                    <td className="clip" title={row.url}>
                      {row.url}
                    </td>
                    <td>
                      <VerdictBadge verdict={row.verdict} />
                    </td>
                    <td className="num">{formatProbability(row.probability)}</td>
                    <td className="num">{formatDuration(row.duration_ms)}</td>
                    <td>{yesNo(row.page_fetched)}</td>
                    <td>{yesNo(row.tls_checked)}</td>
                    <td>
                      <button
                        type="button"
                        className="row-link"
                        onClick={() =>
                          navigate(`/?url=${encodeURIComponent(row.url)}`)
                        }
                      >
                        Scan again
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {hasMore ? (
            <div className="load-more">
              <button
                type="button"
                className="ghost-button"
                disabled={loadingMore}
                onClick={() => void load(scans.length, true)}
              >
                {loadingMore ? "Loading…" : "Load more"}
              </button>
            </div>
          ) : null}
        </>
      ) : null}
    </>
  );
}
