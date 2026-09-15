import { type FormEvent, useCallback, useState } from "react";
import {
  POLL_START_MS,
  RATE_LIMIT_RETRIES,
  createScanBatch,
  fetchScanBatch,
  isRateLimited,
  nextPollDelay,
  rateLimitWaitMs,
} from "../api";
import { EmptyState, StatusMessage } from "../components/EmptyState";
import { VerdictBadge } from "../components/VerdictBadge";
import { downloadJson, downloadText } from "../export";
import { formatProbability } from "../format";
import type { ScanBatch, ScanJob } from "../types";

export function Batch() {
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [batch, setBatch] = useState<ScanBatch | null>(null);

  const poll = useCallback(async (batchId: string) => {
    let delay = POLL_START_MS;
    let rateLimited = 0;
    for (;;) {
      let payload: ScanBatch;
      try {
        payload = await fetchScanBatch(batchId);
      } catch (err) {
        // A 429 means this client spent its read budget, not that the batch
        // failed — the jobs are still running server-side, so wait for the
        // window to drain instead of reporting a failure that did not happen.
        if (!isRateLimited(err) || ++rateLimited > RATE_LIMIT_RETRIES) throw err;
        await new Promise((resolve) => setTimeout(resolve, rateLimitWaitMs(err)));
        continue;
      }
      rateLimited = 0;
      setBatch(payload);
      if (payload.status === "done" || payload.status === "error") return;
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = nextPollDelay(delay);
    }
  }, []);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const urls = text
      .split(/[\n,]+/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (!urls.length || busy) return;
    setBusy(true);
    setError(null);
    try {
      const { batch_id } = await createScanBatch(urls);
      await poll(batch_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Batch scan failed.");
    } finally {
      setBusy(false);
    }
  }

  const jobs = batch?.jobs ?? [];
  const completed = jobs.filter((job) => job.status === "done" && job.result);

  function exportJson() {
    downloadJson(`sphinx-batch-${batch?.batch_id ?? "results"}.json`, completed.map((job) => job.result));
  }

  function exportCsv() {
    const header = "url,final_url,verdict,probability,model,status,error";
    const rows = jobs.map((job) =>
      [
        csv(job.url),
        csv(job.result?.final_url ?? ""),
        csv(job.result?.verdict ?? ""),
        job.result ? String(job.result.probability) : "",
        csv(job.result?.model ?? ""),
        csv(job.status),
        csv(job.error ?? ""),
      ].join(","),
    );
    downloadText(`sphinx-batch-${batch?.batch_id ?? "results"}.csv`, [header, ...rows].join("\n"), "text/csv");
  }

  return (
    <>
      <p className="hero-kicker">Many URLs at once</p>
      <h2 className="page-title">Batch scan</h2>
      <form className="batch-form" onSubmit={(event) => void onSubmit(event)}>
        <label className="batch-label" htmlFor="batch-urls">
          One URL per line
        </label>
        <textarea
          id="batch-urls"
          className="batch-input"
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder={"https://example.com\nhttps://another.example/login"}
          spellCheck={false}
          disabled={busy}
        />
        <div className="toolbar">
          <p>
            Each URL spends one scan from the per-minute budget, so the cap
            tracks that budget and is enforced by the server — an oversized
            batch is rejected with the limit in the message.
            {batch
              ? ` ${batch.done + batch.error} of ${batch.total} finished.`
              : null}
          </p>
          <div className="toolbar-actions">
            <button className="scan-button" type="submit" disabled={busy || !text.trim()}>
              {busy ? "Scanning…" : "Scan batch"}
            </button>
            <button
              type="button"
              className="ghost-button"
              onClick={exportCsv}
              disabled={!completed.length}
            >
              Export CSV
            </button>
            <button
              type="button"
              className="ghost-button"
              onClick={exportJson}
              disabled={!completed.length}
            >
              Export JSON
            </button>
          </div>
        </div>
      </form>

      {error ? <StatusMessage message={error} error /> : null}
      {busy && !batch ? <StatusMessage message="Queued…" /> : null}
      {batch && jobs.length === 0 ? (
        <EmptyState title="No jobs in this batch">Paste URLs above and scan.</EmptyState>
      ) : null}
      {jobs.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>URL</th>
                <th>Status</th>
                <th>Verdict</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <BatchRow key={job.job_id} job={job} />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </>
  );
}

function BatchRow({ job }: { job: ScanJob }) {
  const result = job.result;
  return (
    <tr>
      <td className="clip" title={job.url}>
        {job.url}
      </td>
      <td>{job.status}</td>
      <td>{result ? <VerdictBadge verdict={result.verdict} /> : job.error || "—"}</td>
      <td className="num">{result ? formatProbability(result.probability) : "—"}</td>
    </tr>
  );
}

function csv(value: string) {
  if (/[",\n]/.test(value)) return `"${value.replaceAll('"', '""')}"`;
  return value;
}
