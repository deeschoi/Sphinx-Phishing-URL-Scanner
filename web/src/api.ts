import { getGroqApiKey } from "./groqKey";

export function errorMessage(payload: unknown, fallback = "Request failed."): string {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail: unknown }).detail;
    if (typeof detail === "string" && detail.trim()) return detail;
    if (Array.isArray(detail)) {
      const parts = detail
        .map((item) =>
          item && typeof item === "object" && "msg" in item
            ? String((item as { msg: unknown }).msg)
            : "",
        )
        .filter(Boolean);
      if (parts.length) return parts.join("; ");
    }
  }
  return fallback;
}

/** A non-2xx response, carrying the bits a caller needs to decide whether to
 *  retry. Extends Error so existing `err instanceof Error` / `err.message`
 *  handling keeps working unchanged. */
export class ApiError extends Error {
  readonly status: number;
  readonly retryAfterMs: number | null;

  constructor(message: string, status: number, retryAfterMs: number | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

function parseRetryAfter(response: Response): number | null {
  // Test doubles stub Response as a bare object with no headers.
  const raw = response.headers?.get("Retry-After");
  if (!raw) return null;
  const seconds = Number(raw);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : null;
}

/** Polling cadence. A job poll spends from the same per-minute read budget as
 *  the rest of the UI, so the interval grows instead of hammering a fixed one:
 *  400ms first (a short scan still feels instant), then ×1.5 up to 3s, which
 *  keeps a multi-minute scan near 20 polls/min against a 60/min budget. */
export const POLL_START_MS = 400;
const POLL_MAX_MS = 3000;

export function nextPollDelay(current: number): number {
  return Math.min(Math.round(current * 1.5), POLL_MAX_MS);
}

/** How many consecutive 429s a polling loop rides out before giving up. At the
 *  clamp below this spans more than one full rate-limit window, so the budget
 *  is guaranteed to have drained if the server is going to let us back in. */
export const RATE_LIMIT_RETRIES = 5;

export function rateLimitWaitMs(error: ApiError): number {
  return Math.min(Math.max(error.retryAfterMs ?? 5000, 1000), 15000);
}

export function isRateLimited(error: unknown): error is ApiError {
  return error instanceof ApiError && error.status === 429;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  // Set when the API is deployed with SPHINX_API_KEY. Unset for the local demo.
  const key = import.meta.env.VITE_SPHINX_API_KEY;
  if (key) headers.set("X-API-Key", key);
  const response = await fetch(path, { ...init, headers });
  const payload: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new ApiError(
      errorMessage(payload, response.statusText || "Request failed."),
      response.status,
      parseRetryAfter(response),
    );
  }
  return payload as T;
}

export function scanUrl(url: string, timeout = 8, signal?: AbortSignal) {
  return request<import("./types").ScanResult>("/api/scan", {
    method: "POST",
    body: JSON.stringify({ url, timeout }),
    signal,
  });
}

export function createScanJob(url: string, timeout = 8, signal?: AbortSignal) {
  return request<{ job_id: string }>("/api/scan/jobs", {
    method: "POST",
    body: JSON.stringify({ url, timeout }),
    signal,
  });
}

export function fetchScanJob(jobId: string, signal?: AbortSignal) {
  return request<import("./types").ScanJob>(`/api/scan/jobs/${jobId}`, { signal });
}

export function createScanBatch(urls: string[], timeout = 8, signal?: AbortSignal) {
  return request<{ batch_id: string; job_ids: string[] }>("/api/scan/batch", {
    method: "POST",
    body: JSON.stringify({ urls, timeout }),
    signal,
  });
}

export function fetchScanBatch(batchId: string, signal?: AbortSignal) {
  return request<import("./types").ScanBatch>(`/api/scan/batch/${batchId}`, { signal });
}

export function fetchScan(scanId: number | string, signal?: AbortSignal) {
  return request<import("./types").ScanResult>(`/api/scans/${scanId}`, { signal });
}

export function fetchAgentStatus() {
  return request<import("./types").AgentStatus>("/api/agent");
}

/** Ask the analyst about a scan. The scan payload is the grounding evidence;
 *  the model reaches the rest through server-side tools. */
export function askAnalyst(
  scan: import("./types").ScanResult,
  messages: import("./types").ChatMessage[],
  signal?: AbortSignal,
) {
  const headers: Record<string, string> = {};
  const groq = getGroqApiKey();
  if (groq) headers["X-Groq-Api-Key"] = groq;
  return request<import("./types").ChatReply>("/api/chat", {
    method: "POST",
    headers,
    body: JSON.stringify({ scan, messages }),
    signal,
  });
}

export function fetchFindings() {
  return request<import("./types").Findings>("/api/findings");
}

export function fetchScans(limit = 50, offset = 0) {
  return request<import("./types").ScanList>(`/api/scans?limit=${limit}&offset=${offset}`);
}

export function fetchStats(days = 30) {
  return request<import("./types").ScanStats>(`/api/stats?days=${days}`);
}
