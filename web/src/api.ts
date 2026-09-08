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
    throw new Error(errorMessage(payload, response.statusText || "Request failed."));
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
