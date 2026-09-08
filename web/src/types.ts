/** Closed union. `| string` here defeated every exhaustiveness check the
 *  compiler could have run, which is how `not_probed` shipped with no label
 *  and rendered as a raw identifier in the verdict badge. */
export type Verdict =
  | "phishing"
  | "suspicious"
  | "probably safe"
  | "legitimate"
  | "unreachable"
  | "not_probed";

/** Live-site risk bands. Withheld verdicts carry `risk: null` instead. */
export type Risk = "phishing" | "suspicious" | "probably safe" | "legitimate";

export interface Signal {
  feature: string;
  label: string;
  contribution: number;
  measured: boolean;
  value_meaning: string;
  encoding_unreliable: boolean;
  evidence: string;
  direction: string;
}

export interface Coverage {
  reachability: string;
  dns_ok: boolean | null;
  page_fetched: boolean;
  /** HTTPS on the landing page, read from the scheme. No handshake is made. */
  https: boolean;
  tls_checked: boolean;
  http_status: number | null;
  redirects: number;
  truncated: boolean;
  features_used: number;
  features_in_dataset: number;
  redirect_hops?: RedirectHop[];
}

export interface RedirectHop {
  url: string;
  host: string;
  shortener: boolean;
}

export interface LiveSample {
  accuracy: number;
  recall: number;
  false_positive_rate: number;
  precision?: number;
  n_per_class?: number;
  unrated_hosts?: number;
  seed?: number;
  note?: string;
}

export interface ModelQuality {
  accuracy: number;
  auroc: number;
  recall_at_warn: number;
  false_positive_rate_at_warn: number;
  warn_threshold: number;
  block_threshold: number;
  measured_on?: string;
  /** Same model, features re-extracted over the network. What a real scan gets. */
  live_sample?: LiveSample | null;
}

export interface FeatureWarning {
  feature: string;
  message: string;
  fallback: number;
}

export interface Reachability {
  status: string;
  dns_ok: boolean | null;
  page_fetched: boolean;
  tls_inspected: boolean;
  final_url: string | null;
  status_code: number | null;
  n_redirects: number;
  redirect_chain: string[];
  truncated: boolean;
}

export interface ScanResult {
  url: string;
  /** The page that was actually scored. Differs from `url` after a redirect. */
  final_url: string;
  /** Unicode form of an `xn--` host, when the landing host is punycode. */
  host_unicode?: string | null;
  redirect_chain?: string[];
  http_status?: number | null;
  reachability: Reachability;
  verdict: Verdict;
  /** null whenever the verdict is withheld — there is no live-site rating. */
  risk: Risk | null;
  prediction: "phishing" | "legitimate" | null;
  threshold: number;
  warnings: FeatureWarning[];
  features: Record<string, number>;
  url_only: boolean;
  probability: number;
  /** Page-model score before any disagreement fallback; null when HTML was not measured. */
  page_probability?: number | null;
  /** URL-string-only score, always present when the fallback model is loaded. */
  url_probability?: number | null;
  /** Judgment of the URL string alone. Not a live-site verdict. */
  url_pattern_risk?: Risk | null;
  /** True when the URL-string score replaced a high page-model score. */
  url_disagreement?: boolean;
  rationale: string;
  notes: string[];
  error: string | null;
  signals: Signal[];
  coverage: Coverage;
  model: string;
  model_quality: ModelQuality;
  scan_id?: number | null;
  duration_ms?: number;
}

export interface ScanRecord {
  id: number;
  created_at: string | null;
  url: string;
  host: string;
  verdict: string;
  probability: number;
  model: string;
  duration_ms: number;
  page_fetched: boolean;
  tls_checked: boolean;
}

export interface ScanList {
  scans: ScanRecord[];
}

export interface DailyStat {
  date: string;
  scans: number;
  mean_probability: number;
}

export interface ScanStats {
  /** Size of the window every aggregate below is filtered to. */
  days: number;
  since: string;
  total_scans: number;
  total_scans_all_time: number;
  verdicts: Record<string, number>;
  daily: DailyStat[];
  url_only?: number;
  page?: number;
  disagreement?: number;
  withheld?: number;
}

export interface ScanJob {
  job_id: string;
  status: "queued" | "running" | "done" | "error" | string;
  url: string;
  batch_id?: string | null;
  scan_id?: number | null;
  error?: string | null;
  result?: ScanResult | null;
}

export interface ScanBatch {
  batch_id: string;
  status: string;
  total: number;
  queued: number;
  running: number;
  done: number;
  error: number;
  jobs: ScanJob[];
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface ToolUse {
  tool: string;
  arguments: Record<string, unknown>;
}

export interface ChatReply {
  reply: string;
  tools_used: ToolUse[];
  model: string;
}

export interface AgentStatus {
  enabled: boolean;
  /** True when the server has no GROQ_API_KEY and the visitor must paste one. */
  requires_user_key?: boolean;
  model: string | null;
  detail: string | null;
}

export interface Leakage {
  duplicate_row_fraction?: number;
  random_split_test_rows_seen_in_train?: number;
  conflicting_label_patterns?: number;
}

export interface ModelRow {
  model: string;
  random_accuracy: number;
  grouped_accuracy: number;
  accuracy_optimism: number;
}

export interface EncodingAuditRow {
  feature: string;
  "documented -1 means": string;
  "P(phish|-1)": number;
  "P(phish|+1)": number;
  verdict: string;
}

export interface ScenarioRow {
  scenario: string;
  n_features: number;
  accuracy: number;
  delta_vs_full: number;
}

export interface Findings {
  leakage: Leakage;
  models: ModelRow[];
  reversed_features: string[];
  no_signal_features: string[];
  encoding_audit: EncodingAuditRow[];
  scenarios: ScenarioRow[];
  unavailable_features: Array<{ feature: string; reason: string }>;
}
