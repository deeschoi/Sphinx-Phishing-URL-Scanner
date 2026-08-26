export const GAUGE_CIRCUMFERENCE = 327;

export const VERDICT_LABEL: Record<string, string> = {
  phishing: "phishing",
  suspicious: "suspicious",
  "probably safe": "probably safe",
  legitimate: "legitimate",
  unreachable: "unreachable",
  // The API withholds a rating for an offline scan. Without a label here the
  // badge rendered the raw identifier.
  not_probed: "not rated",
};

export const BADGE_CLASS: Record<string, string> = {
  phishing: "is-phishing",
  suspicious: "is-suspicious",
  "probably safe": "is-safe",
  legitimate: "is-safe",
  unreachable: "is-unknown",
  not_probed: "is-unknown",
};

export const GAUGE_COLOUR: Record<string, string> = {
  phishing: "var(--danger)",
  suspicious: "var(--warn)",
  "probably safe": "var(--safe)",
  legitimate: "var(--safe)",
  unreachable: "var(--muted)",
  not_probed: "var(--muted)",
};

export const VERDICT_ORDER = [
  "phishing",
  "suspicious",
  "probably safe",
  "legitimate",
  "unreachable",
  "not_probed",
] as const;

/** Verdicts that are not a live-site rating. The API withholds `risk` for
 *  exactly these, so the UI offers the URL-string judgment instead.
 *  `fetch_failed` used to be listed here and is never returned as a verdict —
 *  a failed fetch still gets a real risk band from the URL-only model. */
export const WITHHELD_VERDICTS: ReadonlySet<string> = new Set([
  "unreachable",
  "not_probed",
]);

export function verdictLabel(verdict: string): string {
  return VERDICT_LABEL[verdict] ?? verdict;
}

export function badgeClass(verdict: string): string {
  return BADGE_CLASS[verdict] ?? "is-unknown";
}

export function gaugeColour(verdict: string): string {
  return GAUGE_COLOUR[verdict] ?? "var(--muted)";
}

const URL_PATTERN_CLASS: Record<string, string> = {
  phishing: "is-pattern-phishing",
  suspicious: "is-pattern-suspicious",
  "probably safe": "is-pattern-safe",
  legitimate: "is-pattern-safe",
};

/** Styling for the URL-string chip. Never reuses the live-verdict classes. */
export function urlPatternClass(risk: string): string {
  return URL_PATTERN_CLASS[risk] ?? "";
}

export function urlPatternLabel(risk: string): string {
  return `URL pattern: ${verdictLabel(risk)}`;
}
