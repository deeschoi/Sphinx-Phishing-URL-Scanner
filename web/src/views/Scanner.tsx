import { type FormEvent, useEffect, useLayoutEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { scanUrl } from "../api";
import { Analyst } from "../components/Analyst";
import { Gauge } from "../components/Gauge";
import { StatusMessage } from "../components/EmptyState";
import { VerdictBadge } from "../components/VerdictBadge";
import { formatProbability, pct, yesNo } from "../format";
import { WITHHELD_VERDICTS, urlPatternClass, urlPatternLabel } from "../verdict";
import type { ScanResult, Signal } from "../types";

const EXAMPLES = [
  { url: "https://www.wikipedia.org", label: "wikipedia.org" },
  { url: "http://neverssl.com", label: "neverssl.com" },
  { url: "https://github.com/python/cpython", label: "github.com" },
];

const LIVE_SIGNALS_TITLE = "Why the model decided this";
const LIVE_SIGNALS_SUB =
  "Each bar is a SHAP value: how far that single signal pushed the score, in log-odds, away from the model's average prediction.";
const URL_ONLY_SIGNALS_TITLE = "URL-string score (page not measured)";
const URL_ONLY_SIGNALS_SUB =
  "The model scored the URL string and placeholder features. That number is not a live-site judgment.";

export function Scanner() {
  const [params] = useSearchParams();
  const [url, setUrl] = useState(params.get("url") ?? "");
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  // Guards against out-of-order responses: only the newest scan may write.
  const requestId = useRef(0);
  const autoScanned = useRef<string | null>(null);

  async function runScan(target: string) {
    const trimmed = target.trim();
    // Without this the example chips could start a second scan while the first
    // was in flight, and whichever finished last won.
    if (!trimmed || busy) return;
    const id = ++requestId.current;
    setBusy(true);
    setError(false);
    setStatus("Fetching the page and parsing its HTML…");
    try {
      const payload = await scanUrl(trimmed);
      if (id !== requestId.current) return;
      setResult(payload);
      setStatus(null);
    } catch (err) {
      if (id !== requestId.current) return;
      setError(true);
      setStatus(err instanceof Error ? err.message : "Scan failed.");
      // The previous result is deliberately left on screen. Clearing it meant a
      // transient network error wiped the verdict the user was still reading.
    } finally {
      if (id === requestId.current) setBusy(false);
    }
  }

  // History's "Scan again" navigates here with ?url=. Prefilling the box alone
  // made that button a lie, so the scan actually runs — once per URL.
  useEffect(() => {
    const preset = params.get("url");
    if (!preset) return;
    setUrl(preset);
    if (autoScanned.current === preset) return;
    autoScanned.current = preset;
    void runScan(preset);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  // Keep the compact scan bar and verdict at the top. Layout effect so this
  // wins over scroll anchoring / live-region focus before the first paint of
  // the result.
  useLayoutEffect(() => {
    if (!result) return;
    window.scrollTo(0, 0);
  }, [result]);

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    void runScan(url);
  }

  return (
    <div className={result ? "scanner-active" : "scanner-idle"}>
      <div className="scan-stage">
        <section className="scan-hero" aria-label="Scan a URL">
          {result ? (
            <p className="hero-kicker">Scan another URL</p>
          ) : (
            <>
              <p className="hero-kicker">Live phishing scanner</p>
              <h2 className="hero-title">Paste a URL. Sphinx will score it.</h2>
              <p className="hero-lede">
                Sphinx fetches the page (JavaScript is never executed), extracts
                signals from the URL and the HTML, and returns a verdict with the
                features that moved the score.
              </p>
            </>
          )}
          <form className="scanbar" autoComplete="off" onSubmit={onSubmit}>
            <input
              className="url-input"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="Paste a URL for Sphinx to judge"
              aria-label="URL to scan"
              spellCheck={false}
            />
            <button className="scan-button" type="submit" disabled={busy}>
              {busy ? "Scanning…" : "Scan"}
            </button>
          </form>
          <p className="examples">
            Try:
            {EXAMPLES.map((example) => (
              <button
                key={example.url}
                type="button"
                className="chip"
                disabled={busy}
                onClick={() => {
                  setUrl(example.url);
                  void runScan(example.url);
                }}
              >
                {example.label}
              </button>
            ))}
          </p>
        </section>
        <div aria-live="polite" aria-atomic="true">
          {status ? <StatusMessage message={status} error={error} /> : null}
        </div>
      </div>
      {result ? <ScanResultView result={result} /> : <ScannerPrimer />}
    </div>
  );
}

function ScanResultView({ result }: { result: ScanResult }) {
  const coverage = result.coverage;
  const quality = result.model_quality;
  const live = quality.live_sample;
  const notes = [...(result.notes ?? [])];
  if (result.error) notes.unshift(result.error);
  // Only worth showing when there is no live verdict to show instead.
  const patternRisk = WITHHELD_VERDICTS.has(result.verdict)
    ? result.url_pattern_risk
    : null;
  const redirected = result.final_url !== result.url;

  return (
    <article className="result">
      <div className="verdict-card">
        <div className="verdict-main">
          <VerdictBadge verdict={result.verdict} />
          {patternRisk ? (
            <span
              className={`badge-url-pattern ${urlPatternClass(patternRisk)}`}
              title="How the URL string alone scores. The site itself was not reachable, so this is not a live-page judgment."
            >
              {urlPatternLabel(patternRisk)}
            </span>
          ) : null}
          <h2 className="verdict-url">{result.final_url}</h2>
          {redirected ? (
            <p className="verdict-redirect">
              Redirected from <span className="clip">{result.url}</span>
            </p>
          ) : null}
          <p className="rationale">{result.rationale}</p>
        </div>
        <Gauge
          probability={result.probability}
          verdict={result.verdict}
          urlOnly={result.url_only}
        />
      </div>

      <DualScores result={result} />

      {notes.length ? (
        <div className="notes">
          {notes.map((text) => (
            <div className="note" key={text}>
              {text}
            </div>
          ))}
        </div>
      ) : null}

      <h3 className="section-title">
        {result.url_only ? URL_ONLY_SIGNALS_TITLE : LIVE_SIGNALS_TITLE}
      </h3>
      <p className="section-sub">
        {result.url_only ? URL_ONLY_SIGNALS_SUB : LIVE_SIGNALS_SUB}
      </p>
      <SignalList signals={result.signals} />

      <div className="meta-grid">
        <div className="meta-card">
          <h4>Scan coverage</h4>
          <dl>
            <Meta term="Reachability" value={coverage.reachability || "—"} />
            <Meta term="DNS resolved" value={yesNo(coverage.dns_ok)} />
            <Meta term="Page downloaded" value={yesNo(coverage.page_fetched)} />
            <Meta
              term="HTTP status"
              value={coverage.http_status ? String(coverage.http_status) : "—"}
            />
            <Meta term="Redirects followed" value={String(coverage.redirects ?? 0)} />
            {/* Not "certificate inspected": no handshake is made and no
                certificate is parsed. This is the scheme of the landing page. */}
            <Meta term="Served over HTTPS" value={yesNo(coverage.https)} />
            <Meta
              term="Signals used"
              value={`${coverage.features_used} of ${coverage.features_in_dataset}`}
            />
            <Meta term="Model" value={result.model} />
          </dl>
        </div>
        <div className="meta-card">
          <h4>Model reliability</h4>
          <dl>
            <Meta term="Held-out accuracy" value={pct(quality.accuracy)} />
            <Meta term="AUROC" value={quality.auroc.toFixed(3)} />
            <Meta
              term="Warn / block thresholds"
              value={`${quality.warn_threshold.toFixed(2)} / ${quality.block_threshold.toFixed(2)}`}
            />
          </dl>
          <p className="meta-caption">
            Measured on {quality.measured_on ?? "a held-out split"} — not on live
            pages.
          </p>
          {live ? (
            <>
              <h5 className="meta-subhead">On live pages</h5>
              <dl>
                <Meta term="Accuracy" value={pct(live.accuracy)} />
                <Meta term="Phishing caught" value={pct(live.recall, 0)} />
                <Meta term="False alarm rate" value={pct(live.false_positive_rate)} />
              </dl>
              <p className="meta-caption">
                Same model, features re-extracted over the network on{" "}
                {live.n_per_class ?? "—"} hosts per class. This is what a scan of a
                real URL gets. {live.unrated_hosts ?? 0} sampled hosts no longer
                resolved and were not rated at all.
              </p>
            </>
          ) : null}
        </div>
      </div>

      <Analyst result={result} />
    </article>
  );
}

/** Both estimators' scores, shown whenever they exist and disagree materially.
 *  The API has always returned these; hiding them made a rescued false positive
 *  look like a mysteriously low page score. */
function DualScores({ result }: { result: ScanResult }) {
  const page = result.page_probability;
  const urlScore = result.url_probability;
  if (page == null || urlScore == null) return null;
  const gap = Math.abs(page - urlScore);
  if (!result.url_disagreement && gap < 0.2) return null;
  return (
    <div className={`dual-scores${result.url_disagreement ? " is-reconciled" : ""}`}>
      <div className="dual-score">
        <span className="dual-label">Page-content model</span>
        <strong>{formatProbability(page)}</strong>
      </div>
      <div className="dual-score">
        <span className="dual-label">URL-string model</span>
        <strong>{formatProbability(urlScore)}</strong>
      </div>
      <p className="dual-note">
        {result.url_disagreement
          ? "The two models disagreed. The URL-string score is the one shown above, because the page model's heaviest features are the ones that drifted since the 2023 training crawl."
          : "The two models differ on this page. The score above is the page model's; the URL-string score is what the model would say without downloading anything."}
      </p>
    </div>
  );
}

function Meta({ term, value }: { term: string; value: string }) {
  return (
    <>
      <dt>{term}</dt>
      <dd>{value}</dd>
    </>
  );
}

function SignalList({ signals }: { signals: Signal[] }) {
  if (!signals.length) {
    return (
      <p className="section-sub">
        No per-signal attribution is available for this scan.
      </p>
    );
  }
  const scale = Math.max(...signals.map((s) => Math.abs(s.contribution)), 0.5);
  return (
    <ul className="signals">
      {signals.map((signal) => {
        const width = (Math.abs(signal.contribution) / scale) * 50;
        const dir = signal.contribution >= 0 ? "up" : "down";
        const flat = Math.abs(signal.contribution) < 0.005;
        return (
          <li
            key={signal.feature}
            className={`signal${signal.measured ? "" : " is-unmeasured"}`}
          >
            <div>
              <span className="signal-name">{signal.label}</span>
              <span className="signal-value">
                {signal.measured ? signal.value_meaning : "Could not be measured"}
              </span>
              {signal.encoding_unreliable ? (
                <span
                  className="signal-flag"
                  title="In this dataset the feature behaves opposite to its documented meaning."
                >
                  encoding unreliable
                </span>
              ) : null}
            </div>
            <div className="signal-evidence">{signal.evidence}</div>
            <div className="bar">
              <span className="bar-axis" />
              <span className={`bar-fill ${dir}`} style={{ width: `${width}%` }} />
            </div>
            <div
              className={`signal-score ${flat ? "flat" : dir}`}
              title={signal.direction}
            >
              {signal.contribution >= 0 ? "+" : "−"}
              {Math.abs(signal.contribution).toFixed(2)}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function ScannerPrimer() {
  return (
    <div className="primer">
      <div className="primer-split">
        <section className="primer-card">
          <h3>What Sphinx looks at</h3>
          <p className="section-sub">
            Private and local addresses are refused before any request is made.
          </p>
          <ul className="primer-list">
            <li>Host and path shape, including IP-looking hosts and odd tokens</li>
            <li>Whether the page arrived over HTTPS, and how many redirects ran</li>
            <li>Page composition: external links, forms, and HTML structure</li>
            <li>Reachability: a host that does not resolve is not rated live</li>
          </ul>
        </section>
        <section className="primer-card">
          <h3>What you get back</h3>
          <p className="section-sub">
            Optional analyst chat can walk through the same evidence if you paste
            a Groq key.
          </p>
          <ul className="primer-list">
            <li>A verdict and a phishing probability for the landing page</li>
            <li>Per-signal SHAP bars so you can see what moved the score</li>
            <li>Coverage: DNS, fetch, status, HTTPS, and features used</li>
            <li>Both estimators when the page model and the URL-string model disagree</li>
          </ul>
        </section>
      </div>

      <h3 className="section-title">Verdicts Sphinx can return</h3>
      <p className="section-sub">
        Live-site ratings need a page that actually loaded. An unreachable host
        is reported as such, not guessed safe.
      </p>
      <div className="primer-verdicts">
        <article className="primer-verdict">
          <span className="badge is-phishing">phishing</span>
          <p>High confidence the page is malicious. Treat the link as hostile.</p>
        </article>
        <article className="primer-verdict">
          <span className="badge is-suspicious">suspicious</span>
          <p>Elevated risk. The score cleared the warn threshold but not a block.</p>
        </article>
        <article className="primer-verdict">
          <span className="badge is-safe">probably safe</span>
          <p>Low score on a live page. Still not a guarantee the site is honest.</p>
        </article>
        <article className="primer-verdict">
          <span className="badge is-unknown">unreachable</span>
          <p>The host did not resolve. Sphinx withholds a live-site rating.</p>
        </article>
      </div>
    </div>
  );
}
