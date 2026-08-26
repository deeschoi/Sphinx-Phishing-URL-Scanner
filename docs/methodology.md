# How a scan is extracted

Sphinx is not a blocklist lookup. It measures the URL string and, when it can, the HTML of the landing page, then scores those 48 features with XGBoost. For the column list, thresholds, and payload shape, see [parameters.md](parameters.md). For live vs holdout numbers, see [findings.md](findings.md).

## Guards

Sphinx only fetches public `http`/`https` URLs. Because the target is chosen by whoever is typing, `src/phishing/netguard.py` closes three holes before a socket is opened:

- **The literal target.** Loopback, RFC1918, link-local, CGNAT (`100.64.0.0/10`, which is neither `is_private` nor `is_global`), multicast, reserved, IPv4-mapped IPv6, and cloud-metadata addresses are refused — by name and by address.
- **Redirects.** Auto-redirects are off. Each hop is re-validated before it is followed, because an open redirect lets the *target* choose hop *n+1*. Up to 8 redirects are followed by hand.
- **DNS rebinding.** The connection is bound to the address the socket actually reached, so a short-TTL name that answers public for the check and loopback for the connection is dropped mid-handshake.

`user:password@host` is stripped before the request, so credentials never reach the target or scan history. Timeouts default to 8s (API max 20s). Bodies are capped at 2 MB. Only a 2xx response counts as a page: a 404, parking page, or WAF interstitial falls back to URL-only scoring instead of being scored as the site's markup.

JavaScript is never executed. SPA shells are imputed for a handful of link-count features; password / bank / pay markers are left as measured.

## Two extractors, two estimators

Features share one definition with training:

- **20 URL-string features** — length, IP host, HTTPS scheme bit, TLD prior, obfuscation, special-character ratios. `www` is not counted as a subdomain, extra special character, or path leak (every legitimate PhiUSIIL row has `www` and none has a path).
- **28 HTML features** — line count, title↔domain match, favicon, forms, password fields, social/copyright markers, image/CSS/JS/self/external ref counts. These replace the 2012 reputation columns (Alexa, PageRank, inbound links) that no longer exist.

Identifiers and label leaks (`URL`, `Domain`, `Title`, `URLSimilarityIndex`, `URLCharProb`, …) are dropped.

Two estimators are persisted:

1. The **48-feature page model**, used when HTML was actually measured.
2. A **URL-only fallback**, used when HTML was not measured. Missing HTML is never scored as zeros. A failed fetch still gets a live risk band from this estimator. DNS failure (`unreachable`) and an offline `--tier A` scan (`not_probed`) do not: those verdicts withhold `risk`.

The response names the page that was actually scored. A URL that 302s somewhere else shows the landing page and the hop count, because that redirect is often the whole attack.

Every scan is logged so History and Stats work. A logging failure never fails a scan. History strips credentials, query strings, fragments, and path segments that look like secrets (OTPs, JWTs, hex tokens, a segment after `/reset` / `/token` / …) before storage. Best-effort: a readable slug that is itself a secret is kept.

## Disagreement

The page model's heaviest weights (`NoOfExternalRef` 57%, `LineOfCode` 10%, `NoOfSelfRef` 9%) drifted between the 2023 crawl and 2026 markup, so a rich modern homepage can pin at *p* ≈ 1.0. When the page model says phishing and the URL string looks clean, the URL score wins — except on free-hosting suffixes (`github.io`, `vercel.app`, `firebaseapp.com`, …), where kits look clean by construction.

That suffix list is a routing hint, not a model feature. In PhiUSIIL it covers 22,478 phishing rows and 1 legitimate row; trained as an input it scored real docs sites at *p* ≈ 0.999. When the two scores disagree, or differ by 0.2 or more, the Scanner shows both rather than hiding the unused estimator.

## Withheld live ratings

DNS failure (`unreachable`) and an offline `--tier A` scan (`not_probed`) do not get a live `risk` band. A failed fetch still does: the URL-only model scores the string.

Unreachable hosts may show a `url_pattern_risk` chip (`URL pattern: phishing` / `suspicious`) only when the origin string, or a kit-shaped path (`*.html`, `*.php`, …), actually looks like phishing. A clean origin is left unchipped — that is not a safety clearance, and the chip never reuses the live-verdict colours. Kit-shaped paths are a routing hint like the free-hosting suffixes, not a model feature: counting any path in the URL-only model made `/en-us` look like a kit. The origin-only model ignores the path, so a dead host with `/wetj/famt.html` is flagged from that suffix rather than from the host alone.

## Analyst chat

Chat is an explanation layer over a scan that already happened. The verdict, probability, and SHAP attributions are computed by the classifier before a token is generated. Scans never need Groq. Changing the URL starts a new conversation, so evidence from one scan cannot leak into the next.

If the server has no `GROQ_API_KEY`, the panel stays visible and asks for a visitor key from [console.groq.com/keys](https://console.groq.com/keys). Save stores it in `sessionStorage` (gone when the tab closes). `POST /api/chat` sends it as `X-Groq-Api-Key`; `/api/scan` never accepts that header. A request header wins over the env key. Without either, chat returns 503.

Starter chips: *Why this verdict?*, *What would change your mind?*, *What could this scan have missed?*, *How much should I trust this score?* Answers must use two headings, in that order:

| Section | What belongs there |
|---|---|
| **Findings** | Measured evidence only, as bullets. Each bullet names the feature, its measured value, and the SHAP direction (log-odds, not a percentage of the verdict). |
| **Commentary** | One or two short paragraphs that synthesize those findings for this verdict, including limits. No new facts that are not in Findings or a tool result. |

The UI (`web/src/analystReply.ts`) parses those headings into two panels. If the model skips the headings, the parser still splits evidence bullets from surrounding prose.

Grounding is the tool surface, not a request to be careful. `src/phishing/agent.py` exposes six tools over the real payload (listed in [parameters.md](parameters.md)). The UI lists which of them an answer actually consulted.

The system prompt is server-side. Client messages are filtered to `user` / `assistant` turns. The `scan` object on `/api/chat` is schema-validated (unknown keys dropped); when a `scan_id` resolves in telemetry, stored `url` / `verdict` / `probability` / `model` override the client. Four things the prompt insists on:

1. **Never clear a site.** A `legitimate` verdict means the model found no phishing signals — not that it is safe to type a password. On the live sample this model misses about a quarter of the phishing pages it can reach.
2. **Say which accuracy number applies.** ~99.9% is the frozen-column holdout; ~90.6% accuracy / 75% recall is live re-extraction, which is what a real scan gets.
3. **Lead with withheld / URL-only scans.** A URL-string score is not a judgment of a live site.
4. **Volunteer the known blind spots** — the plain-HTTP prior, the `.io`/`.app` TLD prior, and phishing kits on trusted platforms — when they bear on the answer.

Asked about `http://neverssl.com`, which the scanner flags at *p* ≈ 1.0, it names `IsHTTPS` and its +10.9 log-odds contribution under Findings, then says in Commentary that the flag is more likely a false positive than evidence, because the training table has essentially no legitimate HTTP rows. That is the intended behaviour: the interesting answer is usually why a score should not be trusted.
