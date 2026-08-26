import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Scanner } from "./views/Scanner";
import type { ScanResult } from "./types";

function jsonResponse(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 403 ? "Forbidden" : "OK",
    json: () => Promise.resolve(body),
  } as Response);
}

function scanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    url: "https://example.com",
    final_url: "https://example.com",
    redirect_chain: [],
    http_status: 200,
    reachability: {
      status: "resolved",
      dns_ok: true,
      page_fetched: true,
      tls_inspected: true,
      final_url: "https://example.com",
      status_code: 200,
      n_redirects: 0,
      redirect_chain: [],
      truncated: false,
    },
    verdict: "legitimate",
    risk: "legitimate",
    prediction: "legitimate",
    threshold: 0.205,
    warnings: [],
    features: {},
    url_only: false,
    probability: 0.02,
    page_probability: 0.02,
    url_probability: 0.05,
    url_pattern_risk: "legitimate",
    url_disagreement: false,
    rationale: "This looks legitimate; page structure pulled the score toward safe.",
    notes: [],
    error: null,
    signals: [
      {
        feature: "NoOfExternalRef",
        label: "Off-domain links",
        contribution: -2.1,
        measured: true,
        value_meaning: "42",
        encoding_unreliable: false,
        evidence: "42",
        direction: "pushed toward legitimate",
      },
    ],
    coverage: {
      reachability: "resolved",
      dns_ok: true,
      page_fetched: true,
      https: true,
      tls_checked: true,
      http_status: 200,
      redirects: 0,
      truncated: false,
      features_used: 48,
      features_in_dataset: 48,
    },
    model: "XGBoost",
    model_quality: {
      accuracy: 0.9995,
      auroc: 0.9999,
      recall_at_warn: 0.9995,
      false_positive_rate_at_warn: 0.0005,
      warn_threshold: 0.205,
      block_threshold: 0.9,
      measured_on: "grouped holdout of the frozen 2023 dataset columns",
      live_sample: {
        accuracy: 0.906,
        recall: 0.75,
        false_positive_rate: 0.009,
        n_per_class: 120,
        unrated_hosts: 59,
      },
    },
    ...overrides,
  } as ScanResult;
}

function renderScanner(initial = "/") {
  return render(
    <MemoryRouter
      initialEntries={[initial]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <Scanner />
    </MemoryRouter>,
  );
}

/** The Analyst panel polls /api/agent on mount; every test stubs it off so the
 *  chat UI never interferes with what is being asserted. */
function stubFetch(handler: (url: string, init?: RequestInit) => Promise<Response>) {
  const spy = vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
    handler(String(input), init),
  );
  vi.stubGlobal("fetch", spy);
  return spy;
}

const AGENT_OFF = { enabled: false, model: null, detail: "not configured" };

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Scanner", () => {
  it("fills the idle scanner with primer cards", () => {
    renderScanner();
    expect(
      screen.getByRole("heading", { name: "Paste a URL. Sphinx will score it." }),
    ).toBeInTheDocument();
    expect(screen.getByText("What Sphinx looks at")).toBeInTheDocument();
    expect(screen.getByText("What you get back")).toBeInTheDocument();
    expect(screen.getByText("Verdicts Sphinx can return")).toBeInTheDocument();
  });

  it("hides the idle primer after a scan returns", async () => {
    stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse(scanResult()),
    );
    const user = userEvent.setup();
    renderScanner();

    await user.type(screen.getByLabelText("URL to scan"), "https://example.com");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    expect(await screen.findByText("legitimate")).toBeInTheDocument();
    expect(screen.queryByText("What Sphinx looks at")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Paste a URL. Sphinx will score it." }),
    ).not.toBeInTheDocument();
  });

  it("renders a verdict, its rationale, and the live-sample metrics", async () => {
    stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse(scanResult()),
    );
    const user = userEvent.setup();
    renderScanner();

    await user.type(screen.getByLabelText("URL to scan"), "https://example.com");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    expect(await screen.findByText("legitimate")).toBeInTheDocument();
    expect(screen.getByText(/pulled the score toward safe/)).toBeInTheDocument();
    // Both accuracy figures are on screen, and each says what it measured.
    expect(screen.getByText("100.0%")).toBeInTheDocument(); // held-out, rounded
    expect(screen.getByText("90.6%")).toBeInTheDocument(); // live sample
    expect(screen.getByText(/not on live pages/)).toBeInTheDocument();
    expect(screen.getByText("On live pages")).toBeInTheDocument();
  });

  it("shows the API's message when a private target is refused", async () => {
    stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse({ detail: "Refusing to scan a private or local address." }, 403),
    );
    const user = userEvent.setup();
    renderScanner();

    await user.type(screen.getByLabelText("URL to scan"), "http://127.0.0.1");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    expect(
      await screen.findByText("Refusing to scan a private or local address."),
    ).toBeInTheDocument();
  });

  it("keeps the previous result on screen when a later scan fails", async () => {
    let call = 0;
    stubFetch((url) => {
      if (url.includes("/api/agent")) return jsonResponse(AGENT_OFF);
      call += 1;
      return call === 1
        ? jsonResponse(scanResult())
        : jsonResponse({ detail: "Scan failed: ConnectionError" }, 500);
    });
    const user = userEvent.setup();
    renderScanner();

    const input = screen.getByLabelText("URL to scan");
    await user.type(input, "https://example.com");
    await user.click(screen.getByRole("button", { name: "Scan" }));
    expect(await screen.findByText("legitimate")).toBeInTheDocument();

    await user.clear(input);
    await user.type(input, "https://broken.example");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    expect(await screen.findByText("Scan failed: ConnectionError")).toBeInTheDocument();
    // The verdict the user was reading is still there.
    expect(screen.getByText("legitimate")).toBeInTheDocument();
  });

  it("withholds a rating for an unreachable host but still shows the URL chip", async () => {
    stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse(
            scanResult({
              verdict: "unreachable",
              risk: null,
              prediction: null,
              url_only: true,
              url_pattern_risk: "phishing",
              probability: 0.94,
              rationale: "The hostname does not resolve, so this is not a live-site judgment.",
              coverage: {
                ...scanResult().coverage,
                reachability: "unreachable",
                dns_ok: false,
                page_fetched: false,
                https: false,
                tls_checked: false,
                http_status: null,
              },
            }),
          ),
    );
    const user = userEvent.setup();
    renderScanner();

    await user.type(screen.getByLabelText("URL to scan"), "https://gone.example");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    // The badge and the coverage row both say "unreachable"; the badge is the
    // one that matters, so match it by its class rather than by text alone.
    const badge = await screen.findByText("unreachable", { selector: ".badge" });
    expect(badge).toBeInTheDocument();
    expect(screen.getByText("URL pattern: phishing")).toBeInTheDocument();
    expect(screen.getByText(/URL-string score/)).toBeInTheDocument();
  });

  it("does not show a legitimate URL chip for an unreachable clean origin", async () => {
    stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse(
            scanResult({
              verdict: "unreachable",
              risk: null,
              prediction: null,
              url_only: true,
              url_pattern_risk: null,
              probability: 0.06,
              rationale:
                "The hostname does not resolve, so this is not a live-site judgment. A clean-looking origin is not a finding that the site is safe.",
              coverage: {
                ...scanResult().coverage,
                reachability: "unreachable",
                dns_ok: false,
                page_fetched: false,
                https: false,
                tls_checked: false,
                http_status: null,
              },
            }),
          ),
    );
    const user = userEvent.setup();
    renderScanner();

    await user.type(screen.getByLabelText("URL to scan"), "https://inzizi.com/");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    const badge = await screen.findByText("unreachable", { selector: ".badge" });
    expect(badge).toBeInTheDocument();
    expect(screen.queryByText(/URL pattern:/)).not.toBeInTheDocument();
    expect(screen.queryByText("legitimate")).not.toBeInTheDocument();
  });

  it("labels an offline scan instead of printing the raw verdict", async () => {
    stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse(
            scanResult({ verdict: "not_probed", risk: null, url_only: true }),
          ),
    );
    const user = userEvent.setup();
    renderScanner();

    await user.type(screen.getByLabelText("URL to scan"), "https://example.com");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    expect(await screen.findByText("not rated")).toBeInTheDocument();
    expect(screen.queryByText("not_probed")).not.toBeInTheDocument();
  });

  it("shows both estimator scores when the disagreement rule fires", async () => {
    stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse(
            scanResult({
              url_disagreement: true,
              page_probability: 0.999,
              url_probability: 0.03,
              probability: 0.03,
            }),
          ),
    );
    const user = userEvent.setup();
    renderScanner();

    await user.type(screen.getByLabelText("URL to scan"), "https://modern.example");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    expect(await screen.findByText("Page-content model")).toBeInTheDocument();
    expect(screen.getByText("URL-string model")).toBeInTheDocument();
    expect(screen.getByText(/The two models disagreed/)).toBeInTheDocument();
  });

  it("reports the landing page after a redirect, not the URL that was typed", async () => {
    stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse(
            scanResult({
              url: "https://short.example/abc",
              final_url: "https://phish.example/login",
            }),
          ),
    );
    const user = userEvent.setup();
    renderScanner();

    await user.type(screen.getByLabelText("URL to scan"), "https://short.example/abc");
    await user.click(screen.getByRole("button", { name: "Scan" }));

    expect(await screen.findByText("https://phish.example/login")).toBeInTheDocument();
    expect(screen.getByText(/Redirected from/)).toBeInTheDocument();
  });

  it("scans automatically when arriving with ?url=", async () => {
    const spy = stubFetch((url) =>
      url.includes("/api/agent")
        ? jsonResponse(AGENT_OFF)
        : jsonResponse(scanResult({ url: "https://preset.example" })),
    );
    renderScanner("/?url=https%3A%2F%2Fpreset.example");

    expect(await screen.findByText("legitimate")).toBeInTheDocument();
    await waitFor(() =>
      expect(
        spy.mock.calls.some(([input]) => String(input).includes("/api/scan")),
      ).toBe(true),
    );
  });

  it("does not start a second scan while one is in flight", async () => {
    let resolveScan: (value: Response) => void = () => {};
    const spy = stubFetch((url) => {
      if (url.includes("/api/agent")) return jsonResponse(AGENT_OFF);
      return new Promise<Response>((resolve) => {
        resolveScan = resolve;
      });
    });
    const user = userEvent.setup();
    renderScanner();

    await user.click(screen.getByRole("button", { name: "wikipedia.org" }));
    // The chips are disabled while busy, so a second click cannot fire.
    expect(screen.getByRole("button", { name: "neverssl.com" })).toBeDisabled();

    resolveScan({
      ok: true,
      status: 200,
      json: () => Promise.resolve(scanResult()),
    } as Response);

    expect(await screen.findByText("legitimate")).toBeInTheDocument();
    const scanCalls = spy.mock.calls.filter(([input]) =>
      String(input).includes("/api/scan"),
    );
    expect(scanCalls).toHaveLength(1);
  });
});
