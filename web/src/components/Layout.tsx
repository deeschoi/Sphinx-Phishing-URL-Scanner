import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

const TABS = [
  { to: "/", label: "Scanner", end: true },
  { to: "/history", label: "History", end: false },
  { to: "/stats", label: "Stats", end: false },
  { to: "/findings", label: "Research findings", end: false },
] as const;

export function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <header className="masthead">
        <div className="wrap">
          <div className="brand">
            <div>
              <h1>Sphinx</h1>
              <p className="brand-kicker">phishing scanner</p>
              <p>
                Sphinx is a live phishing scanner. Paste a URL and it fetches the
                page, scores the risk with a trained classifier, and shows which
                signals decided the verdict.
              </p>
            </div>
          </div>
          {/* Plain navigation, not a tablist. role="tablist" without
              aria-selected/aria-controls told a screen reader these were tabs
              and then gave it none of the state a tab is supposed to carry. */}
          <nav className="tabs" aria-label="Sections">
            {TABS.map((tab) => (
              <NavLink
                key={tab.to}
                to={tab.to}
                end={tab.end}
                className={({ isActive }) => (isActive ? "tab is-active" : "tab")}
              >
                {tab.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="wrap">
        <section className="view">{children}</section>
      </main>
      <footer className="wrap footer">
        <p>
          The scanner is trained on the PhiUSIIL Phishing URL dataset (Prasad
          &amp; Chandra, 2023): 48 features from the URL string and the fetched
          HTML, evaluated on a hold-out split grouped by hostname so no host
          appears in both training and test. Held-out accuracy is measured on
          that dataset's frozen columns; the live figures on each scan are the
          same model re-extracting features over the network, and they are the
          ones that describe a real scan.
        </p>
        <p>
          The <strong>Research findings</strong> tab is separate coursework on
          the older UCI Phishing Websites dataset (Mohammad, Thabtah &amp;
          McCluskey, 2012). Nothing there is used to score a URL.
        </p>
      </footer>
    </>
  );
}
