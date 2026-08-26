import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

const TABS = [
  { to: "/", label: "Scanner", end: true },
  { to: "/history", label: "History", end: false },
  { to: "/stats", label: "Stats", end: false },
  { to: "/findings", label: "Research findings", end: false },
] as const;

function SphinxMark() {
  return (
    <svg
      className="brand-mark"
      viewBox="0 0 48 48"
      aria-hidden="true"
      focusable="false"
    >
      <rect width="48" height="48" rx="4" fill="currentColor" />
      <circle cx="24" cy="11.4" r="2.15" fill="var(--bg)" />
      <path
        d="M10.8 29.2c-2.6.3-3.8 3.2-2.2 5.1"
        fill="none"
        stroke="var(--bg)"
        strokeWidth="1.65"
        strokeLinecap="round"
      />
      <ellipse cx="16.6" cy="31.2" rx="6" ry="5" fill="var(--bg)" />
      <rect x="16.2" y="27.4" width="15.2" height="8.4" rx="2.2" fill="var(--bg)" />
      <rect x="30.2" y="24.2" width="5.4" height="11.6" rx="1.8" fill="var(--bg)" />
      <rect x="31.6" y="33.6" width="8.2" height="2.5" rx="1.2" fill="var(--bg)" />
      <path fill="var(--bg)" d="M30.4 16.4h8.8l1.7 8H28.8l1.6-8z" />
      <rect
        x="12.4"
        y="36.2"
        width="24"
        height="1.2"
        rx="0.4"
        fill="var(--bg)"
        opacity="0.7"
      />
    </svg>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <header className="masthead">
        <div className="wrap">
          <div className="masthead-inner">
            <div className="brand">
              <SphinxMark />
              <div>
                <h1>Sphinx</h1>
                <p className="brand-kicker">phishing scanner</p>
              </div>
            </div>
            <p className="brand-aside">
              Live page fetch. Trained classifier. Explained verdict. No login.
            </p>
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
      <footer className="footer">
        <div className="wrap footer-grid">
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
        </div>
      </footer>
    </>
  );
}
