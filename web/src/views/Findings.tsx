import { useEffect, useState } from "react";
import { fetchFindings } from "../api";
import { DataTable } from "../components/DataTable";
import { StatusMessage } from "../components/EmptyState";
import { fixed, pct } from "../format";
import type { Findings } from "../types";

export function FindingsView() {
  const [data, setData] = useState<Findings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchFindings()
      .then((payload) => {
        if (!cancelled) setData(payload);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Could not load findings.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) return <StatusMessage message={`Could not load findings: ${error}`} error />;
  if (!data) return <StatusMessage message="Loading findings…" />;

  return (
    <div className="findings">
      <header>
        <p className="hero-kicker">2012 UCI analysis</p>
        <h2 className="page-title">Research findings</h2>
        <p className="section-sub">
          Headline tables from the coursework that started this project. Nothing on
          this page is used to score a URL.
        </p>
      </header>
      <LeakageCard data={data} />
      <EncodingCard data={data} />
      <ObsolescenceCard data={data} />
    </div>
  );
}

function LeakageCard({ data }: { data: Findings }) {
  const leakage = data.leakage || {};
  return (
    <section className="finding">
      <h3>Duplicate feature vectors inflate the published accuracy</h3>
      <p className="lede">
        Roughly half the dataset consists of repeated feature patterns. Under a random
        split most test rows have already been seen during training, so the model is
        scored partly on memory. Re-partitioning so each pattern falls entirely on one
        side lowers every score, and the drop is largest for the models with the most
        capacity to memorise.
      </p>
      <div className="stat-row">
        <div className="stat">
          <strong>{pct(leakage.duplicate_row_fraction)}</strong>
          <span>of rows are duplicate patterns</span>
        </div>
        <div className="stat">
          <strong>{pct(leakage.random_split_test_rows_seen_in_train)}</strong>
          <span>of test rows already seen in training</span>
        </div>
        <div className="stat">
          <strong>{leakage.conflicting_label_patterns ?? "—"}</strong>
          <span>patterns with contradictory labels</span>
        </div>
      </div>
      <DataTable
        headers={["Model", "Random split", "Grouped split", "Optimism"]}
        rows={(data.models || []).map((row) => [
          row.model,
          { value: fixed(row.random_accuracy, 4), num: true },
          { value: fixed(row.grouped_accuracy, 4), num: true },
          {
            value: `+${fixed(row.accuracy_optimism, 4)}`,
            num: true,
            cls: row.accuracy_optimism > 0.015 ? "bad" : "",
          },
        ])}
      />
    </section>
  );
}

function EncodingCard({ data }: { data: Findings }) {
  const reversed = data.reversed_features || [];
  const audit = (data.encoding_audit || []).filter((row) => row.verdict === "reversed");
  return (
    <section className="finding">
      <h3>
        {reversed.length} features are encoded backwards from their documented meaning
      </h3>
      <p className="lede">
        The source paper defines -1 as a phishing indicator, so the phishing rate should
        fall as the encoded value rises. For these features the data does the opposite.
        This is measured directly from the raw table, with no model involved, and it
        means the published feature definitions cannot be taken at face value.
      </p>
      <DataTable
        headers={["Feature", "Documented -1 means", "P(phish | -1)", "P(phish | +1)"]}
        rows={audit.map((row) => [
          row.feature,
          row["documented -1 means"],
          { value: fixed(row["P(phish|-1)"], 3), num: true },
          { value: fixed(row["P(phish|+1)"], 3), num: true, cls: "bad" },
        ])}
      />
      {(data.no_signal_features || []).length ? (
        <>
          <p className="lede" style={{ marginTop: 16 }}>
            A further set carries no marginal signal at all, with an identical phishing
            rate at every value:
          </p>
          <ul className="pill-list">
            {data.no_signal_features.map((feature) => (
              <li className="pill" key={feature}>
                {feature}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}

function ObsolescenceCard({ data }: { data: Findings }) {
  const unavailable = data.unavailable_features || [];
  return (
    <section className="finding">
      <h3>What survives when 2012-era features disappear</h3>
      <p className="lede">
        Five features depend on services that no longer exist. Dropping them costs about
        two accuracy points, so a model that can actually run today remains viable.
        Removing the certificate signal hurts far more, and the URL string on its own is
        not enough.
      </p>
      <DataTable
        headers={["Feature set", "Features", "Accuracy", "Change"]}
        rows={(data.scenarios || []).map((row) => [
          row.scenario,
          { value: row.n_features, num: true },
          { value: fixed(row.accuracy, 4), num: true },
          {
            value: row.delta_vs_full === 0 ? "—" : fixed(row.delta_vs_full, 4),
            num: true,
            cls:
              row.delta_vs_full < -0.02 ? "bad" : row.delta_vs_full >= 0 ? "good" : "",
          },
        ])}
      />
      {unavailable.length ? (
        <>
          <p className="lede" style={{ marginTop: 18 }}>
            Why each of those five can no longer be computed:
          </p>
          <DataTable
            headers={["Feature", "Reason"]}
            rows={unavailable.map((row) => [row.feature, row.reason])}
          />
        </>
      ) : null}
    </section>
  );
}
