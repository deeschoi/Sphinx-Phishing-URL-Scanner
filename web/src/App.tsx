import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Layout } from "./components/Layout";
import { Scanner } from "./views/Scanner";

const History = lazy(() =>
  import("./views/History").then((module) => ({ default: module.History })),
);
const Batch = lazy(() =>
  import("./views/Batch").then((module) => ({ default: module.Batch })),
);
const Stats = lazy(() =>
  import("./views/Stats").then((module) => ({ default: module.Stats })),
);
const FindingsView = lazy(() =>
  import("./views/Findings").then((module) => ({ default: module.FindingsView })),
);

export default function App() {
  return (
    <Layout>
      <ErrorBoundary>
        <Suspense fallback={<p className="status">Loading…</p>}>
          <Routes>
            <Route path="/" element={<Scanner />} />
            <Route path="/batch" element={<Batch />} />
            <Route path="/history" element={<History />} />
            <Route path="/stats" element={<Stats />} />
            <Route path="/findings" element={<FindingsView />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </ErrorBoundary>
    </Layout>
  );
}
