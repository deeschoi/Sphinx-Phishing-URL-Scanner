import { type FormEvent, useEffect, useRef, useState } from "react";
import { askAnalyst, fetchAgentStatus } from "../api";
import { clearGroqApiKey, getGroqApiKey, setGroqApiKey } from "../groqKey";
import type { AgentStatus, ChatMessage, ScanResult, ToolUse } from "../types";
import { AnalystReply } from "./AnalystReply";

/** Questions worth asking about any scan, phrased so the answer has to cite
 *  measured evidence rather than an opinion about the URL string. */
const PROMPTS = [
  "Why this verdict?",
  "What would change your mind?",
  "What could this scan have missed?",
  "How much should I trust this score?",
];

const TOOL_LABEL: Record<string, string> = {
  get_signals: "read the SHAP attributions",
  get_features: "read the extracted features",
  get_extraction_warnings: "checked what could not be measured",
  get_model_card: "read the model card",
  get_feature_definition: "looked up a feature definition",
  get_host_history: "looked up this host in scan history",
  rescan_url: "ran a fresh scan",
};

interface Turn extends ChatMessage {
  tools?: ToolUse[];
}

const MIN_THINKING_MS = 700;

export function Analyst({ result }: { result: ScanResult }) {
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [draft, setDraft] = useState("");
  const [keyDraft, setKeyDraft] = useState("");
  const [hasKey, setHasKey] = useState(() => Boolean(getGroqApiKey()));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchAgentStatus()
      .then((payload) => {
        if (!cancelled) setStatus(payload);
      })
      .catch(() => {
        if (!cancelled) {
          setStatus({
            enabled: true,
            requires_user_key: true,
            model: null,
            detail: null,
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Each scan is its own conversation. Carrying turns across scans would let
  // the analyst answer about one URL using evidence from another.
  useEffect(() => {
    setTurns([]);
    setError(null);
    setDraft("");
  }, [result.url, result.probability]);

  useEffect(() => {
    // Mounting an empty log still moves the page if we scrollIntoView here —
    // the sentinel sits below the fold after a scan. Only follow new turns.
    if (turns.length === 0 && !busy) return;
    const log = endRef.current?.closest(".analyst-log");
    if (log) {
      log.scrollTop = log.scrollHeight;
      return;
    }
    endRef.current?.scrollIntoView({ block: "nearest" });
  }, [turns, busy]);

  const needsKey = Boolean(status?.requires_user_key) && !hasKey;
  const chatLocked = needsKey || busy;

  async function ask(question: string) {
    const text = question.trim();
    if (!text || chatLocked) return;
    const next: Turn[] = [...turns, { role: "user", content: text }];
    setTurns(next);
    setDraft("");
    setBusy(true);
    setError(null);
    try {
      const started = Date.now();
      const reply = await askAnalyst(
        result,
        next.map(({ role, content }) => ({ role, content })),
      );
      const elapsed = Date.now() - started;
      if (elapsed < MIN_THINKING_MS) {
        await new Promise((resolve) => setTimeout(resolve, MIN_THINKING_MS - elapsed));
      }
      setTurns([
        ...next,
        { role: "assistant", content: reply.reply, tools: reply.tools_used },
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The analyst is unavailable.");
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    void ask(draft);
  }

  function onSaveKey(event: FormEvent) {
    event.preventDefault();
    const value = keyDraft.trim();
    if (!value.startsWith("gsk_") || value.length < 8) {
      setError("Groq keys start with gsk_.");
      return;
    }
    setGroqApiKey(value);
    setKeyDraft("");
    setHasKey(true);
    setError(null);
  }

  function onClearKey() {
    clearGroqApiKey();
    setHasKey(false);
    setError(null);
  }

  if (status && status.enabled === false) {
    return (
      <section className="analyst is-off">
        <h3 className="section-title">Ask about this scan</h3>
        <p className="section-sub">
          {status.detail ??
            "The analyst is not configured on this deployment."}
        </p>
      </section>
    );
  }

  return (
    <section className="analyst" aria-label="Ask about this scan">
      <h3 className="section-title">Ask about this scan</h3>
      <p className="section-sub">
        Answers are grounded in this scan's own evidence — the SHAP
        attributions, the extracted features, what could not be measured, and
        the model card. The analyst explains the classifier's verdict; it does
        not produce one of its own.
      </p>

      {needsKey ? (
        <form className="analyst-key" onSubmit={onSaveKey} autoComplete="off">
          <p className="analyst-key-trust">
            {status?.detail ??
              "Scans work without a key. Chat needs a Groq API key from you."}{" "}
            The key is sent only with chat, not stored on the server, and gone
            when this tab closes.
          </p>
          <div className="analyst-key-row">
            <input
              className="url-input"
              type="password"
              value={keyDraft}
              onChange={(event) => setKeyDraft(event.target.value)}
              placeholder="gsk_…"
              aria-label="Groq API key"
              autoComplete="off"
              spellCheck={false}
            />
            <button
              className="scan-button"
              type="submit"
              disabled={!keyDraft.trim()}
            >
              Save
            </button>
          </div>
        </form>
      ) : null}

      {status?.requires_user_key && hasKey ? (
        <p className="analyst-key-saved">
          Using a session Groq key.{" "}
          <button
            type="button"
            className="analyst-key-clear"
            onClick={onClearKey}
          >
            Clear
          </button>
        </p>
      ) : null}

      <div className="analyst-log" aria-live="polite" aria-busy={busy}>
        {turns.length === 0 && !busy ? (
          <p className="analyst-hint">
            {needsKey
              ? "Save a Groq key above to ask about this scan."
              : "Nothing asked yet. Try one of the questions below."}
          </p>
        ) : null}
        {turns.map((turn, index) => (
          <div
            key={`${turn.role}-${index}`}
            className={`analyst-turn is-${turn.role}`}
          >
            <span className="analyst-who">
              {turn.role === "user" ? "You" : "Analyst"}
            </span>
            {turn.role === "assistant" ? (
              <AnalystReply content={turn.content} />
            ) : (
              <div className="analyst-text">{turn.content}</div>
            )}
            {turn.tools && turn.tools.length ? (
              <div className="analyst-tools">
                Checked:{" "}
                {[
                  ...new Set(
                    turn.tools.map((t) => TOOL_LABEL[t.tool] ?? t.tool),
                  ),
                ].join(", ")}
              </div>
            ) : null}
          </div>
        ))}
        {busy ? (
          <div
            className="analyst-turn is-assistant is-thinking"
            role="status"
            aria-live="polite"
            aria-label="Analyst is thinking"
          >
            <span className="analyst-who">Analyst</span>
            <div className="analyst-thinking">
              <span className="analyst-spinner" aria-hidden="true" />
              <span className="analyst-thinking-copy">Reading the evidence</span>
              <span className="analyst-dots" aria-hidden="true">
                <span />
                <span />
                <span />
              </span>
            </div>
          </div>
        ) : null}
        <div ref={endRef} />
      </div>

      {error ? (
        <div className="status is-error" role="alert">
          {error}
        </div>
      ) : null}

      <div className="analyst-prompts">
        {PROMPTS.map((prompt) => (
          <button
            key={prompt}
            type="button"
            className="chip"
            disabled={chatLocked}
            onClick={() => void ask(prompt)}
          >
            {prompt}
          </button>
        ))}
      </div>

      <form className="analyst-bar" onSubmit={onSubmit} autoComplete="off">
        <input
          className="url-input"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="Ask about the signals, the score, or what was missed"
          aria-label="Ask the analyst about this scan"
          maxLength={2000}
          disabled={chatLocked}
        />
        <button
          className="scan-button"
          type="submit"
          disabled={chatLocked || !draft.trim()}
        >
          Ask
        </button>
      </form>
      {status?.model ? (
        <p className="analyst-model">
          Answers generated by {status.model} via Groq, restricted to this scan's
          evidence. Treat them as an explanation of the model, not as security advice.
        </p>
      ) : null}
    </section>
  );
}
