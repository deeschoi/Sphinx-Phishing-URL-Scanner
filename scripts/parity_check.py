#!/usr/bin/env python3
"""Compare Render and a Vercel deploy before switching the public link.

Verdicts on the platform-legitimate URL list must agree. Model-card accuracy
and AUROC must be within ``--metric-tolerance`` (default 0.02). The Vercel
function trains on xgboost-cpu, so the cards are not bit-identical to the
Render image. History and stats must answer. Chat is checked when
``--groq-key`` is set.

Exit 0 when the hosts agree. Exit 2 when a base URL was not given.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _platform_urls() -> list[str]:
    source = (Path(__file__).resolve().parent / "07_live_sample_eval.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "PLATFORM_LEGIT_URLS":
                value = node.value
                if not isinstance(value, ast.List):
                    break
                urls = []
                for element in value.elts:
                    if isinstance(element, ast.Constant):
                        urls.append(str(element.value))
                return urls
    raise SystemExit("PLATFORM_LEGIT_URLS is missing from scripts/07_live_sample_eval.py")


def request(
    method: str,
    url: str,
    body: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 90,
) -> tuple[int, dict[str, str], bytes]:
    data = None if body is None else json.dumps(body).encode()
    merged = dict(headers or {})
    if data is not None:
        merged.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=merged, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def header(headers: dict[str, str], name: str) -> str:
    folded = name.casefold()
    for key, value in headers.items():
        if key.casefold() == folded:
            return value
    return ""


def scan(base: str, url: str) -> dict:
    for _attempt in range(8):
        status, headers, raw = request("POST", base + "/api/scan", {"url": url})
        if status == 429:
            time.sleep(int(header(headers, "Retry-After") or "8"))
            continue
        if status != 200:
            raise SystemExit(f"{base} scan {url} returned {status}: {raw[:240]!r}")
        return json.loads(raw)
    raise SystemExit(f"{base} stayed rate-limited while scanning {url}")


def model_card(base: str) -> dict[str, dict]:
    status, _headers, raw = request("GET", base + "/api/model", timeout=30)
    if status != 200:
        raise SystemExit(f"{base} /api/model returned {status}")
    payload = json.loads(raw)
    return {
        name: card
        for name, card in payload.items()
        if isinstance(card, dict) and "accuracy" in card
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("render", help="Current public host, for example the Render URL")
    parser.add_argument("vercel", help="Vercel deployment to compare")
    parser.add_argument("--metric-tolerance", type=float, default=0.02)
    parser.add_argument(
        "--groq-key",
        default="",
        help="Optional visitor key. When set, chat is posted against the Vercel scan.",
    )
    args = parser.parse_args()
    left = args.render.rstrip("/")
    right = args.vercel.rstrip("/")

    failures: list[str] = []
    left_card = model_card(left)
    right_card = model_card(right)
    if set(left_card) != set(right_card):
        failures.append(f"model names {sorted(left_card)} vs {sorted(right_card)}")
    for name in sorted(set(left_card) & set(right_card)):
        for metric in ("accuracy", "auroc"):
            delta = abs(float(left_card[name][metric]) - float(right_card[name][metric]))
            print(f"{name} {metric} delta {delta:.4f}")
            if delta > args.metric_tolerance:
                failures.append(f"{name} {metric} delta {delta:.4f}")

    for path in ("/api/scans", "/api/stats"):
        status, _headers, raw = request("GET", right + path, timeout=30)
        if status != 200:
            failures.append(f"Vercel {path} returned {status}: {raw[:160]!r}")

    sample: dict | None = None
    for url in _platform_urls():
        render_row = scan(left, url)
        vercel_row = scan(right, url)
        sample = vercel_row
        same = render_row.get("verdict") == vercel_row.get("verdict")
        render_verdict = render_row.get("verdict")
        vercel_verdict = vercel_row.get("verdict")
        print(f"{'ok' if same else 'DIFF'} {url} {render_verdict} / {vercel_verdict}")
        if not same:
            failures.append(f"{url}: {render_row.get('verdict')} vs {vercel_row.get('verdict')}")

    if args.groq_key:
        if sample is None:
            failures.append("no scan payload to send to chat")
        else:
            status, _headers, raw = request(
                "POST",
                right + "/api/chat",
                {"scan": sample, "messages": [{"role": "user", "content": "Why this verdict?"}]},
                headers={"X-Groq-Api-Key": args.groq_key},
                timeout=90,
            )
            if status != 200:
                failures.append(f"Vercel chat returned {status}: {raw[:240]!r}")
    else:
        status, _headers, _raw = request("POST", right + "/api/chat", {}, timeout=30)
        if status != 422:
            failures.append(f"Vercel chat rejected an empty body with {status}, expected 422")

    if failures:
        print(f"\n{len(failures)} difference(s):", file=sys.stderr)
        for item in failures:
            print(f"  {item}", file=sys.stderr)
        return 1
    print("\nHosts agree. The README link can move to Vercel.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
