"""Cold-start guard: importing the app must not load the model stack.

On Vercel every cold instance pays for what ``import app`` pulls in, even for
/api/health. The model (xgboost, scipy, and sklearn to unpickle) and pandas
load on the first scan or /api/warm instead.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEAVY = ("sklearn", "scipy", "xgboost", "pandas", "numpy")


def test_import_app_skips_the_model_stack():
    code = (
        "import json, sys; import app; "
        f"print(json.dumps([m for m in {HEAVY!r} if m in sys.modules]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    loaded = json.loads(result.stdout.strip().splitlines()[-1])
    assert loaded == [], f"import app loaded {loaded}"


def test_import_app_ignores_runtime_secrets():
    """Vercel's build imports the app to find app.frontend() for the CDN.

    ``vercel pull`` cannot read Sensitive variables, so REDIS_URL is not a real
    URL there. If the import touches it, discovery finds no frontend and the
    deploy fails the static-output check.
    """
    import os

    env = {
        **os.environ,
        "SPHINX_RATE_LIMIT_BACKEND": "redis",
        "REDIS_URL": "not-a-redis-url",
    }
    code = (
        "import app; "
        "groups = getattr(app.app.router, '_low_priority_routes', []); "
        "print(len(groups))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr[-2000:]
    if (ROOT / "web" / "dist" / "index.html").is_file():
        assert result.stdout.strip().splitlines()[-1] == "1"
