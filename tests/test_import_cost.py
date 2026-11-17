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
