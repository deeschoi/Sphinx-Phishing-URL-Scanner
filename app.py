"""Vercel entrypoint.

Vercel loads one FastAPI app from a supported file (``app.py`` at the repo
root, or ``tool.vercel.entrypoint``). Files under ``api/`` are the application
package. Without this module, those files would be built as separate
functions, and ``api/security.py`` has no handler.

``OMP_NUM_THREADS`` is set before the model imports. XGBoost's default thread
pool is a poor fit for a short function.

``src`` goes on ``sys.path`` so ``phishing`` imports even when the builder
did not install the project. Docker and CI install it with ``pip install .``;
the function must not depend on that.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")

_SRC = str(Path(__file__).resolve().parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from api.main import app

__all__ = ["app"]
