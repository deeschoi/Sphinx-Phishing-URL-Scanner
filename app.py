"""Vercel entrypoint.

Vercel loads one FastAPI app from a supported file (``app.py`` at the repo
root, or ``tool.vercel.entrypoint``). Files under ``api/`` are the application
package. Without this module, those files would be built as separate
functions, and ``api/security.py`` has no handler.

``OMP_NUM_THREADS`` is set before the model imports. XGBoost's default thread
pool is a poor fit for a short function.
"""

import os

os.environ.setdefault("OMP_NUM_THREADS", "1")

from api.main import app

__all__ = ["app"]
