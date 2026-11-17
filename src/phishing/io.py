"""Serialisation helpers shared by the analysis scripts."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any


def to_jsonable(value: Any) -> Any:
    """Convert numpy scalars, arrays, and non-finite floats into JSON-safe types.

    ``json.dump`` emits ``NaN`` and ``Infinity``, which are not valid JSON and
    break the browser's ``JSON.parse`` when the API serves these files.
    """
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    # Only look for numpy types when numpy is already loaded: if it is not,
    # no value can be one, and the agent/findings paths stay numpy-free.
    np = sys.modules.get("numpy")
    if np is not None:
        if isinstance(value, np.ndarray):
            return [to_jsonable(v) for v in value.tolist()]
        if isinstance(value, np.integer):
            return int(value)
        if isinstance(value, np.floating):
            value = float(value)
        if isinstance(value, np.bool_):
            return bool(value)
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if isinstance(value, Path):
        return str(value)
    return value


def save_json(payload: Any, path: Path, indent: int = 2) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_jsonable(payload), indent=indent))
    return path


def load_json(path: Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {}
    return json.loads(path.read_text())
