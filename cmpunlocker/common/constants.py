from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_CONSTANTS_PATH = Path(__file__).parent / "constants.yaml"


def _load_constants() -> dict:
    with open(_CONSTANTS_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@lru_cache(maxsize=1)
def get_constants() -> dict:
    return _load_constants()


def get(key: str, default: Any = None) -> Any:
    parts = key.split(".")
    val = get_constants()
    for part in parts:
        if isinstance(val, dict) and part in val:
            val = val[part]
        elif isinstance(val, list):
            try:
                idx = int(part)
                val = val[idx]
            except (ValueError, IndexError):
                return default
        else:
            return default
    return val
