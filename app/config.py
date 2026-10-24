from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(os.environ.get("UNKEV_CONFIG_DIR", ROOT / "config"))


def load_yaml(name: str) -> dict:
    path = CONFIG_DIR / name
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@dataclass(frozen=True)
class Settings:
    db_path: str
    anthropic_api_key: str | None
    anthropic_version: str
    extract_model: str
    brief_model: str
    llm_daily_token_budget: int
    llm_batch_size: int
    nvd_api_key: str | None
    dashboard_user: str
    dashboard_password: str | None
    http_timeout: float
    user_agent: str
    inprocess_worker: bool
    interval_minutes: int


@lru_cache
def get_settings() -> Settings:
    e = os.environ.get
    return Settings(
        db_path=e("UNKEV_DB", str(ROOT / "unkev.db")),
        anthropic_api_key=e("ANTHROPIC_API_KEY"),
        anthropic_version=e("ANTHROPIC_VERSION", "2023-06-01"),
        # IDs checked against GET /v1/models on 2026-10-23. Any listed model works for
        # extraction; ones that reject forced tool_choice fall back to auto (see llm.py).
        extract_model=e("UNKEV_EXTRACT_MODEL", "claude-opus-5-5"),
        brief_model=e("UNKEV_BRIEF_MODEL", "claude-opus-5-5"),
        llm_daily_token_budget=int(e("UNKEV_LLM_DAILY_TOKENS", "400000") or 0),   # 0 = no cap
        llm_batch_size=int(e("UNKEV_LLM_BATCH", "8")),
        nvd_api_key=e("NVD_API_KEY"),
        dashboard_user=e("UNKEV_USER", "operator"),
        dashboard_password=e("UNKEV_PASSWORD"),
        http_timeout=float(e("UNKEV_HTTP_TIMEOUT", "30")),
        user_agent=e("UNKEV_UA", "UnKEV/0.2 (+https://github.com/networkitout/UnKEV)"),
        inprocess_worker=e("UNKEV_INPROCESS_WORKER", "0") == "1",
        interval_minutes=int(e("UNKEV_INTERVAL_MIN", "60")),
    )
