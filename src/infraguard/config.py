"""도구 설정 — 실행 폴더의 config.json.

workspace 가 아니라 실행 폴더에 둔다. 완전삭제 후에도 도구 설정은 유지되어야 하기 때문(§10).
**호스트 주소·계정·비밀번호를 절대 쓰지 않는다.** 저장 시 금지 키를 강제로 걸러낸다.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from infraguard.workspace.layout import app_root

log = logging.getLogger(__name__)

CONFIG_NAME = "config.json"

# 접속 대상·계정·비밀번호가 새어 들어오는 것을 막는 금지 키(부분일치)
FORBIDDEN_SUBSTRINGS = (
    "password", "passwd", "pwd", "secret", "token", "credential", "passphrase",
    "username", "account", "host", "address", "ip", "key", "api", "bastion",
)

DEFAULTS: dict[str, Any] = {
    "concurrency": 5,
    "default_timeout": 1800,
    "max_output_kb": 1024,
    "use_sudo": False,
    "connect_timeout": 15,
    "idle_lock_minutes": 15,
    "terminal_recording": True,
    "export_format": "xlsx",
    "company_name": "",
    "theme": "dark",
    "wipe_on_exit": True,     # 고객사 PC 반입 시 켜 둔다. 자기 PC(개발·검토)에서는 꺼서 결과·자산을 유지
}


def _forbidden(key: str) -> bool:
    k = key.lower()
    return any(s in k for s in FORBIDDEN_SUBSTRINGS)


def config_path() -> Path:
    return app_root() / CONFIG_NAME


def load() -> dict[str, Any]:
    p = config_path()
    cfg = dict(DEFAULTS)
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            for k, v in data.items():
                if not _forbidden(k):
                    cfg[k] = v
        except (json.JSONDecodeError, OSError) as e:
            log.warning("config 읽기 실패: %s", e)
    return cfg


def save(cfg: dict[str, Any]) -> Path:
    """금지 키(접속·계정·비밀번호)는 저장하지 않는다."""
    clean = {k: v for k, v in cfg.items() if not _forbidden(k)}
    p = config_path()
    p.write_text(json.dumps(clean, ensure_ascii=False, indent=2), encoding="utf-8")
    return p
