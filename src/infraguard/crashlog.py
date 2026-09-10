"""크래시 로그 — 처리되지 않은 예외를 workspace/logs/crash.log 에 남긴다(아키텍처 §9, §12).

- 마스킹 적용: 트레이스백 문자열에 크리덴셜·해시·키가 섞여도 파일에 남지 않는다.
- workspace 안에만 쓴다 → 완전삭제 대상.
- --noconsole 빌드에서는 stderr 가 없으므로 이 파일이 유일한 단서다.
"""

from __future__ import annotations

import sys
import traceback
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from infraguard.result.masking import mask

Hook = Callable[[type[BaseException], BaseException, object], None]


def format_masked(exc_type: type[BaseException], exc: BaseException, tb: object) -> str:
    text = "".join(traceback.format_exception(exc_type, exc, tb))  # type: ignore[arg-type]
    return mask(text) or ""


def install(log_path: Path, notify: Callable[[str], None] | None = None) -> Hook:
    """sys.excepthook 을 설치하고 훅을 돌려준다(테스트용)."""

    def hook(exc_type: type[BaseException], exc: BaseException, tb: object) -> None:
        body = format_masked(exc_type, exc, tb)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"\n### {datetime.now().isoformat(timespec='seconds')}\n{body}")
        except OSError:
            pass
        try:
            sys.__stderr__ and sys.__stderr__.write(body)  # 콘솔이 있으면 그대로도
        except Exception:  # noqa: BLE001,S110
            pass
        if notify is not None:
            try:
                notify(str(log_path))
            except Exception:  # noqa: BLE001,S110
                pass

    sys.excepthook = hook
    return hook
