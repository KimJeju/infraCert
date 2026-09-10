"""터미널 기록기(§7.3) — 입력·출력을 모두 기록하되 비밀은 남기지 않는다.

비밀 입력 판별 2중 장치:
  A) 프롬프트 패턴 — 직전 출력이 비밀번호 요구로 끝나면 다음 입력 라인은 비밀
  B) 에코 부재   — 보낸 문자가 ECHO_GRACE 안에 출력에 나타나지 않으면 에코 꺼진 상태로 간주
둘 중 하나라도 걸리면 그 입력 라인은 '***' 로만 기록한다. 애매하면 마스킹한다.

출력 라인에는 result/masking.py 의 값 패턴 마스킹을 한 번 더 건다(`cat /etc/shadow` 대응).
파일은 workspace/logs/terminal/ 아래에만 쓴다 → Sanitizer 삭제 대상.
순수 파이썬(Qt 없음) — 테스트가 시계를 주입할 수 있다.
"""

from __future__ import annotations

import re
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from infraguard.result.masking import mask

ECHO_GRACE = 0.2   # 초. 이보다 오래 에코가 안 오면 비밀 입력으로 간주
TAIL_KEEP = 400    # 프롬프트 판별용 직전 출력 보관 길이

PROMPT_PATTERNS = tuple(re.compile(p) for p in (
    r"\[sudo\] password for .*:\s*$",
    r"(?i)password\s*:\s*$",
    r"(?i)passphrase[^:]*:\s*$",
    r"(?i)enter .*password.*:\s*$",
    r"(?i)current password:\s*$",
    r"(?i)(?:new|retype new|old) password:\s*$",
    r"(?:새 암호|비밀번호|암호)\s*:\s*$",
))

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|[\x00-\x08\x0b\x0c\x0e-\x1f]")


def strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


class TerminalRecorder:
    def __init__(self, path: Path, *, clock: Callable[[], float] = time.monotonic,
                 host_label: str = "") -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8", errors="replace")
        self._clock = clock
        self._tail = ""                    # 직전 출력(ANSI 제거)
        self._line = ""                    # 조립 중인 입력 라인
        self._pending: deque[tuple[str, float]] = deque()   # 에코 대기 중 문자
        self._secret_by_prompt = False
        self._out_buf = ""                 # 출력 라인 버퍼
        self.masked_inputs = 0
        self._write(f"### InfraGuard terminal log {host_label} {datetime.now().isoformat(timespec='seconds')}")
        self._write("### 자동 진단(Bundle)은 Read-only 이며 대상을 변경하지 않습니다. "
                    "터미널에서 사용자가 직접 입력한 명령은 이 보장의 대상이 아니며 사용자 책임입니다.")

    # --------------------------------------------------------------- 출력
    def on_output(self, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        plain = strip_ansi(text)
        # 에코 대조: 보낸 문자가 출력에 나타나면 대기열에서 제거(순서대로)
        for ch in plain:
            if self._pending and self._pending[0][0] == ch:
                self._pending.popleft()
        self._tail = (self._tail + plain)[-TAIL_KEEP:]
        self._secret_by_prompt = any(p.search(self._tail.rstrip("\r\n ")) for p in PROMPT_PATTERNS) \
            and self._tail.rstrip().endswith(":")
        # 라인 단위로 마스킹 후 기록
        self._out_buf += plain
        while "\n" in self._out_buf:
            line, self._out_buf = self._out_buf.split("\n", 1)
            self._write("[OUT] " + (mask(line.rstrip("\r")) or ""))

    # --------------------------------------------------------------- 입력
    def on_input(self, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        now = self._clock()
        for ch in text:
            if ch in ("\r", "\n"):
                self._finish_line(now)
            elif ch in ("\x7f", "\b"):
                self._line = self._line[:-1]
            elif ch == "\x03":
                self._write("[IN] ^C")
                self._line = ""
                self._pending.clear()
            elif ch.isprintable():
                self._line += ch
                self._pending.append((ch, now))
            # 그 외 제어문자(방향키 등)는 기록하지 않는다

    def _finish_line(self, now: float) -> None:
        stale = any(now - t > ECHO_GRACE for _, t in self._pending)
        secret = self._secret_by_prompt or stale
        if self._line or secret:
            if secret:
                self._write("[IN] ***")
                self.masked_inputs += 1
            else:
                self._write("[IN] " + (mask(self._line) or ""))
        self._line = ""
        self._pending.clear()
        self._secret_by_prompt = False
        self._tail = ""

    # --------------------------------------------------------------- 파일
    def _write(self, s: str) -> None:
        self._fh.write(s + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._out_buf.strip():
            self._write("[OUT] " + (mask(self._out_buf) or ""))
            self._out_buf = ""
        try:
            self._fh.close()
        except OSError:
            pass
