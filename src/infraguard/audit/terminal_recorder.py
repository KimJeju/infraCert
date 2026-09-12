"""터미널 기록기(§7.3) — 입력·출력을 모두 기록하되 비밀은 남기지 않는다.

비밀 입력 판별 2중 장치:
  A) 프롬프트 패턴 — 직전 출력이 비밀번호 요구로 끝나면 다음 입력 라인은 비밀
  B) 에코 부재   — 보낸 문자가 출력에 되돌아오지 않으면 에코 꺼진 상태로 간주

B 는 **지연 판정**이다. Enter 시점에 아직 에코가 안 온 문자가 있으면 판정을 미루고,
이후 출력에서 에코가 돌아오면 평문(명령어), ECHO_GRACE 가 지나도록 안 오면 '***'(비밀) 로 확정한다.
Enter 시점 즉시판정은 붙여넣기·초고속 입력에서 뚫린다(2026-09-10 리뷰). 애매하면 마스킹한다.

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

ECHO_GRACE = 0.2   # 초. Enter 후 이만큼 지나도 에코가 없으면 비밀 입력으로 확정
TAIL_KEEP = 400    # 프롬프트 판별용 직전 출력 보관 길이

# 프롬프트 종결은 ':' 뿐 아니라 '>'·'?' 도 흔하다(장비 CLI·Oracle 계열).
_END = r"[:>?]\s*$"
PROMPT_PATTERNS = tuple(re.compile(p) for p in (
    r"\[sudo\] password for .*" + _END,
    r"(?i)pass(word|phrase|code)[^\n]*" + _END,
    r"(?i)enter .*(password|pin|otp|passcode)[^\n]*" + _END,
    r"(?i)(current|new|retype new|old) password" + _END,
    r"(?i)\b(pin|otp|passcode|one[- ]time (code|password))\b[^\n]*" + _END,
    r"(새 암호|비밀번호|암호|인증\s?번호|인증\s?코드)[^\n]*" + _END,
))

_ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|[\x00-\x08\x0b\x0c\x0e-\x1f]"
)


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
        self._pending: deque[str] = deque()            # 에코 대기 중 문자(순서 유지)
        self._deferred: tuple[str, float] | None = None  # (라인, Enter 시각) — 판정 보류 중
        self._secret_by_prompt = False
        self._out_buf = ""                 # 출력 라인 버퍼
        self.masked_inputs = 0
        self.input_lines = 0
        self._host_label = host_label
        self._started = datetime.now()
        self._write(f"### InfraGuard terminal log {host_label} "
                    f"{datetime.now().isoformat(timespec='seconds')}")
        self._write("### 자동 진단(Bundle)은 Read-only 이며 대상을 변경하지 않습니다. "
                    "터미널에서 사용자가 직접 입력한 명령은 이 보장의 대상이 아니며 사용자 책임입니다.")

    # --------------------------------------------------------------- 출력
    def on_output(self, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        plain = strip_ansi(text)
        # 에코 대조: 보낸 문자가 출력에 순서대로 나타나면 대기열에서 제거
        for ch in plain:
            if self._pending and self._pending[0] == ch:
                self._pending.popleft()
        self._tail = (self._tail + plain)[-TAIL_KEEP:]
        self._secret_by_prompt = any(p.search(self._tail.rstrip("\r\n ")) for p in PROMPT_PATTERNS)
        # 라인 단위로 마스킹 후 기록
        self._out_buf += plain
        while "\n" in self._out_buf:
            line, self._out_buf = self._out_buf.split("\n", 1)
            self._write("[OUT] " + (mask(line.rstrip("\r")) or ""))
        self._resolve_deferred()

    # --------------------------------------------------------------- 입력
    def on_input(self, data: bytes) -> None:
        self._resolve_deferred()           # 다음 입력이 오면 보류분부터 정리(시간 경과 판정)
        text = data.decode("utf-8", errors="replace")
        now = self._clock()
        for ch in text:
            if ch in ("\r", "\n"):
                self._finish_line(now)
            elif ch in ("\x7f", "\b"):
                if self._line:
                    self._line = self._line[:-1]
                    if self._pending:
                        self._pending.pop()
            elif ch == "\x03":
                self._write("[IN] ^C")
                self._line = ""
                self._pending.clear()
            elif ch.isprintable():
                self._line += ch
                self._pending.append(ch)
            # 그 외 제어문자(방향키 등)는 기록하지 않는다

    def _finish_line(self, now: float) -> None:
        if self._deferred is not None:     # 직전 라인이 아직 보류 중이면 보수적으로 확정
            self._commit_secret()
        if self._secret_by_prompt:
            self._commit_secret()
        elif not self._pending:            # 전부 에코됨 → 평범한 명령
            if self._line:
                self._write("[IN] " + (mask(self._line) or ""))
        else:                              # 에코 미확인 → 더 지켜본다 (_pending 유지)
            self._deferred = (self._line, now)
        self._line = ""
        self._secret_by_prompt = False
        self._tail = ""

    def _resolve_deferred(self) -> None:
        if self._deferred is None:
            return
        line, t0 = self._deferred
        if not self._pending:              # 에코가 돌아왔다 → 명령어
            self._deferred = None
            if line:
                self._write("[IN] " + (mask(line) or ""))
        elif self._clock() - t0 > ECHO_GRACE:   # 끝내 에코 없음 → 비밀
            self._commit_secret()

    def _commit_secret(self) -> None:
        self._deferred = None
        self._pending.clear()
        self._write("[IN] ***")
        self.masked_inputs += 1

    # --------------------------------------------------------------- 파일
    def _write(self, s: str) -> None:
        if s.startswith("[IN] "):
            self.input_lines += 1
        self._fh.write(s + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._deferred is not None:     # 미해결 보류분은 '***' 로 확정(보수적)
            self._commit_secret()
        if self._out_buf.strip():
            self._write("[OUT] " + (mask(self._out_buf) or ""))
            self._out_buf = ""
        ended = datetime.now()
        self._write(f"### session end {self._host_label} start={self._started.isoformat(timespec='seconds')} "
                    f"end={ended.isoformat(timespec='seconds')} inputs={self.input_lines} masked={self.masked_inputs}")
        try:
            self._fh.close()
        except OSError:
            pass
