"""크리덴셜 세션 — 프로세스 메모리 전용.

고객사 PC 에 계정 정보를 어떤 형태로도 기록하지 않는다.
암호화 보관조차 하지 않는다. 잠긴 금고 파일도 잔류물이다.

세션 잠금(idle timeout) 시 메모리에서 폐기한다.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Literal, NoReturn

from infraguard.credentials.secret import Secret

AuthKind = Literal["password", "key", "agent"]

DEFAULT_IDLE_SECONDS = 15 * 60


@dataclass(slots=True)
class Credential:
    """접속 자격. password/passphrase 는 Secret 으로만 보유한다."""

    cred_id: str
    username: str
    kind: AuthKind = "password"
    password: Secret | None = None
    key_path: str | None = None          # 경로만. 키 파일 본문은 보유하지 않는다
    key_passphrase: Secret | None = None
    sudo_password: Secret | None = None

    def __reduce__(self) -> NoReturn:
        raise TypeError("Credential is not serializable")

    def clear(self) -> None:
        for s in (self.password, self.key_passphrase, self.sudo_password):
            if s is not None:
                s.clear()
        self.password = None
        self.key_passphrase = None
        self.sudo_password = None


class CredentialSession:
    """메모리 전용 크리덴셜 보관소.

    - 디스크 기록 경로 없음
    - idle timeout 경과 시 자동 폐기
    - 여러 호스트가 같은 계정을 공유하면 세션 내 재사용
    """

    def __init__(self, idle_seconds: int = DEFAULT_IDLE_SECONDS) -> None:
        self._creds: dict[str, Credential] = {}
        self._lock = threading.RLock()
        self._idle = idle_seconds
        self._last_touch = time.monotonic()
        self._locked = False

    # --- 상태 ---
    @property
    def is_locked(self) -> bool:
        self._check_idle()
        return self._locked

    def _touch(self) -> None:
        self._last_touch = time.monotonic()

    def _check_idle(self) -> None:
        if self._locked:
            return
        if time.monotonic() - self._last_touch > self._idle:
            self.lock()

    # --- 조작 ---
    def put(self, cred: Credential) -> None:
        with self._lock:
            self._check_idle()
            if self._locked:
                raise RuntimeError("credential session is locked")
            self._creds[cred.cred_id] = cred
            self._touch()

    def get(self, cred_id: str) -> Credential | None:
        with self._lock:
            self._check_idle()
            if self._locked:
                raise RuntimeError("credential session is locked")
            c = self._creds.get(cred_id)
            if c is not None:
                self._touch()
            return c

    def ids(self) -> list[str]:
        with self._lock:
            self._check_idle()
            return sorted(self._creds)

    def lock(self) -> None:
        """메모리에서 폐기한다."""
        with self._lock:
            for c in self._creds.values():
                c.clear()
            self._creds.clear()
            self._locked = True

    def unlock(self) -> None:
        """다시 입력받을 수 있는 상태로. 이전 값은 복구되지 않는다."""
        with self._lock:
            self._locked = False
            self._touch()

    # --- 컨텍스트 ---
    def __enter__(self) -> CredentialSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.lock()

    def __reduce__(self) -> NoReturn:
        raise TypeError("CredentialSession is not serializable")

    def __repr__(self) -> str:
        return f"CredentialSession(count={len(self._creds)}, locked={self._locked})"
