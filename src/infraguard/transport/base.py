"""Transport 공통 인터페이스.

Orchestrator 는 프로토콜(SSH/WinRM/NetDev/Local)을 알지 못한다.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from infraguard.core.models import RemoteEnvironment


@dataclass(slots=True)
class ExecResult:
    argv: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    encoding_error: bool = False
    error: str = ""          # 전송 계층 오류. 비어있지 않으면 ERROR 판정 근거

    @property
    def ok(self) -> bool:
        return not self.timed_out and not self.error and self.exit_code == 0


@dataclass(slots=True)
class CleanupReport:
    """원격 정리 결과. 삭제 실패를 조용히 넘기지 않는다."""

    requested: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    leftovers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.leftovers and not self.errors


class TransportError(Exception):
    pass


class HostKeyRejected(TransportError):
    pass


class Connection(ABC):
    """대상 시스템 연결."""

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def probe(self) -> RemoteEnvironment: ...

    @abstractmethod
    def exec(
        self, argv: list[str], *, timeout: int, cwd: str | None = None,
        stdin_data: str | None = None, max_output: int = 1 << 20,
    ) -> ExecResult: ...

    @abstractmethod
    def upload(self, local: Path, remote: str) -> None: ...

    @abstractmethod
    def download(self, remote: str, local: Path) -> None: ...

    @abstractmethod
    def cleanup(self, paths: list[str]) -> CleanupReport: ...

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self) -> Connection:
        self.connect()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
