"""파서 공통."""

from __future__ import annotations

from dataclasses import dataclass, field

from infraguard.core.models import RawFinding


@dataclass(slots=True)
class ParseResult:
    findings: list[RawFinding] = field(default_factory=list)
    profile: str | None = None
    encoding: str | None = None
    encoding_error: bool = False
    warnings: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


class ProfileNotFound(Exception):
    pass


class AmbiguousProfile(Exception):
    """복수 프로파일이 동일 구체성으로 매칭. 추측하지 않고 실패시킨다."""
