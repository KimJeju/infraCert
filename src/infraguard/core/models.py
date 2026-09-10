"""표준 데이터 모델.

Result Schema 는 엔진 전체의 계약이다. 여기가 바뀌면 파서·판정·리포트가 모두 영향받는다.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from infraguard.core.status import Severity, Status


class Platform:
    LINUX = "linux"
    UNIX = "unix"        # AIX / HP-UX / Solaris
    WINDOWS = "windows"
    DBMS = "dbms"
    NETWORK = "network"
    CLOUD = "cloud"
    PC = "pc"


class RemoteEnvironment(BaseModel):
    """대상 시스템 환경. 확인 못한 값은 None 으로 둔다. 추측해서 채우지 않는다."""

    model_config = ConfigDict(frozen=True)

    os: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    hostname: str | None = None
    user: str | None = None
    privileged: bool | None = None
    shell: str | None = None
    locale: str | None = None
    encoding: str | None = None
    available_commands: dict[str, bool] = Field(default_factory=dict)
    incomplete: bool = False
    notes: list[str] = Field(default_factory=list)


class ExecutionInfo(BaseModel):
    duration_ms: int | None = None
    exit_code: int | None = None
    executor: str | None = None
    started_at: datetime | None = None
    stdout_truncated: bool = False
    encoding_error: bool = False


class SourceInfo(BaseModel):
    """이 결과가 어디서 나왔는지. 추적성의 핵심."""

    bundle_id: str | None = None
    artifact: str | None = None       # 산출물 파일명
    profile: str | None = None        # 사용된 파서 프로파일
    line: int | None = None


class RawFinding(BaseModel):
    """파서가 산출물에서 뽑아낸 원문 한 건. 아직 판정하지 않은 상태."""

    rule_id: str
    name: str | None = None
    severity_raw: str | None = None
    verdict_raw: str | None = None
    evidence_raw: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)
    source: SourceInfo = Field(default_factory=SourceInfo)


class CheckResult(BaseModel):
    """정규화·판정을 마친 항목 결과."""

    rule_id: str
    name: str
    status: Status
    reason: str                        # 왜 이 status 인가. 항상 존재한다.
    severity: Severity | None = None

    value: Any | None = None
    expected: Any | None = None
    evidence: str | None = None        # 마스킹 적용 후
    evidence_ref: str | None = None    # 대용량은 파일 참조

    verdict_source: Literal["script", "analyst"] = "script"
    analyst_note: str | None = None

    source: SourceInfo = Field(default_factory=SourceInfo)
    execution: ExecutionInfo = Field(default_factory=ExecutionInfo)
    warnings: list[str] = Field(default_factory=list)


class HostResult(BaseModel):
    host_id: str
    hostname: str
    address: str | None = None
    environment: RemoteEnvironment = Field(default_factory=RemoteEnvironment)
    results: list[CheckResult] = Field(default_factory=list)
    orphan_findings: list[RawFinding] = Field(default_factory=list)
    cleanup_ok: bool | None = None
    cleanup_leftovers: list[str] = Field(default_factory=list)
    error: str | None = None

    def summary(self) -> dict[Status, int]:
        out: dict[Status, int] = {s: 0 for s in Status}
        for r in self.results:
            out[r.status] += 1
        return out


class ScanResult(BaseModel):
    scan_id: str
    engine_version: str
    rule_pack_version: str | None = None
    profile: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    hosts: list[HostResult] = Field(default_factory=list)

    def summary(self) -> dict[Status, int]:
        out: dict[Status, int] = {s: 0 for s in Status}
        for h in self.hosts:
            for s, n in h.summary().items():
                out[s] += n
        return out
