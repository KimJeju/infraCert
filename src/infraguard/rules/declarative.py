"""선언형(YAML) 네이티브 룰 — 명령 수집 → 정규식 추출 → 화이트리스트 연산자 판정.

원칙:
  - **eval/exec 금지.** 조건은 {변수: {연산자: 값}} 구조만 허용하고 연산자는 OPERATORS 에 있는 것만.
    룰팩(데이터 디렉터리)이 코드 실행 경로가 되면 안 된다. 정적 테스트가 강제한다.
  - 명령은 상수 문자열. 변수 치환 없음(인젝션 원천 차단). 읽기전용 명령만 쓴다(룰 작성 규칙).
  - 판정은 원문 어휘(GOOD/VULN/MANUAL/NA)만 낸다. Status 확정은 core.decision.decide().
  - 추측하지 않는다: 추출 실패는 `missing` 로 명시한 판정(기본 MANUAL)으로 드러낸다.

룰 파일 예시는 rulepacks/kisa-2026/rules/U-09.yaml, 스키마는 아래 pydantic 모델이 정본.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from infraguard.core.models import RemoteEnvironment
from infraguard.rules import REGISTRY, NativeOutcome, NativeRule
from infraguard.transport.base import Connection

Verdict = Literal["GOOD", "VULN", "MANUAL", "NA"]


# ------------------------------------------------------------------ 스키마
class Collect(BaseModel):
    key: str
    cmd: str
    timeout: int = 60

    @field_validator("key")
    @classmethod
    def _ident(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v):
            raise ValueError(f"collect.key 는 식별자여야 함: {v!r}")
        return v


class Extract(BaseModel):
    from_: str = Field(alias="from")
    regex: str | None = None            # 이름 있는 그룹(?P<name>) → 변수
    lines: str | None = None            # 비어있지 않은 줄 수 → 이 이름의 변수
    missing: Verdict | None = None      # 정규식 미매치 시 즉시 판정 (None 이면 변수만 None)

    model_config = {"populate_by_name": True}

    @field_validator("regex")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as e:            # pydantic 은 ValueError 만 검증오류로 감싼다
                raise ValueError(f"정규식 오류: {e}") from e
        return v


class Step(BaseModel):
    when: dict[str, dict[str, Any]] | None = None   # {var: {op: value}} — 전부 AND
    then: Verdict | None = None
    else_: Verdict | None = Field(default=None, alias="else")

    model_config = {"populate_by_name": True}

    @field_validator("when")
    @classmethod
    def _ops_whitelisted(cls, v: dict | None) -> dict | None:
        for var, conds in (v or {}).items():
            if not isinstance(conds, dict) or not conds:
                raise ValueError(f"when.{var} 는 {{연산자: 값}} 이어야 함")
            for op in conds:
                if op not in OPERATORS:
                    raise ValueError(f"허용되지 않은 연산자 {op!r} (허용: {sorted(OPERATORS)})")
        return v


class RuleSpec(BaseModel):
    id: str
    name: str
    severity: str = ""
    category: str = ""
    platforms: list[str] = Field(default_factory=lambda: ["linux"])
    manual: bool = False
    collect: list[Collect] = Field(default_factory=list)
    extract: list[Extract] = Field(default_factory=list)
    verdict: list[Step] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)   # 근거로 남길 collect 키
    note: str = ""                                       # 근거에 덧붙일 기준 설명
    remediation: str = ""
    shell: Literal["sh", "powershell", "raw"] = "sh"     # sh: POSIX, powershell: WinRM/로컬, raw: 장비 CLI 한 줄

    @field_validator("id")
    @classmethod
    def _rule_id(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Z]+-\d+", v):
            raise ValueError(f"룰 id 형식 오류: {v!r}")
        return v


# ------------------------------------------------------------------ 연산자
def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _mode_bits(perm: str) -> int | None:
    """'-rw-r-----' → 0o640. 형식이 아니면 None."""
    if not isinstance(perm, str) or len(perm) < 10:
        return None
    bits = 0
    for i, ch in enumerate(perm[1:10]):
        if ch != "-":
            bits |= 1 << (8 - i)
    return bits


def _op_eq(v: Any, x: Any) -> bool: return v is not None and str(v) == str(x)
def _op_ne(v: Any, x: Any) -> bool: return v is None or str(v) != str(x)
def _op_in(v: Any, x: Any) -> bool: return v is not None and str(v) in [str(i) for i in (x or [])]
def _op_contains(v: Any, x: Any) -> bool: return v is not None and str(x) in str(v)
def _op_regex(v: Any, x: Any) -> bool: return v is not None and re.search(str(x), str(v)) is not None
def _op_exists(v: Any, x: Any) -> bool: return (v is not None and str(v).strip() != "") == bool(x)
def _op_absent(v: Any, x: Any) -> bool: return (v is None or str(v).strip() == "") == bool(x)


def _cmp(fn):  # noqa: ANN001,ANN202
    def op(v: Any, x: Any) -> bool:
        a, b = _num(v), _num(x)
        return a is not None and b is not None and fn(a, b)
    return op


def _op_mode_le(v: Any, x: Any) -> bool:
    """권한 문자열이 8진 상한 이하인가(초과 비트 없음)."""
    bits = _mode_bits(v)
    try:
        limit = int(str(x), 8)
    except ValueError:
        return False
    return bits is not None and (bits & ~limit) == 0


OPERATORS: dict[str, Any] = {
    "eq": _op_eq, "ne": _op_ne, "in": _op_in, "contains": _op_contains, "regex": _op_regex,
    "exists": _op_exists, "absent": _op_absent,
    "ge": _cmp(lambda a, b: a >= b), "le": _cmp(lambda a, b: a <= b),
    "gt": _cmp(lambda a, b: a > b), "lt": _cmp(lambda a, b: a < b),
    "mode_le": _op_mode_le,
}


# ------------------------------------------------------------------ 평가기
SHELLS: dict[str, Any] = {
    "sh": lambda c: ["sh", "-c", c],
    "powershell": lambda c: ["powershell", "-NoProfile", "-NonInteractive", "-Command", c],
    "raw": lambda c: [c],
}


def build_argv(spec: RuleSpec, cmd: str, params: dict[str, str]) -> list[str]:
    """수집 명령 argv. sh 룰은 호스트 파라미터를 `env K=V` 로 앞에 붙인다(값은 validate_env 통과분만)."""
    argv = SHELLS[spec.shell](cmd)
    if spec.shell == "sh" and params:
        from infraguard.orchestrator.remote_runner import (
            validate_env,  # noqa: PLC0415 - 계층 역참조 최소화
        )
        validate_env(params)
        argv = ["env", *[f"{k}={v}" for k, v in params.items()], *argv]
    return argv


def evaluate(spec: RuleSpec, conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
    vars_: dict[str, Any] = {}
    raw: dict[str, str] = {}

    for c in spec.collect:
        r = conn.exec(build_argv(spec, c.cmd, env.params), timeout=c.timeout)
        if r.error or r.timed_out:
            # 전송 계층 실패는 판정(MANUAL)로 위장하지 않는다 — 예외로 올려 native_runner 가 ERROR 로 기록
            raise RuntimeError(f"collect {c.key!r} 실행 실패: {r.error or f'timeout {c.timeout}s'}")
        out = (r.stdout or "").replace("\r\n", "\n").replace("\r", "\n")   # PowerShell/장비 CRLF → 값 끝 \r 제거
        raw[c.key] = out
        vars_[c.key] = out.strip()
        vars_[c.key + "_ok"] = bool(r.ok and not r.error)

    def evidence() -> str:
        parts = [raw.get(k, "").strip() for k in spec.evidence if raw.get(k, "").strip()]
        if spec.note:
            parts.append(spec.note)
        return "\n".join(parts) or "(수집값 없음)"

    for e in spec.extract:
        src = raw.get(e.from_, "")
        if e.lines:
            vars_[e.lines] = sum(1 for ln in src.splitlines() if ln.strip())
        if e.regex:
            m = re.search(e.regex, src, re.M)
            if m:
                vars_.update({k: v for k, v in m.groupdict().items() if v is not None})
            elif e.missing:
                return NativeOutcome(e.missing, evidence())
            else:
                for name in re.compile(e.regex).groupindex:
                    vars_.setdefault(name, None)

    for step in spec.verdict:
        if step.when is None:
            if step.else_:
                return NativeOutcome(step.else_, evidence())
            continue
        if all(OPERATORS[op](vars_.get(var), val)
               for var, conds in step.when.items() for op, val in conds.items()):
            return NativeOutcome(step.then or "MANUAL", evidence())
    # 어느 단계에도 안 걸리면 추측하지 않는다
    return NativeOutcome("MANUAL", evidence() + "\n※ 판정 규칙 미해당 — 확인 필요")


def load_file(path: Path) -> RuleSpec:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return RuleSpec.model_validate(data)


def to_native(spec: RuleSpec) -> NativeRule:
    def check(conn: Connection, env: RemoteEnvironment) -> NativeOutcome:
        return evaluate(spec, conn, env)
    return NativeRule(spec.id, spec.name, spec.severity, tuple(spec.platforms), check,
                      collects=tuple((spec.shell, c.cmd) for c in spec.collect))


def register_dir(directory: Path) -> tuple[dict[str, RuleSpec], list[str]]:
    """디렉터리의 *.yaml 을 전부 로드해 REGISTRY 에 등록. (specs, problems)."""
    specs: dict[str, RuleSpec] = {}
    problems: list[str] = []
    for f in sorted(directory.glob("*.yaml")):
        try:
            spec = load_file(f)
        except Exception as e:  # noqa: BLE001 - 파일 하나가 전체 로드를 막지 않게, 문제는 드러낸다
            problems.append(f"rule {f.name}: {e}")
            continue
        if spec.id in specs:
            problems.append(f"rule {f.name}: id {spec.id} 중복")
            continue
        specs[spec.id] = spec
        REGISTRY[spec.id] = to_native(spec)
    return specs, problems
