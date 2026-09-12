"""Rule Tester — 원격 없이 "이 출력이면 어떤 판정이 나오는가" 를 돌려본다.

룰 개발자가 샘플 출력을 바꿔 가며 GOOD/VULN/NA/MANUAL 이 실제로 갈리는지 확인한다.
평가기는 실제 evaluate 그대로(가짜 연결만 끼운다) — 테스터와 실전이 다른 코드를 타지 않는다.
파이썬 룰은 명령 문자열 부분일치(substring) 키로 출력을 준다(명령이 길고 룰 안에 박혀 있어서).
"""

from __future__ import annotations

from infraguard.core.models import RemoteEnvironment
from infraguard.rules import REGISTRY, NativeOutcome, load_all
from infraguard.rules.declarative import RuleSpec, evaluate
from infraguard.transport.base import CleanupReport, Connection, ExecResult


class CannedConnection(Connection):
    """cmd → (stdout, exit_code). 정확히 일치하는 키 우선, 없으면 부분일치(긴 키부터). 둘 다 없으면 exit 1·빈 출력."""

    def __init__(self, outputs: dict[str, str], exit_codes: dict[str, int] | None = None) -> None:
        self.outputs = outputs
        self.exit_codes = exit_codes or {}
        self.calls: list[str] = []

    def _key(self, cmd: str) -> str | None:
        if cmd in self.outputs:
            return cmd
        for k in sorted(self.outputs, key=len, reverse=True):
            if k and k in cmd:
                return k
        return None

    def connect(self) -> None: ...
    def probe(self) -> RemoteEnvironment: return RemoteEnvironment()
    def exec(self, argv, **kw):  # noqa: ANN001,ANN201
        cmd = argv[-1]
        self.calls.append(cmd)
        k = self._key(cmd)
        if k is not None:
            return ExecResult(list(argv), self.exit_codes.get(k, 0), self.outputs[k], "", 1)
        return ExecResult(list(argv), 1, "", "", 1)
    def upload(self, local, remote) -> None: ...  # noqa: ANN001
    def download(self, remote, local) -> None: ...  # noqa: ANN001
    def cleanup(self, paths) -> CleanupReport: return CleanupReport()  # noqa: ANN001
    def close(self) -> None: ...


def run(spec: RuleSpec, outputs: dict[str, str], *, platform: str | None = None,
        exit_codes: dict[str, int] | None = None, params: dict[str, str] | None = None) -> NativeOutcome:
    """outputs 의 키는 collect.key 또는 명령 문자열 둘 다 받는다."""
    blk = spec.for_platform(platform)
    by_cmd: dict[str, str] = {}
    codes: dict[str, int] = {}
    for c in blk.collect:
        if c.key in outputs:
            by_cmd[c.cmd] = outputs[c.key]
        elif c.cmd in outputs:
            by_cmd[c.cmd] = outputs[c.cmd]
        if exit_codes and c.key in exit_codes:
            codes[c.cmd] = exit_codes[c.key]
    env = RemoteEnvironment(os=platform or (spec.platforms[0] if spec.platforms else None), params=params or {})
    return evaluate(spec, CannedConnection(by_cmd, codes), env)


def run_rule(rule_id: str, outputs: dict[str, str], *, spec: RuleSpec | None = None, platform: str | None = None,
             exit_codes: dict[str, int] | None = None) -> NativeOutcome:
    """선언형이면 run(), 파이썬 룰이면 레지스트리 check 를 부분일치 연결로 실행."""
    if spec is not None:
        return run(spec, outputs, platform=platform, exit_codes=exit_codes)
    rule = load_all().get(rule_id) or REGISTRY[rule_id]
    env = RemoteEnvironment(os=platform or rule.platforms[0])
    return rule.check(CannedConnection(outputs, exit_codes), env)
