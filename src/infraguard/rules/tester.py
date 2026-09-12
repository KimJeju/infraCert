"""Rule Tester — 원격 없이 "이 출력이면 어떤 판정이 나오는가" 를 돌려본다.

룰 개발자가 샘플 출력을 바꿔 가며 GOOD/VULN/NA/MANUAL 이 실제로 갈리는지 확인한다.
평가기는 실제 evaluate 그대로(가짜 연결만 끼운다) — 테스터와 실전이 다른 코드를 타지 않는다.
"""

from __future__ import annotations

from infraguard.core.models import RemoteEnvironment
from infraguard.rules import NativeOutcome
from infraguard.rules.declarative import RuleSpec, evaluate
from infraguard.transport.base import CleanupReport, Connection, ExecResult


class CannedConnection(Connection):
    """collect cmd → (stdout, exit_code). 없는 명령은 exit 1·빈 출력(명령 없음/실패 흉내)."""

    def __init__(self, outputs: dict[str, str], exit_codes: dict[str, int] | None = None) -> None:
        self.outputs = outputs
        self.exit_codes = exit_codes or {}
        self.calls: list[str] = []

    def connect(self) -> None: ...
    def probe(self) -> RemoteEnvironment: return RemoteEnvironment()
    def exec(self, argv, **kw):  # noqa: ANN001,ANN201
        cmd = argv[-1]
        self.calls.append(cmd)
        if cmd in self.outputs:
            return ExecResult(list(argv), self.exit_codes.get(cmd, 0), self.outputs[cmd], "", 1)
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
