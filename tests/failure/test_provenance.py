"""판정 추적(provenance) + 실행 엔진 명령 정책 + 룰팩 SHA 기록.

"왜 취약인가" 에 판정 → 명령(종료코드·출력해시) → 추출값 → 매치 절 → 룰팩 정체 로 답할 수 있어야 한다.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from infraguard.core.models import RemoteEnvironment, ScanResult
from infraguard.core.status import Status
from infraguard.orchestrator.native_runner import run_native
from infraguard.orchestrator.results_store import ResultsStore
from infraguard.result.engine import normalize, provenance_text
from infraguard.rulepack import loader
from infraguard.rules import REGISTRY, NativeOutcome, NativeRule, declarative
from infraguard.rules.declarative import RuleSpec
from infraguard.transport.base import CleanupReport, Connection, ExecResult

PACK = Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"


class FakeConnection(Connection):
    def __init__(self, outputs: dict[str, str]):
        self.outputs = outputs
        self.seen: list[list[str]] = []

    def connect(self): ...
    def probe(self): return RemoteEnvironment(os="linux")
    def exec(self, argv, **kw):
        self.seen.append(argv)
        cmd = argv[-1]
        for k, v in self.outputs.items():
            if k in cmd:
                return ExecResult(argv, 0, v, "", 7)
        return ExecResult(argv, 1, "", "", 1)
    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


SPEC = RuleSpec.model_validate({
    "id": "T-01", "name": "테스트", "platforms": ["linux"],
    "collect": [{"key": "ls", "cmd": "ls -ld /etc/passwd 2>/dev/null"}],
    "extract": [{"from": "ls", "regex": r"^(?P<perm>\S{10})\s+\S+\s+(?P<owner>\S+)", "missing": "NA"}],
    "verdict": [{"when": {"owner": {"ne": "root"}}, "then": "VULN"},
                {"when": {"perm": {"mode_le": "644"}}, "then": "GOOD"}, {"else": "VULN"}],
    "evidence": ["ls"],
})


def _register(spec: RuleSpec) -> None:
    REGISTRY[spec.id] = declarative.to_native(spec)


def test_yaml_rule_provenance_traces_command_extract_and_clause() -> None:
    _register(SPEC)
    out = "-rw-r--r-- 1 root root 2000 Jan 1 /etc/passwd\n"
    conn = FakeConnection({"ls -ld": out})
    findings, errors = run_native(conn, RemoteEnvironment(os="linux"), ["T-01"])
    assert not errors
    p = findings[0].provenance
    assert p["transport"] == "fake" and p["impl"] == "yaml"
    (c,) = p["commands"]
    assert c["argv"] == ["sh", "-c", "ls -ld /etc/passwd 2>/dev/null"]
    assert c["exit_code"] == 0 and c["duration_ms"] == 7
    assert c["stdout_sha256"] == hashlib.sha256(out.encode()).hexdigest()
    assert p["extracted"]["owner"] == "root" and p["extracted"]["perm"] == "-rw-r--r--"
    assert p["matched"].startswith("#2 when") and p["matched"].endswith("→ GOOD")
    # CheckResult 까지 그대로 전달되고, 사람이 읽는 텍스트로 풀린다
    results, _ = normalize(findings, bundle_id="native")
    txt = provenance_text(results[0])
    assert "$ ls -ld /etc/passwd" in txt and "owner='root'" in txt and "판정식: #2" in txt


def test_missing_extract_is_traced() -> None:
    _register(SPEC)
    findings, _ = run_native(FakeConnection({"ls -ld": "garbage"}), RemoteEnvironment(os="linux"), ["T-01"])
    assert findings[0].verdict_raw == "NA"
    assert "미매치" in findings[0].provenance["matched"]


def test_engine_refuses_write_command_even_from_python_rule() -> None:
    """로더를 거치지 않는 파이썬 룰이 변경 명령을 내면 실행 엔진이 막고 ERROR 로 남긴다."""
    def evil(conn, env):
        conn.exec(["sh", "-c", "rm -rf /tmp/x"], timeout=5)
        return NativeOutcome("GOOD", "did it")
    REGISTRY["T-99"] = NativeRule("T-99", "evil", "상", ("linux",), evil)
    conn = FakeConnection({})
    findings, errors = run_native(conn, RemoteEnvironment(os="linux"), ["T-99"])
    assert not findings and conn.seen == []          # 대상에 명령이 나가지 않았다
    assert errors[0].status is Status.ERROR and "정책 위반" in errors[0].reason


def test_loader_blocks_pack_with_write_rule(tmp_path: Path) -> None:
    d = tmp_path / "bad"
    (d / "rules").mkdir(parents=True)
    rule = (d / "rules" / "X-01.yaml")
    rule.write_text(
        "id: X-01\nname: nope\nplatforms: [linux]\n"
        "collect:\n  - key: a\n    cmd: \"sed -i 's/a/b/' /etc/hosts\"\n"
        "verdict:\n  - else: GOOD\n", encoding="utf-8")
    (d / "manifest.yaml").write_text(
        "name: bad\nversion: '1'\nrule_files:\n"
        f"  - path: rules/X-01.yaml\n    sha256: {loader.file_sha256(rule)}\n"
        "native: [X-01]\n", encoding="utf-8")
    pack = loader.load(d)
    assert not pack.runnable
    assert any("X-01" in p and "sed" in p for p in pack.problems), pack.problems


def test_bundled_pack_has_sha_and_meta_and_passes_policy() -> None:
    pack = loader.load(PACK)
    assert pack.runnable, pack.problems[:5]
    assert len(pack.sha256) == 64 and pack.sha256 == loader.file_sha256(PACK / "manifest.yaml")
    assert pack.meta.get("guide_version") == "2026"


def test_results_store_keeps_rulepack_sha(tmp_path: Path) -> None:
    st = ResultsStore(tmp_path / "r.db")
    st.start_scan(ScanResult(scan_id="s1", engine_version="0", rule_pack_version="kisa-2026 1",
                             rule_pack_sha256="ab" * 32, started_at=datetime.now()))
    assert st.load_scan("s1").rule_pack_sha256 == "ab" * 32
    st.close()
