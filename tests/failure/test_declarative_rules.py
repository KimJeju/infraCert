"""선언형(YAML) 룰 — 코드 실행 경로가 되지 않고, 추측하지 않는다.

- 평가기에 eval/exec 없음(정적).
- 화이트리스트 밖 연산자는 로드 단계에서 거부.
- 추출 실패는 missing 판정으로 드러남, 규칙 미해당은 MANUAL.
- 실제 룰팩 YAML(U-16/U-18/U-05, KISA 2026 번호)이 가짜 서버 출력으로 기대 판정을 낸다.
- manifest.rule_files 에 미등록/해시불일치 파일은 무결성 실패로 실행을 막는다.
"""
import ast
import hashlib
import pathlib

import pytest
import yaml

from infraguard.core.models import RemoteEnvironment
from infraguard.core.status import Status
from infraguard.orchestrator.native_runner import run_native
from infraguard.result.engine import normalize
from infraguard.rulepack import loader
from infraguard.rules import REGISTRY, declarative
from infraguard.rules.declarative import OPERATORS, RuleSpec, evaluate
from infraguard.transport.base import CleanupReport, Connection, ExecResult

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "infraguard"
PACK = pathlib.Path(__file__).resolve().parents[2] / "rulepacks" / "kisa-2026"


class _Conn(Connection):
    def __init__(self, outputs: dict[str, str], fail: set[str] = frozenset()):
        self.outputs, self.fail = outputs, fail

    def connect(self): ...
    def probe(self): return RemoteEnvironment(os="linux")
    def exec(self, argv, **kw):
        cmd = argv[-1]
        for k, v in self.outputs.items():
            if k in cmd:
                return ExecResult(argv, 0, v, "", 1)
        for k in self.fail:
            if k in cmd:
                return ExecResult(argv, 1, "", "denied", 1, error="denied")
        return ExecResult(argv, 0, "", "", 1)

    def upload(self, l, r): ...
    def download(self, r, l): ...
    def cleanup(self, p): return CleanupReport()
    def close(self): ...


ENV = RemoteEnvironment(os="linux")


def test_evaluator_has_no_eval_or_exec():
    tree = ast.parse((SRC / "rules" / "declarative.py").read_text(encoding="utf-8"))
    calls = {n.func.id for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not calls & {"eval", "exec", "compile", "__import__"}, calls


def test_unknown_operator_rejected_at_load():
    with pytest.raises(ValueError, match="허용되지 않은 연산자"):
        RuleSpec.model_validate({
            "id": "T-01", "name": "t",
            "verdict": [{"when": {"x": {"python": "1==1"}}, "then": "GOOD"}],
        })


def test_bad_regex_and_bad_id_rejected():
    with pytest.raises(ValueError):
        RuleSpec.model_validate({"id": "T-01", "name": "t", "extract": [{"from": "a", "regex": "("}]})
    with pytest.raises(ValueError):
        RuleSpec.model_validate({"id": "lowercase", "name": "t"})


@pytest.mark.parametrize("op,var,val,expect", [
    ("eq", "root", "root", True), ("eq", None, "root", False),
    ("ne", "bin", "root", True), ("ne", None, "root", True),
    ("in", "b", ["a", "b"], True), ("contains", "abc", "b", True),
    ("regex", "PermitRootLogin no", r"no$", True),
    ("exists", "x", True, True), ("exists", "", True, False), ("absent", None, True, True),
    ("ge", "8", 8, True), ("lt", "5", 8, True), ("ge", "abc", 8, False),
    ("mode_le", "-rw-r--r--", "644", True), ("mode_le", "-rw-rw-r--", "644", False),
    ("mode_le", "-rw-r-----", "640", True), ("mode_le", "garbage", "644", False),
])
def test_operators(op, var, val, expect):
    assert OPERATORS[op](var, val) is expect


def _spec(**kw) -> RuleSpec:
    base = {"id": "T-01", "name": "t", "platforms": ["linux"]}
    base.update(kw)
    return RuleSpec.model_validate(base)


def test_missing_extract_surfaces_declared_verdict_not_guess():
    spec = _spec(collect=[{"key": "ls", "cmd": "ls -ld /nope"}],
                 extract=[{"from": "ls", "regex": r"^(?P<perm>\S{10})", "missing": "NA"}],
                 verdict=[{"else": "GOOD"}])
    out = evaluate(spec, _Conn({}), ENV)
    assert out.verdict_raw == "NA"


def test_no_matching_step_is_manual_not_pass():
    spec = _spec(collect=[{"key": "a", "cmd": "echo x"}],
                 verdict=[{"when": {"a": {"eq": "never"}}, "then": "GOOD"}])
    out = evaluate(spec, _Conn({"echo x": "x\n"}), ENV)
    assert out.verdict_raw == "MANUAL" and "미해당" in out.evidence


def _load_rule(rid: str) -> RuleSpec:
    return declarative.load_file(PACK / "rules" / f"{rid}.yaml")


def test_u16_yaml_matches_python_behaviour():
    good = evaluate(_load_rule("U-16"), _Conn({"/etc/passwd": "-rw-r--r-- 1 root root 1515 Sep 9 /etc/passwd\n"}), ENV)
    bad = evaluate(_load_rule("U-16"), _Conn({"/etc/passwd": "-rw-rw-r-- 1 root root 1515 Sep 9 /etc/passwd\n"}), ENV)
    other = evaluate(_load_rule("U-16"), _Conn({"/etc/passwd": "-rw-r--r-- 1 bin root 1515 Sep 9 /etc/passwd\n"}), ENV)
    none = evaluate(_load_rule("U-16"), _Conn({}), ENV)
    assert (good.verdict_raw, bad.verdict_raw, other.verdict_raw, none.verdict_raw) == ("GOOD", "VULN", "VULN", "NA")
    assert "기준" in good.evidence


def test_u18_yaml_debian_shadow_group_exception():
    deb = evaluate(_load_rule("U-18"), _Conn({"/etc/shadow": "-rw-r----- 1 root shadow 921 Sep 9 /etc/shadow\n"}), ENV)
    strict = evaluate(_load_rule("U-18"), _Conn({"/etc/shadow": "-r-------- 1 root root 921 Sep 9 /etc/shadow\n"}), ENV)
    loose = evaluate(_load_rule("U-18"), _Conn({"/etc/shadow": "-rw-r----- 1 root root 921 Sep 9 /etc/shadow\n"}), ENV)
    assert (deb.verdict_raw, strict.verdict_raw, loose.verdict_raw) == ("GOOD", "GOOD", "VULN")


def test_u05_yaml_through_runner_and_decide():
    loader.load(PACK)   # YAML 룰을 REGISTRY 에 등록
    conn = _Conn({"$1 != \"root\"": "backdoor\n", "$3 == 0 {print $1}": "root\nbackdoor\n"})
    findings, errors = run_native(conn, ENV, ["U-05"])
    assert not errors
    res, _ = normalize(findings)
    assert res[0].status is Status.FAIL and "backdoor" in res[0].evidence
    conn_ok = _Conn({"$1 != \"root\"": "", "$3 == 0 {print $1}": "root\n"})
    findings, _ = run_native(conn_ok, ENV, ["U-05"])
    assert normalize(findings)[0][0].status is Status.PASS


def test_real_pack_declarative_rules_registered_with_kind():
    pk = loader.load(PACK)
    assert pk.runnable, pk.problems
    kinds = {rid: pk.rules[rid].kind for rid in pk.native}
    assert kinds["U-16"] == "yaml" and kinds["U-01"] == "python"
    assert all(rid in REGISTRY for rid in pk.native)


def _pack_with_rule(tmp_path, register: bool, tamper: bool = False):
    d = tmp_path / "pk"
    (d / "rules").mkdir(parents=True)
    rule = d / "rules" / "T-01.yaml"
    rule.write_text(yaml.safe_dump({"id": "T-01", "name": "t", "verdict": [{"else": "MANUAL"}]}),
                    encoding="utf-8")
    sha = hashlib.sha256(rule.read_bytes()).hexdigest()
    man = {"name": "t", "version": "1", "native": ["T-01"]}
    if register:
        man["rule_files"] = [{"path": "rules/T-01.yaml", "sha256": "0" * 64 if tamper else sha}]
    (d / "manifest.yaml").write_text(yaml.safe_dump(man), encoding="utf-8")
    return d


def test_unregistered_rule_file_blocks_execution(tmp_path):
    pk = loader.load(_pack_with_rule(tmp_path, register=False))
    assert not pk.integrity_ok and any("미등록" in p for p in pk.problems)
    REGISTRY.pop("T-01", None)


def test_tampered_rule_file_blocks_execution(tmp_path):
    pk = loader.load(_pack_with_rule(tmp_path, register=True, tamper=True))
    assert not pk.integrity_ok and any("SHA-256" in p for p in pk.problems)
    REGISTRY.pop("T-01", None)
