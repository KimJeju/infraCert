"""배치 D — Rule Tester(가짜 연결로 실제 evaluate)·룰팩 diff(manifest 기반)·fixture 커버리지 기록."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

from infraguard.rulepack import diff as rp_diff
from infraguard.rulepack import loader
from infraguard.rules import tester
from infraguard.rules.declarative import RuleSpec

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "rulepacks" / "kisa-2026"


# ------------------------------------------------------------------ Rule Tester
def test_tester_distinguishes_verdicts_with_real_evaluator() -> None:
    pack = loader.load(PACK)
    spec: RuleSpec = pack.specs["U-16"]                # /etc/passwd 소유자·권한
    cmd_key = spec.collect[0].key
    good = tester.run(spec, {cmd_key: "-rw-r--r-- 1 root root 2000 Jan 1 12:00 /etc/passwd\n"}, platform="linux")
    bad = tester.run(spec, {cmd_key: "-rw-rw-rw- 1 nobody root 2000 Jan 1 12:00 /etc/passwd\n"}, platform="linux")
    assert good.verdict_raw == "GOOD" and bad.verdict_raw == "VULN"
    assert "matched" in good.detail and good.detail["extracted"]
    absent = tester.run(spec, {}, platform="linux")     # 출력 없음 → 룰이 선언한 missing 판정(추측 없음)
    assert absent.verdict_raw in ("NA", "MANUAL")
    # 명령 문자열을 키로 줘도 된다
    assert tester.run(spec, {spec.collect[0].cmd: "-rw-r--r-- 1 root root 1 Jan 1 12:00 /etc/passwd"},
                      platform="linux").verdict_raw == "GOOD"


def test_tester_uses_platform_variant() -> None:
    pack = loader.load(PACK)
    spec = pack.specs["N-01"]
    assert spec.variants, "N-01 에 Junos variant 가 있어야 한다"
    jun = spec.for_platform("junos")
    out = tester.run(spec, {c.key: "" for c in jun.collect}, platform="junos")
    assert out.verdict_raw in ("GOOD", "VULN", "MANUAL", "NA")


def test_tester_panel_runs_offscreen(qtbot) -> None:  # noqa: ANN001
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from infraguard.ui.pages.rule_tester import RuleTesterPanel
    pack = loader.load(PACK)
    panel = RuleTesterPanel()
    qtbot.addWidget(panel)
    spec = pack.specs["U-16"]
    panel.set_spec(spec)
    assert panel.run_btn.isEnabled() and set(panel._editors) == {c.key for c in spec.collect}
    panel._editors[spec.collect[0].key].setPlainText("-rw-rw-rw- 1 nobody root 1 Jan 1 12:00 /etc/passwd")
    assert panel.run() == "VULN" and "판정: VULN" in panel.result.text()
    panel.set_spec(None)
    assert not panel.run_btn.isEnabled()


# ------------------------------------------------------------------ 룰팩 diff
def test_rulepack_diff_reports_added_removed_logic_meta_profiles(tmp_path: Path) -> None:
    a = rp_diff.load_manifest(PACK)
    b = copy.deepcopy(a)
    # 추가 W-99 / 삭제 N-08 / U-31 로직 변경 / D-12 remediation 변경 / 프로파일 변경
    b["rules"].append({"id": "W-99", "name": "new", "severity": "중"})
    b["rules"] = [r for r in b["rules"] if r["id"] != "N-08"]
    for rf in b["rule_files"]:
        if rf["path"].endswith("U-31.yaml"):
            rf["sha256"] = "0" * 64
    for r in b["rules"]:
        if r["id"] == "D-12":
            r["remediation"] = "다르게"
    for p in b["profiles"]:
        if p["id"] == "linux-native":
            p["native"] = [x for x in p["native"] if x != "U-01"] + ["W-99"]
    b["version"] = "9.9.9"
    d = rp_diff.diff(a, b)
    assert d.added == ["W-99"] and d.removed == ["N-08"] and d.logic_changed == ["U-31"]
    assert d.meta_changed == {"D-12": ["remediation"]}
    assert d.profiles_changed["linux-native"] == (["W-99"], ["U-01"])
    txt = rp_diff.render(d)
    assert "+ W-99" in txt and "- N-08" in txt and "~ U-31" in txt and "D-12" in txt and "9.9.9" in txt
    assert rp_diff.diff(a, a).empty and "차이 없음" in rp_diff.render(rp_diff.diff(a, a))
    # zip 도 manifest 만 읽는다(풀지 않는다)
    z = tmp_path / "p.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("kisa-2026/manifest.yaml", yaml.safe_dump(b, allow_unicode=True))
        zf.writestr("kisa-2026/rules/../../evil.yaml", "x")
    d2 = rp_diff.diff(a, rp_diff.load_manifest(z))
    assert d2.added == ["W-99"] and not (tmp_path / "evil.yaml").exists()


# ------------------------------------------------------------------ 커버리지 기록
def test_coverage_hook_records_verdicts(tmp_path: Path) -> None:
    """conftest 가 IG_RULE_COVERAGE 로 evaluate 를 감싸 rule→verdict 횟수를 남긴다(서브프로세스 pytest 1개 파일)."""
    out = tmp_path / "cov.json"
    env = dict(os.environ, IG_RULE_COVERAGE=str(out), QT_QPA_PLATFORM="offscreen")
    rc = subprocess.call([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                          "tests/failure/test_provenance.py", "tests/failure/test_rulepack_and_native.py"],
                         cwd=ROOT, env=env)
    assert rc == 0 and out.exists()
    cov = json.loads(out.read_text(encoding="utf-8"))
    assert cov["T-01"]["GOOD"] >= 1 and cov["T-01"]["NA"] >= 1
    assert sum(cov.get("U-01", {}).values()) >= 1                    # 동봉 파이썬 룰(unix.py)도 잡는다
