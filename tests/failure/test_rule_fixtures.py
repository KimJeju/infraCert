"""룰 fixture — tests/fixtures/rules/*.yaml 의 (룰, 케이스) 마다 실전 평가기로 판정을 확인한다.

케이스 이름: <판정>[_<n>][@<platform>]. 값은 {collect.key 또는 명령 부분문자열: stdout}, `_rc` 는 exit code.
"룰이 존재한다" 가 아니라 "룰이 판정을 구분한다" 를 자동으로 잡는 그물이다.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from infraguard.rulepack import loader
from infraguard.rules import tester

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests" / "fixtures" / "rules"
_PACK = None


def _pack():
    global _PACK
    if _PACK is None:
        _PACK = loader.load(ROOT / "rulepacks" / "kisa-2026")
    return _PACK


def _cases() -> list[tuple[str, str, dict]]:
    out = []
    for f in sorted(FIX.glob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for rid, cases in data.items():
            for name, outputs in (cases or {}).items():
                out.append((rid, name, outputs or {}))
    return out


CASES = _cases()


def parse_case(name: str) -> tuple[str, str | None]:
    """'VULN_2@junos' → ('VULN', 'junos')."""
    base, _, plat = name.partition("@")
    return base.split("_")[0], plat or None


@pytest.mark.parametrize(("rid", "case", "outputs"), CASES, ids=[f"{r}:{c}" for r, c, _ in CASES])
def test_rule_fixture(rid: str, case: str, outputs: dict) -> None:
    expected, platform = parse_case(case)
    outputs = dict(outputs)
    rc = outputs.pop("_rc", {}) or {}
    pack = _pack()
    spec = pack.specs.get(rid)
    assert spec is not None or rid in pack.native, f"{rid}: 룰팩에 없는 룰"
    out = tester.run_rule(rid, outputs, spec=spec, platform=platform, exit_codes=rc)
    assert out.verdict_raw == expected, f"{rid} {case}: {out.verdict_raw} (근거: {out.evidence[:160]!r})"


def test_every_native_rule_has_a_fixture() -> None:
    covered = {r for r, _, _ in CASES}
    missing = sorted(set(_pack().native) - covered)
    # 아직 fixture 파일에 없는 룰은 여기서 드러난다(기존 canned 테스트가 따로 덮는 룰 포함)
    assert len(missing) < 120, missing
