"""부분 룰팩 빌드 → zip 가져오기 → 로드 왕복, zip 경로탈출 거부, 가이드 조인·리포트 조치방법 컬럼."""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from openpyxl import load_workbook

from infraguard.core.models import CheckResult, HostResult, ScanResult
from infraguard.core.status import Status
from infraguard.reporting import html as html_report
from infraguard.reporting import xlsx as xlsx_report
from infraguard.rulepack import importer, loader

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "rulepacks" / "kisa-2026"


def _script(name: str) -> str:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_zip_traversal_rejected(tmp_path: Path) -> None:
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("manifest.yaml", "name: evil\n")
        zf.writestr("../../escape.txt", "x")
    with pytest.raises(importer.ImportError_):
        importer.import_zip(z, tmp_path / "packs")
    assert not (tmp_path / "packs" / "evil").exists()      # 하나라도 위험하면 아무것도 풀지 않는다
    assert not (tmp_path / "escape.txt").exists()


def test_zip_without_manifest_rejected(tmp_path: Path) -> None:
    z = tmp_path / "nomf.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a/b/manifest.yaml", "name: deep\n")
    with pytest.raises(importer.ImportError_):
        importer.pack_name(z)


def test_build_subset_import_roundtrip(tmp_path: Path) -> None:
    build = _script("build_rulepack")
    guide = tmp_path / "all.json"
    guide.write_text(
        '[{"id":"U-16","remediation":"가이드 조치 U-16","judgment":{"good":"g","vuln":"v"},"procedures":[]},'
        '{"id":"U-99","remediation":"관계없는 항목"}]', encoding="utf-8")
    out = tmp_path / "acme.zip"
    st = build.build(PACK, "acme test", out, profiles=[], rules=["U-16", "U-01"], bundles=["aix-unix"],
                     guide_json=guide, version="0.1")
    assert st["guide"] == 1 and st["native"] == 2

    dest, pack = importer.import_zip(out, tmp_path / "packs")
    assert dest.name == "acme-test"
    assert pack.runnable, pack.problems                   # sha 재계산·읽기전용 검사 통과
    assert set(pack.native) == {"U-16", "U-01"}
    assert "aix-unix" in pack.bundles
    assert (dest / "rules" / "U-16.yaml").exists() and not (dest / "rules" / "U-05.yaml").exists()
    assert set(pack.guide) == {"U-16"}                    # 선택 항목만 담긴다
    # 번들 provides 항목 메타도 따라온다 (aix 번들이 U-01~67 을 낸다)
    assert "U-30" in pack.rules
    assert pack.remediation_map()["U-16"] == "가이드 조치 U-16"   # 가이드가 manifest 메타보다 우선

    with pytest.raises(importer.ImportError_):
        importer.import_zip(out, tmp_path / "packs")       # 같은 이름은 replace 없이 거부
    dest2, _ = importer.import_zip(out, tmp_path / "packs", replace=True)
    assert dest2 == dest


def test_shipped_pack_has_remediation_meta() -> None:
    pack = loader.load(PACK)
    assert pack.runnable, pack.problems
    rem = pack.remediation_map()
    assert rem["U-16"] and rem["D-01"] and rem["WEB-01"]   # enrich_rules.py 가 채운 manifest 메타
    spec = yaml.safe_load((PACK / "rules" / "U-16.yaml").read_text(encoding="utf-8"))
    assert spec["remediation"] == rem["U-16"]


def _scan() -> ScanResult:
    return ScanResult(
        scan_id="s1", engine_version="t", started_at=datetime.now(UTC),
        hosts=[HostResult(host_id="h1", hostname="srv", results=[
            CheckResult(rule_id="U-16", name="passwd", status=Status.FAIL, reason="bad", verdict_source="script"),
            CheckResult(rule_id="U-01", name="root", status=Status.PASS, reason="ok", verdict_source="script"),
        ])],
    )


def test_reports_carry_remediation_only_for_fail_or_unknown(tmp_path: Path) -> None:
    rem = {"U-16": "권한 644", "U-01": "PermitRootLogin no"}
    x = xlsx_report.build(_scan(), tmp_path / "r.xlsx", rem)
    ws = load_workbook(x)["결과"]
    rows = {r[1]: r for r in ws.iter_rows(min_row=2, values_only=True)}
    assert ws.cell(row=1, column=10).value == "조치방법"
    assert rows["U-16"][9] == "권한 644"
    assert rows["U-01"][9] in ("", None)                   # 양호 항목엔 조치를 붙이지 않는다(빈 셀은 None 으로 읽힘)
    h = html_report.build(_scan(), tmp_path / "r.html", rem).read_text(encoding="utf-8")
    assert "권한 644" in h and "PermitRootLogin no" not in h
