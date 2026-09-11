"""가이드 추출기 회귀 — 라벨 오탐·플랫폼 불릿·변형 분리가 깨지면 실패한다."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "extract_guide", Path(__file__).resolve().parents[2] / "scripts" / "extract_guide.py"
)
eg = importlib.util.module_from_spec(_SPEC)
sys.modules["extract_guide"] = eg
_SPEC.loader.exec_module(eg)

ITEM = (
    "점검 내용비밀번호 정책 여부 점검점검 목적정책을 참고하여 강화하기 위함보안 위협위험 존재참고※용어"
    "점검 대상 및 판단 기준대상대상 시스템 전체판단 기준양호 : 설정된 경우취약 : 아닌 경우"
    "조치 방법파일 수정조치 시 영향없음점검 및 조치 사례lSOLARIS(5.9 이하 버전)[Telnet]Step 1)a[SSH]Step 1)b"
    "lLINUX[Redhat]Step 1)c Step 2)d[Debian]Step 1)elWindows NT(IIS 4.0), 2000Step 1)f"
)


def test_labels_not_confused_by_prose() -> None:
    f = eg.split_fields(ITEM)
    assert f["purpose"] == "정책을 참고하여 강화하기 위함"   # '참고하여' 는 라벨 아님
    assert f["targets"] == "대상 시스템 전체"                 # 본문 첫 단어 '대상' 살아남음
    assert f["good"] == "설정된 경우" and f["vuln"] == "아닌 경우"
    assert f["remediation"] == "파일 수정" and f["impact"] == "없음"


def test_platform_bullets_and_variants() -> None:
    procs = eg.split_procedures(eg.split_fields(ITEM)["procedures"])
    by = {p["platform"]: p for p in procs}
    assert by["SOLARIS(5.9 이하 버전)"]["slugs"] == ["solaris"]
    assert set(by["SOLARIS(5.9 이하 버전)"]["variants"]) == {"Telnet", "SSH"}
    assert by["LINUX"]["variants"]["Redhat"]["steps"] == ["Step 1) c", "Step 2) d"]
    assert by["LINUX"]["variants"]["Debian"]["steps"] == ["Step 1) e"]
    assert by["Windows NT(IIS 4.0), 2000"]["slugs"] == ["windows"]


def test_webapp_dash_remediation_stays_in_procedure() -> None:
    text = "조치 방법입력값 검증점검 및 조치 사례lLDAP 인젝션- 점검 방법Step 1)x- 조치 방법1.필터링"
    f = eg.split_fields(text)
    assert f["remediation"] == "입력값 검증"
    assert "- 조치 방법1.필터링" in f["procedures"]
    procs = eg.split_procedures(f["procedures"])
    assert procs[0]["platform"] == "LDAP 인젝션" and procs[0]["slugs"] == ["common"]
