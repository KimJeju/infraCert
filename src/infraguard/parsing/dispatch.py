"""산출물 파일 → 파서 선택. 확장자와 내용으로 판별하고, 못 알아보면 실패로 드러낸다."""

from __future__ import annotations

from pathlib import Path

from infraguard.parsing import legacy_csv, report_txt
from infraguard.parsing.base import ParseResult

# 회수 산출물 중 파싱 대상 확장자
PARSEABLE = {".csv", ".txt"}


def parse_artifact(path: Path, *, bundle_id: str | None = None,
                   profiles: list[legacy_csv.Profile] | None = None) -> ParseResult | None:
    """파싱 대상이 아니면 None. 대상이면 ParseResult(성공/실패)."""
    ext = path.suffix.lower()
    if ext not in PARSEABLE:
        return None
    data = path.read_bytes()
    if ext == ".csv":
        return legacy_csv.parse_csv_bytes(data, artifact=path.name, profiles=profiles,
                                          bundle_id=bundle_id)
    if report_txt.looks_like_report(data):
        return report_txt.parse_report_bytes(data, artifact=path.name, bundle_id=bundle_id)
    # 진행 로그(__stdout.log 등)나 무관한 txt 는 조용히 건너뛰되 호출측이 경고로 남긴다
    return None
