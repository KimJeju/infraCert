"""레거시 CSV 파서.

기존 자산의 CSV 헤더가 4종 이상으로 갈린다. 코드에 하드코딩하지 않고
YAML 프로파일로 분리해 새 스크립트가 생겨도 프로파일만 추가하면 되게 한다.

동작:
    1. 헤더로 프로파일 자동 판별 (복수 매칭 시 더 구체적인 쪽, 동률이면 실패)
    2. encoding_candidates 순차 시도, 전부 실패하면 replace + encoding_error
    3. 행 -> RawFinding. rule_id 없는 행은 버리지 않고 경고로 남긴다
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from infraguard.core.models import RawFinding, SourceInfo
from infraguard.parsing.base import AmbiguousProfile, ParseResult, ProfileNotFound

PROFILE_DIR = Path(__file__).parent / "profiles"
DEFAULT_ENCODINGS = ("utf-8-sig", "utf-8", "cp949", "euc-kr")


@dataclass(slots=True)
class Profile:
    name: str
    description: str = ""
    match_all: list[str] = field(default_factory=list)
    match_any: list[str] = field(default_factory=list)
    encodings: tuple[str, ...] = DEFAULT_ENCODINGS
    columns: dict[str, list[str]] = field(default_factory=dict)
    extra_columns: list[str] = field(default_factory=list)

    @property
    def specificity(self) -> tuple[int, int]:
        """구체성. 필수컬럼 수가 1순위, 선택컬럼 수가 2순위.

        8컬럼 변형이 5컬럼 변형의 상위집합인 경우 8컬럼 쪽이 이겨야 한다.
        """
        return (len(self.match_all), len(self.match_any))

    def matches(self, header: list[str]) -> bool:
        hs = {h.strip() for h in header}
        if not all(m in hs for m in self.match_all):
            return False
        if self.match_any and not any(m in hs for m in self.match_any):
            return False
        return bool(self.match_all or self.match_any)

    def pick(self, row: dict[str, str], key: str) -> str | None:
        for cand in self.columns.get(key, []):
            if cand in row and row[cand] is not None and row[cand].strip():
                return row[cand].strip()
        return None


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return [str(x) for x in v]


def load_profiles(directory: Path | None = None) -> list[Profile]:
    d = directory or PROFILE_DIR
    out: list[Profile] = []
    for f in sorted(d.glob("*.yaml")):
        raw = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        m = raw.get("match", {}) or {}
        cols = {k: _as_list(v) for k, v in (raw.get("columns") or {}).items()}
        out.append(
            Profile(
                name=raw.get("name", f.stem),
                description=raw.get("description", ""),
                match_all=_as_list(m.get("header_all")),
                match_any=_as_list(m.get("header_any")),
                encodings=tuple(_as_list(raw.get("encoding_candidates")) or DEFAULT_ENCODINGS),
                columns=cols,
                extra_columns=_as_list(raw.get("extra_columns")),
            )
        )
    return out


def _decode(data: bytes, candidates: tuple[str, ...]) -> tuple[str, str, bool]:
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data.decode("utf-8-sig"), "utf-8-sig", False
        except UnicodeDecodeError:
            pass
    else:
        candidates = tuple(c for c in candidates if c != "utf-8-sig")
    for enc in candidates:
        try:
            return data.decode(enc), enc, False
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8(replace)", True


def _read_header(text: str) -> list[str]:
    rdr = csv.reader(io.StringIO(text))
    for row in rdr:
        if row and any(c.strip() for c in row):
            return [c.strip() for c in row]
    return []


def select_profile(header: list[str], profiles: list[Profile]) -> Profile:
    hits = [p for p in profiles if p.matches(header)]
    if not hits:
        raise ProfileNotFound(f"매칭되는 파서 프로파일 없음. header={header}")
    hits.sort(key=lambda p: p.specificity, reverse=True)
    if len(hits) > 1 and hits[0].specificity == hits[1].specificity:
        raise AmbiguousProfile(
            f"프로파일 중복 매칭: {[p.name for p in hits if p.specificity == hits[0].specificity]}"
        )
    return hits[0]


def parse_csv_bytes(
    data: bytes, *, artifact: str = "", profiles: list[Profile] | None = None,
    bundle_id: str | None = None,
) -> ParseResult:
    profs = profiles if profiles is not None else load_profiles()
    res = ParseResult()

    # 헤더 판별용으로 우선 넓은 후보로 디코드
    text, enc, enc_err = _decode(data, DEFAULT_ENCODINGS)
    header = _read_header(text)
    if not header:
        res.error = "empty or unreadable csv"
        return res

    try:
        prof = select_profile(header, profs)
    except (ProfileNotFound, AmbiguousProfile) as e:
        res.error = str(e)
        return res

    # 프로파일이 지정한 인코딩 후보로 재디코드
    text, enc, enc_err = _decode(data, prof.encodings)
    res.profile, res.encoding, res.encoding_error = prof.name, enc, enc_err
    if enc_err:
        res.warnings.append(f"{artifact}: 인코딩 판별 실패, 치환 문자 사용")

    reader = csv.DictReader(io.StringIO(text))
    for i, row in enumerate(reader, start=2):
        clean = {(k.strip() if k else ""): (v or "") for k, v in row.items() if k}
        rid = prof.pick(clean, "rule_id")
        if not rid:
            res.warnings.append(f"{artifact}:{i}: 항목코드 없음 — 행 보존")
            continue
        res.findings.append(
            RawFinding(
                rule_id=rid,
                name=prof.pick(clean, "name"),
                severity_raw=prof.pick(clean, "severity"),
                verdict_raw=prof.pick(clean, "verdict"),
                evidence_raw=prof.pick(clean, "evidence"),
                extra={c: clean[c] for c in prof.extra_columns if c in clean and clean[c]},
                source=SourceInfo(bundle_id=bundle_id, artifact=artifact,
                                  profile=prof.name, line=i),
            )
        )
    if not res.findings:
        res.warnings.append(f"{artifact}: 유효 행 0건")
    return res


def parse_csv_file(path: Path, **kw: Any) -> ParseResult:
    return parse_csv_bytes(path.read_bytes(), artifact=path.name, **kw)
