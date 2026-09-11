"""룰팩 가져오기 — 컨설턴트가 자산에 맞게 만든 부분 룰팩(zip)을 rulepacks/<name>/ 에 푼다.

zip 은 신뢰하지 않는다: 절대경로·`..`·심볼릭링크 멤버는 거부하고, 풀기 전에 전 멤버를 검사한다.
manifest.yaml 이 루트(또는 단일 최상위 폴더 아래)에 있어야 하며, 폴더 이름은 manifest 의 name 으로 정한다.
풀고 나서 로더로 읽어 무결성·읽기전용 검사를 통과하는지 확인한다 — 실패해도 폴더는 남기고 사유를 돌려준다
(사용자가 룰팩 페이지에서 문제 목록을 보고 판단).
"""

from __future__ import annotations

import re
import shutil
import zipfile
from pathlib import Path, PurePosixPath

import yaml

from infraguard.rulepack import loader

_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class ImportError_(Exception):
    pass


def _members(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """전 멤버 경로 검사. 하나라도 위험하면 아무것도 풀지 않는다."""
    out = []
    for info in zf.infolist():
        p = PurePosixPath(info.filename.replace("\\", "/"))
        if p.is_absolute() or ".." in p.parts or info.filename.startswith("/"):
            raise ImportError_(f"위험한 경로 멤버: {info.filename!r}")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:      # 심볼릭링크
            raise ImportError_(f"심볼릭링크 멤버 거부: {info.filename!r}")
        out.append(info)
    return out


def _strip_prefix(members: list[zipfile.ZipInfo]) -> str:
    """manifest.yaml 위치로 공통 접두(단일 최상위 폴더) 결정."""
    names = [m.filename.replace("\\", "/") for m in members]
    if "manifest.yaml" in names:
        return ""
    cands = [n[: -len("manifest.yaml")] for n in names if n.endswith("/manifest.yaml") and n.count("/") == 1]
    if len(cands) != 1:
        raise ImportError_("zip 루트(또는 단일 최상위 폴더)에 manifest.yaml 이 없습니다")
    return cands[0]


def pack_name(zip_path: Path) -> str:
    with zipfile.ZipFile(zip_path) as zf:
        members = _members(zf)
        prefix = _strip_prefix(members)
        raw = yaml.safe_load(zf.read(prefix + "manifest.yaml")) or {}
    name = _NAME_RE.sub("-", str(raw.get("name") or zip_path.stem)).strip("-.")
    if not name:
        raise ImportError_("manifest name 이 비어 있습니다")
    return name


def import_zip(zip_path: Path, root: Path | None = None, *, replace: bool = False) -> tuple[Path, loader.RulePack]:
    """zip → rulepacks/<name>/. 이미 있으면 replace=True 일 때만 덮어쓴다(먼저 지우고 푼다)."""
    root = root or loader.rulepacks_root()
    name = pack_name(zip_path)
    dest = root / name
    if dest.exists():
        if not replace:
            raise ImportError_(f"이미 있는 룰팩: {name}")
        shutil.rmtree(dest)
    with zipfile.ZipFile(zip_path) as zf:
        members = _members(zf)
        prefix = _strip_prefix(members)
        dest.mkdir(parents=True)
        for info in members:
            rel = info.filename.replace("\\", "/")[len(prefix):]
            if not rel or rel.endswith("/"):
                continue
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
    return dest, loader.load(dest)
