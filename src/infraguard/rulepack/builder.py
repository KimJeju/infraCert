"""부분 룰팩 빌더 — 원본 룰팩에서 번들·룰을 골라 zip 으로 만든다(컨설턴트가 고객 자산에 맞게).

CLI(scripts/build_rulepack.py)와 룰팩 탭 버튼이 같이 쓴다. sha256 은 재계산하고,
번들 스크립트·동반파일·선택한 rules/*.yaml·선택 항목의 가이드만 담는다.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import yaml

from infraguard.rulepack.loader import file_sha256


class BuildError(Exception):
    pass


def build(src: Path, name: str, out: Path, *, profiles: list[str] = (), rules: list[str] = (),
          bundles: list[str] = (), guide_items: list[dict] | None = None, version: str = "1.0") -> dict:
    """선택 = profiles 의 bundles/native ∪ rules ∪ bundles. 반환: 담긴 개수 통계."""
    man = yaml.safe_load((src / "manifest.yaml").read_text(encoding="utf-8")) or {}
    user_profiles = {f.stem: (yaml.safe_load(f.read_text(encoding="utf-8")) or {}) | {"id": f.stem}
                     for f in sorted((src / "profiles").glob("*.yaml"))} if (src / "profiles").exists() else {}
    all_profiles = {p["id"]: p for p in man.get("profiles") or []} | user_profiles

    sel_bundles, sel_native = set(bundles), set(rules)
    sel_profiles = []
    for pid in profiles:
        p = all_profiles.get(pid)
        if not p:
            raise BuildError(f"프로파일 없음: {pid}")
        sel_profiles.append(p)
        sel_bundles |= set(p.get("bundles") or [])
        sel_native |= set(p.get("native") or [])
    if not sel_bundles and not sel_native:
        raise BuildError("선택된 번들/룰이 없습니다")

    all_bundles = {b["id"]: b for b in man.get("bundles") or []}
    missing = sel_bundles - set(all_bundles)
    if missing:
        raise BuildError(f"번들 없음: {sorted(missing)}")
    out_bundles = [dict(all_bundles[b]) for b in sorted(sel_bundles)]
    covered = set(sel_native)
    for b in out_bundles:
        covered |= set(b.get("provides") or [])

    bad = sel_native - set(man.get("native") or [])
    if bad:
        raise BuildError(f"네이티브 룰 없음: {sorted(bad)}")

    files: list[tuple[str, Path]] = []            # (zip 내 경로, 원본)
    for b in out_bundles:
        for rel in [b["script"], *(b.get("extra_files") or [])]:
            if not (src / rel).exists():
                raise BuildError(f"번들 파일 없음: {rel}")
            files.append((rel, src / rel))
        b["sha256"] = file_sha256(src / b["script"])

    rule_files = []
    for rid in sorted(sel_native):
        f = src / "rules" / f"{rid}.yaml"
        if f.exists():                             # 파이썬 룰은 파일이 없다(앱 동봉)
            files.append((f"rules/{f.name}", f))
            rule_files.append({"path": f"rules/{f.name}", "sha256": file_sha256(f)})

    new_man = {
        "name": name, "version": version,
        "description": f"{man.get('name')} {man.get('version')} 에서 추린 부분 룰팩",
        "bundles": out_bundles, "rule_files": rule_files, "native": sorted(sel_native),
        "rules": [r for r in man.get("rules") or [] if r.get("id") in covered],
        "profiles": [dict(p) for p in sel_profiles] or [
            {"id": "default", "name": name, "bundles": sorted(sel_bundles), "native": sorted(sel_native)}],
    }
    picked_guide = [it for it in (guide_items or []) if it.get("id") in covered]

    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", yaml.safe_dump(new_man, allow_unicode=True, sort_keys=False, width=120))
        for rel, p in files:
            zf.write(p, rel)
        if picked_guide:
            zf.writestr("guide/items.yaml", yaml.safe_dump(
                {"section": "subset", "count": len(picked_guide), "items": picked_guide},
                allow_unicode=True, sort_keys=False, width=120))
    return {"bundles": len(out_bundles), "native": len(sel_native), "rules_meta": len(new_man["rules"]),
            "guide": len(picked_guide), "files": len(files)}
