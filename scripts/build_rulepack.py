"""부분 룰팩 빌더 — 고객사 자산에 맞는 항목만 골라 zip 으로 만든다. 툴의 '룰팩 가져오기'로 업로드한다.

사용:
    python scripts/build_rulepack.py --src rulepacks/kisa-2026 --name acme-2026q3 --out acme.zip \
        [--profile aix-server] [--rules U-01,U-05,U-16] [--bundles aix-unix] \
        [--guide rulepacks/kisa-2026/guide/all.json] [--version 1.0]

선택 = 프로파일들의 bundles/native ∪ --rules ∪ --bundles. 번들이 provides 하는 항목의 메타도 함께 담는다.
담는 것: manifest(부분, sha 재계산) · rules/<선택>.yaml · 번들 스크립트+동반파일 · 선택 프로파일 · guide/items.yaml(선택 항목만).
--guide 를 주면 수동확인 워크벤치·리포트에 판단기준·조치·사례가 붙는다. 안 주면 manifest 메타의 조치방법만.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from infraguard.rulepack.loader import file_sha256  # noqa: E402


def _csv(s: str | None) -> list[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def build(src: Path, name: str, out: Path, *, profiles: list[str], rules: list[str], bundles: list[str],
          guide_json: Path | None, version: str) -> dict:
    man = yaml.safe_load((src / "manifest.yaml").read_text(encoding="utf-8")) or {}
    user_profiles = {f.stem: yaml.safe_load(f.read_text(encoding="utf-8")) | {"id": f.stem}
                     for f in sorted((src / "profiles").glob("*.yaml"))} if (src / "profiles").exists() else {}
    all_profiles = {p["id"]: p for p in man.get("profiles") or []} | user_profiles

    sel_bundles, sel_native = set(bundles), set(rules)
    sel_profiles = []
    for pid in profiles:
        p = all_profiles.get(pid)
        if not p:
            raise SystemExit(f"프로파일 없음: {pid}")
        sel_profiles.append(p)
        sel_bundles |= set(p.get("bundles") or [])
        sel_native |= set(p.get("native") or [])

    all_bundles = {b["id"]: b for b in man.get("bundles") or []}
    missing = sel_bundles - set(all_bundles)
    if missing:
        raise SystemExit(f"번들 없음: {sorted(missing)}")
    out_bundles = [all_bundles[b] for b in sorted(sel_bundles)]
    covered = set(sel_native)
    for b in out_bundles:
        covered |= set(b.get("provides") or [])

    declared_native = set(man.get("native") or [])
    bad = sel_native - declared_native
    if bad:
        raise SystemExit(f"네이티브 룰 없음: {sorted(bad)}")

    files: list[tuple[str, Path]] = []            # (zip 내 경로, 원본)
    for b in out_bundles:
        for rel in [b["script"], *(b.get("extra_files") or [])]:
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
        "profiles": [{k: v for k, v in p.items()} for p in sel_profiles] or [
            {"id": "default", "name": name, "bundles": sorted(sel_bundles), "native": sorted(sel_native)}],
    }

    guide_items = []
    if guide_json:
        items = json.loads(guide_json.read_text(encoding="utf-8"))
        guide_items = [it for it in items if it.get("id") in covered]

    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", yaml.safe_dump(new_man, allow_unicode=True, sort_keys=False, width=120))
        for rel, p in files:
            zf.write(p, rel)
        if guide_items:
            zf.writestr("guide/items.yaml", yaml.safe_dump(
                {"section": "subset", "count": len(guide_items), "items": guide_items},
                allow_unicode=True, sort_keys=False, width=120))
    return {"bundles": len(out_bundles), "native": len(sel_native), "rules_meta": len(new_man["rules"]),
            "guide": len(guide_items), "files": len(files)}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", default="rulepacks/kisa-2026")
    ap.add_argument("--name", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--version", default="1.0")
    ap.add_argument("--profile", action="append", default=[])
    ap.add_argument("--rules", default="")
    ap.add_argument("--bundles", default="")
    ap.add_argument("--guide", default=None, help="extract_guide.py 의 all.json")
    a = ap.parse_args(argv)
    st = build(Path(a.src), a.name, Path(a.out), profiles=a.profile, rules=_csv(a.rules), bundles=_csv(a.bundles),
               guide_json=Path(a.guide) if a.guide else None, version=a.version)
    print(f"{a.out}: {st}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
