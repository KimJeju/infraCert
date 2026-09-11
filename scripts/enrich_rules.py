"""가이드 → 룰 조치방법 채우기 (id 조인).

사용:  python scripts/enrich_rules.py [rulepacks/kisa-2026] [guide/all.json]

- rules/<id>.yaml 에 `remediation:` 이 없거나 비어 있으면 가이드의 '조치 방법'을 붙인다(주석 보존 — 텍스트로 덧붙임).
- manifest `rules:` 메타의 remediation 을 가이드로 채운다(번들만 다루는 D-/WEB- 항목 포함).
- 끝나면 regen_manifest 로 sha 재계산.
`note` 는 건드리지 않는다 — note 는 증적 끝에 붙는 한 줄 기준이라 가이드 문장을 넣으면 증적이 지저분해진다.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import regen_manifest  # noqa: E402


def _one_line(s: str) -> str:
    return " ".join(str(s).split())


def main(pack_dir: Path, guide_json: Path) -> int:
    items = {it["id"]: it for it in json.loads(guide_json.read_text(encoding="utf-8"))}
    touched = 0
    for f in sorted((pack_dir / "rules").glob("*.yaml")):
        rem = _one_line(items.get(f.stem, {}).get("remediation", ""))
        if not rem:
            continue
        text = f.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        if data.get("remediation"):
            continue
        line = yaml.safe_dump({"remediation": rem}, allow_unicode=True, width=10_000).strip()
        if "remediation:" in text:                # 빈 값 줄 교체
            text = "\n".join(line if ln.split(":", 1)[0].strip() == "remediation" else ln
                             for ln in text.splitlines())
        else:
            text = text.rstrip("\n") + "\n" + line + "\n"
        f.write_text(text, encoding="utf-8", newline="\n")
        touched += 1

    mf = pack_dir / "manifest.yaml"
    man = yaml.safe_load(mf.read_text(encoding="utf-8")) or {}
    meta_touched = 0
    for r in man.get("rules") or []:
        rem = _one_line(items.get(str(r.get("id")), {}).get("remediation", ""))
        if rem and not r.get("remediation"):
            r["remediation"] = rem
            meta_touched += 1
    mf.write_text(yaml.safe_dump(man, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8", newline="\n")
    print(f"rules yaml remediation +{touched}, manifest meta remediation +{meta_touched}")
    return regen_manifest.main(pack_dir)


if __name__ == "__main__":
    pack = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "rulepacks" / "kisa-2026"
    guide = Path(sys.argv[2]) if len(sys.argv) > 2 else pack / "guide" / "all.json"
    raise SystemExit(main(pack, guide))
