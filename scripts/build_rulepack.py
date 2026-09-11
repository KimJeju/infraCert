"""부분 룰팩 빌더 CLI — 고객사 자산에 맞는 항목만 골라 zip 으로. 툴의 '룰팩 가져오기'로 업로드한다.

사용:
    python scripts/build_rulepack.py --src rulepacks/kisa-2026 --name acme-2026q3 --out acme.zip \
        [--profile aix-server] [--rules U-01,U-05,U-16] [--bundles aix-unix] \
        [--guide rulepacks/kisa-2026/guide/all.json] [--version 1.0]

로직은 infraguard.rulepack.builder (룰팩 탭 "선택 항목으로 zip" 버튼과 동일).
--guide 를 주면 수동확인 워크벤치·리포트에 판단기준·조치·사례가 붙는다. 안 주면 manifest 메타의 조치방법만.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from infraguard.rulepack.builder import BuildError  # noqa: E402
from infraguard.rulepack.builder import build as _build  # noqa: E402


def _csv(s: str | None) -> list[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def build(src: Path, name: str, out: Path, *, profiles: list[str], rules: list[str], bundles: list[str],
          guide_json: Path | None, version: str) -> dict:
    items = json.loads(guide_json.read_text(encoding="utf-8")) if guide_json else None
    return _build(src, name, out, profiles=profiles, rules=rules, bundles=bundles, guide_items=items,
                  version=version)


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
    try:
        st = build(Path(a.src), a.name, Path(a.out), profiles=a.profile, rules=_csv(a.rules),
                   bundles=_csv(a.bundles), guide_json=Path(a.guide) if a.guide else None, version=a.version)
    except BuildError as e:
        raise SystemExit(str(e)) from e
    print(f"{a.out}: {st}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
