"""룰 fixture 커버리지 — 테스트 스위트가 어느 룰의 어느 판정을 실제로 만들어 봤는가.

사용:  python scripts/rule_coverage.py [--run] [--json PATH]
  --run  : pytest 를 IG_RULE_COVERAGE=PATH 로 돌려 기록을 새로 만든다(conftest 가 evaluate/check 를 감싼다)
  없으면 : 기존 기록 파일을 읽어 표만 출력

출력: 룰 수, 판정별(GOOD/VULN/MANUAL/NA/ERROR) fixture 보유 룰 수, GOOD 또는 VULN fixture 가 없는 룰 목록.
게이트가 아니라 계기판이다 — "룰이 존재한다" 가 아니라 "룰이 판정을 구분한다" 를 세는 용도.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JSON = ROOT / "workspace" / "rule_coverage.json"
VERDICTS = ("GOOD", "VULN", "MANUAL", "NA", "ERROR")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--json", type=Path, default=DEFAULT_JSON)
    ap.add_argument("--pack", type=Path, default=ROOT / "rulepacks" / "kisa-2026")
    a = ap.parse_args()
    if a.run:
        a.json.parent.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, IG_RULE_COVERAGE=str(a.json), QT_QPA_PLATFORM="offscreen")
        rc = subprocess.call([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=ROOT, env=env)
        if rc != 0:
            print(f"pytest rc={rc} — 기록은 남았지만 실패한 스위트의 커버리지다")
    if not a.json.exists():
        print(f"기록 없음: {a.json} (--run 으로 생성)")
        return 2
    cov: dict[str, dict[str, int]] = json.loads(a.json.read_text(encoding="utf-8"))
    man = yaml.safe_load((a.pack / "manifest.yaml").read_text(encoding="utf-8"))
    native = [str(n if isinstance(n, str) else n.get("id")) for n in man.get("native") or []]
    print(f"네이티브 룰 {len(native)}  (기록된 룰 {len([r for r in native if r in cov])})")
    for v in VERDICTS:
        n = sum(1 for r in native if cov.get(r, {}).get(v, 0) > 0)
        print(f"  {v:<7} fixture  {n:>4}/{len(native)}")
    lacking = [r for r in native if not (cov.get(r, {}).get("GOOD") and cov.get(r, {}).get("VULN"))]
    print(f"\nGOOD·VULN 둘 다 없는 룰 {len(lacking)}: " + ", ".join(lacking[:40]) + ("…" if len(lacking) > 40 else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
