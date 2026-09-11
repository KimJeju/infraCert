"""룰팩 manifest 재생성 — 사람이 SHA-256 을 손으로 계산하지 않게.

사용:  python scripts/regen_manifest.py [rulepacks/kisa-2026]

하는 일:
  - bundles[*].sha256 을 스크립트 파일로 재계산
  - rules/*.yaml 을 전부 rule_files 에 (path, sha256) 로 등록
  - native = 앱 동봉 파이썬 룰 ∪ YAML 룰 id (정렬)
  - profiles 중 id 가 *-native 인 것은 native 전체로 갱신 (platforms 필터는 런타임이 SKIPPED 로 처리)
  - rules 메타(name/severity/category)는 기존 항목을 보존하고, YAML 룰의 메타를 보충

수정하지 않는 것: bundles 의 나머지 필드, 사용자 프로파일(rulepacks/<pack>/profiles/).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from infraguard.rulepack.loader import file_sha256 as sha256  # noqa: E402  # 로더와 동일 정규화
from infraguard.rules import load_all  # noqa: E402
from infraguard.rules.declarative import load_file  # noqa: E402


def normalize_lf(p: Path) -> bool:
    """작업본에 CRLF 가 있으면 LF 로 고쳐 쓴다. (해시는 어차피 정규화하지만 diff 오염 방지)"""
    b = p.read_bytes()
    if b"\r\n" in b:
        p.write_bytes(b.replace(b"\r\n", b"\n"))
        return True
    return False


def rule_key(rid: str) -> tuple[str, int]:
    pre, num = rid.rsplit("-", 1)
    return pre, int(num)


def main(pack_dir: Path) -> int:
    mf = pack_dir / "manifest.yaml"
    man = yaml.safe_load(mf.read_text(encoding="utf-8")) or {}

    fixed = 0
    for b in man.get("bundles") or []:
        fixed += normalize_lf(pack_dir / b["script"])
        b["sha256"] = sha256(pack_dir / b["script"])

    specs = {}
    rule_files = []
    for f in sorted((pack_dir / "rules").glob("*.yaml")):
        fixed += normalize_lf(f)
        spec = load_file(f)                     # 스키마 위반이면 여기서 터진다 — 잘못된 룰을 등록하지 않는다
        if spec.id != f.stem:
            raise SystemExit(f"{f.name}: 파일명과 id 불일치 ({spec.id})")
        specs[spec.id] = spec
        rule_files.append({"path": f"rules/{f.name}", "sha256": sha256(f)})
    man["rule_files"] = rule_files

    native = sorted(set(load_all()) | set(specs), key=rule_key)
    man["native"] = native

    meta = {r["id"]: r for r in man.get("rules") or []}
    for rid, spec in specs.items():
        m = meta.setdefault(rid, {"id": rid})
        m.setdefault("name", spec.name)
        m.setdefault("severity", spec.severity)
        m.setdefault("category", spec.category)
        m["manual"] = bool(spec.manual)     # YAML 이 정본. 이전 값이 남아 N/A 를 수동확인으로 덮지 않게 덮어쓴다
        if spec.remediation:
            m["remediation"] = spec.remediation
    man["rules"] = [meta[k] for k in sorted(meta, key=rule_key)]

    for p in man.get("profiles") or []:
        if str(p.get("id", "")).endswith("-native"):
            p["native"] = native

    order = ["name", "version", "license", "description", "bundles", "rule_files", "native",
             "rules", "profiles"]
    man = {k: man[k] for k in order if k in man} | {k: v for k, v in man.items() if k not in order}
    mf.write_text(yaml.safe_dump(man, allow_unicode=True, sort_keys=False, width=120),
                  encoding="utf-8", newline="\n")
    print(f"{mf}: bundles={len(man.get('bundles') or [])} rule_files={len(rule_files)} "
          f"native={len(native)} rules={len(man['rules'])}"
          + (f"  (CRLF→LF 정규화 {fixed}개)" if fixed else ""))
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "rulepacks" / "kisa-2026"
    raise SystemExit(main(target))
