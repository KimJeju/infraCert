"""룰팩 diff — manifest 만으로 비교한다(스크립트·룰 파일 SHA 가 manifest 안에 있으니 그걸로 충분).

디렉터리든 zip 이든 manifest.yaml 하나만 읽는다. zip 은 풀지 않는다(경로 이탈 걱정 없음).
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

META_FIELDS = ("name", "severity", "category", "remediation", "manual")


@dataclass(slots=True)
class PackDiff:
    a: str = ""
    b: str = ""
    added: list[str] = field(default_factory=list)          # b 에만 있는 룰 id
    removed: list[str] = field(default_factory=list)        # a 에만 있는 룰 id
    logic_changed: list[str] = field(default_factory=list)  # rules/<id>.yaml SHA 변경(판정 조건·명령)
    meta_changed: dict[str, list[str]] = field(default_factory=dict)   # id → 바뀐 메타 필드
    bundles_changed: list[str] = field(default_factory=list)
    profiles_added: list[str] = field(default_factory=list)
    profiles_removed: list[str] = field(default_factory=list)
    profiles_changed: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)  # id → (+rules, -rules)

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.logic_changed or self.meta_changed or self.bundles_changed
                    or self.profiles_added or self.profiles_removed or self.profiles_changed)


def load_manifest(src: Path) -> dict:
    if src.is_dir():
        return yaml.safe_load((src / "manifest.yaml").read_text(encoding="utf-8")) or {}
    with zipfile.ZipFile(src) as zf:
        names = [n for n in zf.namelist() if n.endswith("manifest.yaml") and "/" not in n.strip("/").rstrip("manifest.yaml").rstrip("/")[:0]]
        # zip 루트 또는 <pack>/manifest.yaml 한 단계까지
        cands = [n for n in zf.namelist() if n == "manifest.yaml" or (n.count("/") == 1 and n.endswith("/manifest.yaml"))]
        if not cands:
            raise ValueError(f"{src.name}: manifest.yaml 없음")
        return yaml.safe_load(zf.read(sorted(cands, key=len)[0])) or {}


def _rule_shas(m: dict) -> dict[str, str]:
    return {Path(str(r.get("path"))).stem: str(r.get("sha256") or "") for r in (m.get("rule_files") or [])}


def _rules_meta(m: dict) -> dict[str, dict]:
    return {str(r.get("id")): {k: r.get(k) for k in META_FIELDS} for r in (m.get("rules") or []) if r.get("id")}


def _profiles(m: dict) -> dict[str, set[str]]:
    return {str(p.get("id")): set(map(str, (p.get("native") or []) + (p.get("bundles") or [])))
            for p in (m.get("profiles") or []) if p.get("id")}


def diff(a: dict, b: dict) -> PackDiff:
    d = PackDiff(a=f"{a.get('name', '?')} {a.get('version', '')}".strip(), b=f"{b.get('name', '?')} {b.get('version', '')}".strip())
    ra, rb = _rules_meta(a), _rules_meta(b)
    d.added = sorted(set(rb) - set(ra))
    d.removed = sorted(set(ra) - set(rb))
    sa, sb = _rule_shas(a), _rule_shas(b)
    d.logic_changed = sorted(rid for rid in set(sa) & set(sb) if sa[rid] != sb[rid])
    for rid in sorted(set(ra) & set(rb)):
        changed = [k for k in META_FIELDS if (ra[rid].get(k) or "") != (rb[rid].get(k) or "")]
        if changed:
            d.meta_changed[rid] = changed
    ba = {str(x.get("id")): str(x.get("sha256") or "") for x in (a.get("bundles") or [])}
    bb = {str(x.get("id")): str(x.get("sha256") or "") for x in (b.get("bundles") or [])}
    d.bundles_changed = sorted(k for k in set(ba) | set(bb) if ba.get(k) != bb.get(k))
    pa, pb = _profiles(a), _profiles(b)
    d.profiles_added = sorted(set(pb) - set(pa))
    d.profiles_removed = sorted(set(pa) - set(pb))
    for pid in sorted(set(pa) & set(pb)):
        if pa[pid] != pb[pid]:
            d.profiles_changed[pid] = (sorted(pb[pid] - pa[pid]), sorted(pa[pid] - pb[pid]))
    return d


def render(d: PackDiff) -> str:
    out = [f"{d.a}  →  {d.b}", ""]
    if d.empty:
        out.append("차이 없음")
        return "\n".join(out)
    out += [f"+ {r}  (추가)" for r in d.added]
    out += [f"- {r}  (삭제)" for r in d.removed]
    out += [f"~ {r}  판정 조건/명령 변경 (rules/{r}.yaml)" for r in d.logic_changed]
    out += [f"~ {r}  메타 변경: {', '.join(f)}" for r, f in d.meta_changed.items()]
    out += [f"~ 번들 {b}  스크립트 변경" for b in d.bundles_changed]
    out += [f"+ 프로파일 {p}" for p in d.profiles_added]
    out += [f"- 프로파일 {p}" for p in d.profiles_removed]
    for p, (plus, minus) in d.profiles_changed.items():
        out.append(f"~ 프로파일 {p}: +{len(plus)} -{len(minus)}"
                   + (f"  (+{', '.join(plus[:6])}{'…' if len(plus) > 6 else ''})" if plus else "")
                   + (f"  (-{', '.join(minus[:6])}{'…' if len(minus) > 6 else ''})" if minus else ""))
    out.append("")
    out.append(f"요약: 추가 {len(d.added)} · 삭제 {len(d.removed)} · 로직 변경 {len(d.logic_changed)} · "
               f"메타 변경 {len(d.meta_changed)} · 번들 {len(d.bundles_changed)} · 프로파일 "
               f"{len(d.profiles_added) + len(d.profiles_removed) + len(d.profiles_changed)}")
    return "\n".join(out)
