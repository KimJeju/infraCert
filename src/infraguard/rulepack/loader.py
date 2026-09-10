"""룰팩 로더 — rulepacks/<name>/manifest.yaml.

강제 사항(갭분석 G-22·G-25·G-30):
  - Bundle 스크립트는 side_effects: read 를 명시해야 한다. 미선언·write 는 **로드 거부**하고 목록을 돌려준다.
  - 스크립트 SHA-256 을 manifest 와 대조한다(무결성). 불일치면 실행을 막는다.
  - Native 룰 id 는 앱 동봉 레지스트리(infraguard.rules)에 있어야 한다. 데이터 디렉터리에서 코드를 로드하지 않는다.
  - provides 를 선언한 Bundle 은 산출물에 없는 항목이 UNKNOWN 으로 드러난다(result.engine.normalize).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from infraguard.rules import load_all
from infraguard.workspace.layout import app_root

RULEPACKS_DIRNAME = "rulepacks"
PROFILES_DIRNAME = "profiles"
RULES_DIRNAME = "rules"


class RulePackError(Exception):
    pass


@dataclass(slots=True)
class Bundle:
    id: str
    script: Path
    sha256: str
    provides: list[str]
    platforms: list[str]
    parser: str = "auto"              # auto | report_txt | legacy_csv
    interpreter: str | None = None
    timeout: int = 1800
    side_effects: str = ""            # 반드시 "read"
    args: list[str] = field(default_factory=list)
    extra_files: list[Path] = field(default_factory=list)
    description: str = ""


@dataclass(slots=True)
class RuleMeta:
    id: str
    name: str
    severity: str = ""
    category: str = ""
    manual: bool = False
    remediation: str = ""
    kind: str = ""                    # "" | "yaml" | "python"  (네이티브 룰 구현 종류)


@dataclass(slots=True)
class Profile:
    id: str
    name: str
    bundles: list[str] = field(default_factory=list)      # bundle ids
    native: list[str] = field(default_factory=list)       # native rule ids
    exclude: list[str] = field(default_factory=list)      # 결과에서 제외할 rule ids
    description: str = ""


@dataclass(slots=True)
class RulePack:
    name: str
    version: str
    root: Path
    bundles: dict[str, Bundle]
    native: list[str]                  # 사용 가능한 네이티브 룰 id
    rules: dict[str, RuleMeta]
    profiles: dict[str, Profile]
    integrity_ok: bool
    problems: list[str]                # 로드는 됐지만 실행을 막아야 하는 사유

    @property
    def runnable(self) -> bool:
        return self.integrity_ok and not self.problems

    def manual_rules(self) -> set[str]:
        return {r.id for r in self.rules.values() if r.manual}


def rulepacks_root() -> Path:
    return app_root() / RULEPACKS_DIRNAME


def list_packs() -> list[Path]:
    root = rulepacks_root()
    if not root.exists():
        return []
    return sorted(p for p in root.iterdir() if (p / "manifest.yaml").exists())


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load(pack_dir: Path) -> RulePack:
    mf = pack_dir / "manifest.yaml"
    if not mf.exists():
        raise RulePackError(f"manifest.yaml 없음: {pack_dir}")
    raw = yaml.safe_load(mf.read_text(encoding="utf-8")) or {}
    problems: list[str] = []
    integrity_ok = True

    bundles: dict[str, Bundle] = {}
    for b in raw.get("bundles") or []:
        bid = str(b.get("id") or "")
        se = str(b.get("side_effects") or "").strip().lower()
        if se != "read":
            # 조치형(write) 또는 미선언 → 거부. 목록에 남겨 사용자에게 보여준다.
            problems.append(f"bundle {bid!r}: side_effects={se or '(미선언)'} — 읽기전용(read) 아님, 로드 거부")
            continue
        script = pack_dir / str(b.get("script") or "")
        declared = str(b.get("sha256") or "").lower()
        if not script.exists():
            problems.append(f"bundle {bid!r}: 스크립트 없음 {script.name}")
            integrity_ok = False
            actual = ""
        else:
            actual = _sha256(script)
            if declared and declared != actual:
                problems.append(f"bundle {bid!r}: SHA-256 불일치 (manifest {declared[:12]}… / 실제 {actual[:12]}…)")
                integrity_ok = False
        bundles[bid] = Bundle(
            id=bid, script=script, sha256=actual,
            provides=[str(x) for x in (b.get("provides") or [])],
            platforms=[str(x) for x in (b.get("platforms") or [])],
            parser=str(b.get("parser") or "auto"),
            interpreter=b.get("interpreter"),
            timeout=int(b.get("timeout") or 1800),
            side_effects=se,
            args=[str(x) for x in (b.get("args") or [])],
            extra_files=[pack_dir / str(x) for x in (b.get("extra_files") or [])],
            description=str(b.get("description") or ""),
        )
        for ef in bundles[bid].extra_files:
            if not ef.exists():
                problems.append(f"bundle {bid!r}: 동반 파일 없음 {ef.name}")
                integrity_ok = False

    registry = load_all()

    # 선언형(YAML) 룰: rules/*.yaml. manifest 의 rule_files 에 sha256 으로 등록된 파일만 신뢰한다.
    declared = {str(r.get("path")): str(r.get("sha256") or "").lower()
                for r in (raw.get("rule_files") or [])}
    rules_dir = pack_dir / RULES_DIRNAME
    declarative_kind: dict[str, str] = {}
    if rules_dir.exists():
        for f in sorted(rules_dir.glob("*.yaml")):
            rel = f"{RULES_DIRNAME}/{f.name}"
            actual = _sha256(f)
            if rel not in declared:
                problems.append(f"rule {f.name}: manifest.rule_files 에 미등록 — 무시")
                integrity_ok = False
                continue
            if declared[rel] and declared[rel] != actual:
                problems.append(f"rule {f.name}: SHA-256 불일치")
                integrity_ok = False
        from infraguard.rules.declarative import register_dir
        specs, rp = register_dir(rules_dir)
        problems.extend(rp)
        declarative_kind = {rid: "yaml" for rid in specs}
        for rel in declared:
            if not (pack_dir / rel).exists():
                problems.append(f"rule {rel}: 파일 없음")
                integrity_ok = False

    native: list[str] = []
    for n in raw.get("native") or []:
        nid = str(n if isinstance(n, str) else n.get("id"))
        if nid not in registry:
            problems.append(f"native {nid!r}: 앱에 등록되지 않은 룰")
            continue
        native.append(nid)

    rules: dict[str, RuleMeta] = {}
    for r in raw.get("rules") or []:
        rid = str(r.get("id") or "")
        if rid:
            rules[rid] = RuleMeta(
                id=rid, name=str(r.get("name") or rid), severity=str(r.get("severity") or ""),
                category=str(r.get("category") or ""), manual=bool(r.get("manual", False)),
                remediation=str(r.get("remediation") or ""),
            )
    # 네이티브 룰 메타는 레지스트리에서 보충. kind 로 선언형/파이썬 구분.
    for nid in native:
        nr = registry[nid]
        kind = declarative_kind.get(nid, "python")
        if nid not in rules:
            rules[nid] = RuleMeta(id=nid, name=nr.name, severity=nr.severity, category="native")
        rules[nid].kind = kind

    profiles: dict[str, Profile] = {}
    for p in list(raw.get("profiles") or []) + _load_user_profiles(pack_dir):
        pid = str(p.get("id") or "")
        if not pid:
            continue
        prof = Profile(
            id=pid, name=str(p.get("name") or pid),
            bundles=[str(x) for x in (p.get("bundles") or [])],
            native=[str(x) for x in (p.get("native") or [])],
            exclude=[str(x) for x in (p.get("exclude") or [])],
            description=str(p.get("description") or ""),
        )
        for bid in prof.bundles:
            if bid not in bundles:
                problems.append(f"profile {pid!r}: 알 수 없는 bundle {bid!r}")
        profiles[pid] = prof

    return RulePack(
        name=str(raw.get("name") or pack_dir.name), version=str(raw.get("version") or ""),
        root=pack_dir, bundles=bundles, native=native, rules=rules, profiles=profiles,
        integrity_ok=integrity_ok, problems=problems,
    )


def _load_user_profiles(pack_dir: Path) -> list[dict]:
    d = pack_dir / PROFILES_DIRNAME
    out: list[dict] = []
    if d.exists():
        for f in sorted(d.glob("*.yaml")):
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                data.setdefault("id", f.stem)
                out.append(data)
    return out


def save_profile(pack: RulePack, profile: Profile) -> Path:
    """사용자 프로파일은 workspace 가 아니라 rulepacks/<pack>/profiles/ 에 저장(반출 대상, §9)."""
    d = pack.root / PROFILES_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{profile.id}.yaml"
    p.write_text(yaml.safe_dump({
        "id": profile.id, "name": profile.name, "bundles": profile.bundles,
        "native": profile.native, "exclude": profile.exclude, "description": profile.description,
    }, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return p
