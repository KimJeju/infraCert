"""Dry-run — 진단을 돌리기 전에 "이 프로파일이 이 플랫폼에서 무엇을 실행하는가" 를 정적으로 열거한다.

고객에게 "읽기전용으로 이런 명령만 실행합니다" 라고 보여주는 용도. 원격에 아무것도 붙지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from infraguard.rulepack.loader import Profile, RulePack
from infraguard.rules import load_all
from infraguard.rules.policy import check


@dataclass(slots=True)
class Plan:
    platform: str
    commands: list[tuple[str, str, str]] = field(default_factory=list)   # (rule_id, shell, cmd)
    python_rules: list[str] = field(default_factory=list)                # 명령을 정적으로 열거 못 하는 파이썬 룰
    skipped: list[str] = field(default_factory=list)                     # 플랫폼 불일치로 SKIPPED 될 룰
    bundles: list[tuple[str, str, str]] = field(default_factory=list)    # (bundle_id, script, interpreter)
    violations: list[str] = field(default_factory=list)                  # 정책 위반(정상이면 비어야 한다)


def plan(pack: RulePack, profile: Profile, platform: str) -> Plan:
    reg = load_all()
    p = Plan(platform=platform)
    for rid in profile.native:
        rule = reg.get(rid)
        if rule is None:
            continue
        if platform not in rule.platforms:
            p.skipped.append(rid)
            continue
        spec = pack.specs.get(rid)
        if spec is None:
            p.python_rules.append(rid)
            continue
        blk = spec.for_platform(platform)
        for c in blk.collect:
            p.commands.append((rid, blk.shell, c.cmd))
            p.violations += [f"{rid}: {w}" for w in check(blk.shell, c.cmd)]
    for bid in profile.bundles:
        b = pack.bundles.get(bid)
        if b is not None and (not b.platforms or platform in b.platforms):
            p.bundles.append((bid, b.script.name, b.interpreter or "sh"))
    return p


def render(plans: list[Plan], *, hosts_by_platform: dict[str, int] | None = None) -> str:
    out: list[str] = []
    for p in plans:
        n = (hosts_by_platform or {}).get(p.platform)
        out.append(f"[{p.platform}]" + (f" 호스트 {n}대" if n else ""))
        out.append(f"  네이티브 룰 {len({r for r, _, _ in p.commands}) + len(p.python_rules)}개 · "
                   f"실행 명령 {len(p.commands)}개 · 변경 명령 {len(p.violations)}개 · "
                   f"플랫폼 불일치(SKIPPED) {len(p.skipped)}개")
        if p.bundles:
            out.append("  번들(스크립트 업로드 → mktemp 격리 디렉터리에서 실행 → 산출물 회수 → 디렉터리 삭제):")
            out += [f"    {bid}: {script} ({interp})" for bid, script, interp in p.bundles]
            out.append("  예상 원격 잔류물: 실행 중 임시 디렉터리 1개(종료 시 삭제, 실패하면 결과에 '정리 미완료' 로 표시)")
        else:
            out.append("  예상 원격 잔류물: 없음(명령 실행만)")
        if p.violations:
            out.append("  ⚠ 정책 위반: " + "; ".join(p.violations))
        for rid, sh, cmd in p.commands:
            out.append(f"  {rid:<7} [{sh}] {cmd}")
        if p.python_rules:
            out.append("  (파이썬 룰 — 실행 시 명령이 기록됨, 정적 열거 불가): " + ", ".join(p.python_rules))
        out.append("")
    return "\n".join(out).rstrip()
