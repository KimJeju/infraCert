"""가이드 항목(판단기준·조치·사례) 텍스트 포맷 — 수동확인 워크벤치·룰팩 탭·리포트가 같이 쓴다."""

from __future__ import annotations


def format_guide(g: dict) -> str:
    j = g.get("judgment") or {}
    out: list[str] = []
    if j:
        out.append(f"양호: {j.get('good', '')}\n취약: {j.get('vuln', '')}")
    if g.get("remediation"):
        out.append(f"조치방법: {g['remediation']}")
    if g.get("impact"):
        out.append(f"조치 시 영향: {g['impact']}")
    for pr in g.get("procedures") or []:
        out.append(f"[{pr.get('platform', '')}]")
        for k, v in (pr.get("variants") or {}).items():
            out.append(f"  ({k})")
            out.extend("   " + st for st in v.get("steps") or [])
        out.extend("  " + st for st in pr.get("steps") or [])
    return "\n".join(out)


def criteria_line(g: dict) -> str:
    j = g.get("judgment") or {}
    if not j:
        return ""
    return f"양호: {j.get('good', '')} / 취약: {j.get('vuln', '')}"
