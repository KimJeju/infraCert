"""HTML 리포트 — 단일 파일, 외부 리소스 없음(폐쇄망).

XLSX 와 같은 내용을 브라우저로 바로 보는 용도. 원본 증적은 마스킹 후 인라인.
"""

from __future__ import annotations

import html
from pathlib import Path

from infraguard.core.models import ScanResult
from infraguard.core.status import DISPLAY_KO, ORDER, Status

_BG = {
    Status.PASS: "#e2efda", Status.FAIL: "#fce4e4", Status.UNKNOWN: "#fff2cc",
    Status.SKIPPED: "#f2f2f2", Status.ERROR: "#e4dfec",
}


def _esc(v: object) -> str:
    return html.escape(str(v)) if v is not None else ""


def build(scan: ScanResult, out: Path) -> Path:
    summ = scan.summary()
    cards = "".join(
        f'<div class="card" style="background:{_BG[s]}">'
        f'<div class="n">{summ[s]}</div><div class="l">{DISPLAY_KO[s]}</div></div>'
        for s in ORDER
    )
    rows = []
    for h in scan.hosts:
        for r in h.results:
            rows.append(
                f"<tr><td>{_esc(h.hostname)}</td><td>{_esc(r.rule_id)}</td>"
                f"<td>{_esc(r.name)}</td><td>{_esc(r.severity.value if r.severity else '')}</td>"
                f'<td style="background:{_BG[r.status]};text-align:center">{DISPLAY_KO[r.status]}</td>'
                f"<td>{_esc(r.reason)}</td><td><pre>{_esc(r.evidence or '')}</pre></td></tr>"
            )
    doc = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>InfraGuard 진단결과 {_esc(scan.scan_id)}</title><style>
body{{font-family:'Malgun Gothic',sans-serif;margin:24px;color:#1a1a1a}}
h1{{font-size:18px}} .meta{{color:#666;font-size:13px;margin-bottom:16px}}
.cards{{display:flex;gap:8px;margin:16px 0}}
.card{{padding:12px 20px;border-radius:6px;text-align:center;min-width:72px}}
.card .n{{font-size:24px;font-weight:700}} .card .l{{font-size:12px}}
table{{border-collapse:collapse;width:100%;font-size:12px}}
th,td{{border:1px solid #ccc;padding:4px 6px;vertical-align:top;text-align:left}}
th{{background:#d9d9d9}} pre{{margin:0;white-space:pre-wrap;font-family:Consolas,monospace;max-height:120px;overflow:auto}}
</style></head><body>
<h1>InfraGuard 진단 결과</h1>
<div class="meta">Scan {_esc(scan.scan_id)} · 엔진 {_esc(scan.engine_version)} · 호스트 {len(scan.hosts)}대
· 시작 {_esc(scan.started_at.strftime('%Y-%m-%d %H:%M:%S'))}</div>
<div class="cards">{cards}</div>
<table><thead><tr><th>호스트</th><th>항목코드</th><th>점검항목</th><th>중요도</th>
<th>진단결과</th><th>판정근거</th><th>점검내용</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="meta">※ 수동확인은 자동 판정이 불가한 항목이며 실행오류(ERROR)와 구분됩니다.</p>
</body></html>"""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    return out
