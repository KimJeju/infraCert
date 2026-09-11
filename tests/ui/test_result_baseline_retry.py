"""결과 화면: 전회 대비 '이전' 컬럼·'변경만' 필터, 진단 페이지의 실패·미완료 재진단 대상."""

from __future__ import annotations

import os
from datetime import UTC, datetime

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from infraguard.assets.models import Host  # noqa: E402
from infraguard.core.models import CheckResult, HostResult, ScanResult  # noqa: E402
from infraguard.core.status import Status  # noqa: E402
from infraguard.ui.pages.result import ResultPage  # noqa: E402
from infraguard.ui.pages.scan import ScanPage  # noqa: E402


def _scan(sid: str, rows: dict[str, Status]) -> ScanResult:
    return ScanResult(scan_id=sid, engine_version="t", started_at=datetime.now(UTC), hosts=[HostResult(
        host_id="h", hostname="srv", results=[CheckResult(rule_id=k, name=k, status=v, reason="r") for k, v in rows.items()])])


def _col(page: ResultPage, row: int, col: int) -> str:
    it = page.table.item(row, col)
    return it.text() if it else ""


def test_baseline_column_and_changed_filter(qtbot) -> None:  # noqa: ANN001
    page = ResultPage()
    qtbot.addWidget(page)
    prev = _scan("s0", {"U-01": Status.PASS, "U-02": Status.FAIL, "U-03": Status.UNKNOWN})
    cur = _scan("s1", {"U-01": Status.FAIL, "U-02": Status.FAIL, "U-04": Status.PASS})
    page.set_baseline(prev)
    page.load(cur)
    assert page.changed_only.isEnabled() and "s0" in page.base_label.text()
    assert page.table.rowCount() == 3
    assert _col(page, 0, 1) == "U-01" and _col(page, 0, 5).startswith("양호") and _col(page, 0, 5).endswith("→")   # 양호→취약 변경
    assert _col(page, 1, 1) == "U-02" and _col(page, 1, 5) == "취약"                                              # 동일
    assert _col(page, 2, 1) == "U-04" and _col(page, 2, 5) == ""                                                  # 전회에 없음
    page.changed_only.setChecked(True)
    assert page.table.rowCount() == 1 and _col(page, 0, 1) == "U-01"
    page.table.selectRow(0)
    assert "전회(s0): 양호" in page.detail.toPlainText() and "변경됨" in page.detail.toPlainText()

    page.set_baseline(None)                       # 기준 없으면 필터 꺼지고 비활성
    page.load(cur)
    assert not page.changed_only.isEnabled() and not page.changed_only.isChecked() and page.table.rowCount() == 3


def test_scan_page_pending_or_failed(qtbot) -> None:  # noqa: ANN001
    page = ScanPage()
    qtbot.addWidget(page)
    hosts = [Host(host_id=f"h{i}", name=f"h{i}", address="1.1.1.1") for i in range(3)]
    page.begin(hosts)
    assert not page.retry.isEnabled()
    page.on_result("h0", HostResult(host_id="h0", hostname="h0"))                       # 완료
    page.on_result("h1", HostResult(host_id="h1", hostname="h1", error="connect failed"))  # 오류
    # h2 는 중단으로 안 돎
    page.finished()
    assert page.pending_or_failed() == ["h1", "h2"] and page.retry.isEnabled()
    page.begin([hosts[1], hosts[2]])
    page.on_result("h1", HostResult(host_id="h1", hostname="h1"))
    page.on_result("h2", HostResult(host_id="h2", hostname="h2"))
    page.finished()
    assert page.pending_or_failed() == [] and not page.retry.isEnabled()
