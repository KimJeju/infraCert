"""메인 윈도우 — 사이드바 + 탭 + 상태바 조립, 스캔 오케스트레이션(§1·§2)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from infraguard import config
from infraguard.assets.models import Host
from infraguard.assets.store import AssetStore
from infraguard.core.ids import new_scan_id
from infraguard.core.models import HostResult, ScanResult
from infraguard.core.status import Severity, Status
from infraguard.credentials.session import CredentialSession
from infraguard.orchestrator.results_store import ResultsStore
from infraguard.reporting import html as html_report
from infraguard.reporting import xlsx as xlsx_report
from infraguard.rulepack import loader as rp_loader
from infraguard.rulepack.loader import RulePack
from infraguard.ui.dialogs import AssetEditDialog, CredPromptDialog, HostKeyDialog
from infraguard.ui.exit_flow import CONFIRM_SCANNING, WARN_UNEXPORTED, ExitState, exit_gate
from infraguard.ui.models_qt import HOST_ID_ROLE, AssetTreeModel, StatusDelegate
from infraguard.ui.pages.dashboard import DashboardPage
from infraguard.ui.pages.manual import ManualBenchPage
from infraguard.ui.pages.result import ResultPage
from infraguard.ui.pages.rulepack import RulePackPage
from infraguard.ui.pages.scan import ScanPage
from infraguard.ui.pages.settings import SettingsPage
from infraguard.ui.pages.sftp import SftpPage
from infraguard.ui.terminal import TerminalPage
from infraguard.ui.workers import ScanController, build_job

TERMINAL_NOTICE = (
    "자동 진단(Bundle 실행)은 Read-only 이며 대상 시스템을 변경하지 않습니다.\n\n"
    "터미널 탭에서 사용자가 직접 입력하는 명령은 이 보장의 대상이 아니며 사용자 책임입니다.\n"
    "입력·출력은 workspace/logs/terminal/ 에 기록되며(비밀번호는 마스킹) 종료 시 삭제됩니다."
)
from infraguard.workspace.manager import Workspace

log = logging.getLogger(__name__)


@dataclass
class AppContext:
    workspace: Workspace
    assets: AssetStore
    results: ResultsStore
    creds: CredentialSession
    config: dict


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle("InfraGuard")
        self.resize(1360, 860)
        self.setMinimumSize(1100, 700)

        self._scan_id: str | None = None
        self._scanning = False
        self._unexported = False
        self._stages: dict[str, str] = {}
        self._pcts: dict[str, int] = {}
        self._terminals: list[TerminalPage] = []
        self._sftps: list[SftpPage] = []
        self._notice_shown = False

        self.controller = ScanController()
        self.controller.host_key_bridge.request.connect(self._on_host_key)
        self.pack: RulePack | None = self._load_rulepack()

        self._build_menu()
        self._build_body()
        self._wire_controller()
        self._refresh_assets()
        self._refresh_dashboard()
        self._refresh_profiles()

    def _load_rulepack(self, name: str | None = None) -> RulePack | None:
        """rulepacks/<name>. name 없으면 config 의 rulepack, 그것도 없으면 첫 번째."""
        packs = rp_loader.list_packs()
        if not packs:
            return None
        want = name or str(self.ctx.config.get("rulepack") or "")
        chosen = next((p for p in packs if p.name == want), packs[0])
        try:
            return rp_loader.load(chosen)
        except Exception as e:  # noqa: BLE001 - 룰팩 깨져도 앱은 떠야 한다(문제를 보여준다)
            log.exception("rulepack load failed")
            return RulePack(name=chosen.name, version="?", root=chosen, bundles={}, native=[],
                            rules={}, profiles={}, integrity_ok=False, problems=[f"로드 실패: {e}"])

    def _switch_rulepack(self, name: str) -> None:
        if not name or self._scanning:
            return
        self.pack = self._load_rulepack(name)
        self.ctx.config["rulepack"] = name
        config.save(self.ctx.config)
        self._refresh_profiles()

    def _import_rulepack(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "룰팩 가져오기", "", "룰팩 zip (*.zip)")
        if not path:
            return
        from pathlib import Path

        from infraguard.rulepack import importer
        try:
            name = importer.pack_name(Path(path))
            replace = False
            if (rp_loader.rulepacks_root() / name).exists():
                if QMessageBox.question(self, "룰팩 가져오기", f"'{name}' 이(가) 이미 있습니다. 덮어쓸까요?") \
                        != QMessageBox.StandardButton.Yes:
                    return
                replace = True
            dest, pack = importer.import_zip(Path(path), replace=replace)
        except Exception as e:  # noqa: BLE001 - zip 검사 실패·manifest 오류 전부 사용자에게
            QMessageBox.warning(self, "룰팩 가져오기 실패", str(e))
            return
        msg = f"{dest.name}: 번들 {len(pack.bundles)} · 네이티브 {len(pack.native)} · 가이드 {len(pack.guide)}항목"
        if not pack.runnable:
            msg += f"\n⚠ 문제 {len(pack.problems)}건 — 실행 차단 (룰팩 탭에서 확인)"
        QMessageBox.information(self, "룰팩 가져오기", msg)
        self._switch_rulepack(dest.name)

    def _refresh_profiles(self) -> None:
        self.rulepack.set_packs([p.name for p in rp_loader.list_packs()], self.pack.name if self.pack else None)
        self.rulepack.load(self.pack)
        self.manual.set_guide(self.pack.guide if self.pack else {},
                              self.pack.remediation_map() if self.pack else {})
        items = []
        if self.pack:
            for pid, p in self.pack.profiles.items():
                desc = (f"번들 {len(p.bundles)}개 · 네이티브 룰 {len(p.native)}개"
                        + (f" · 제외 {len(p.exclude)}" if p.exclude else ""))
                items.append((pid, f"{p.name}", desc))
        self.scan.set_profiles(items)

    # ------------------------------------------------------------------ 구성
    def _build_menu(self) -> None:
        mb = self.menuBar()
        m_file = mb.addMenu("파일")
        m_file.addAction("완전삭제 후 종료", self.close)
        m_asset = mb.addMenu("자산")
        m_asset.addAction("자산 추가", self._add_asset)
        m_asset.addAction("자산 가져오기(JSON)", self._import_assets)
        mb.addMenu("진단").addAction("새 진단 시작", self._start_scan)
        mb.addMenu("도구").addAction("지금 완전삭제", self._sanitize_now)
        mb.addMenu("도움말").addAction("정보", self._about)

        # 참조를 self 에 붙잡아 둔다. 지역변수로 두면 파이썬 GC 가 회수해 코너 위젯이 사라진다.
        self._menu_corner = QWidget(mb)
        cl = QHBoxLayout(self._menu_corner)
        cl.setContentsMargins(0, 0, 8, 0)
        cl.setSpacing(10)
        self.cred_lbl = QLabel("● 크리덴셜 잠김")
        self.cred_lbl.setStyleSheet("color:#8B949E")
        cl.addWidget(self.cred_lbl)
        wipe = QPushButton("완전삭제")
        wipe.setObjectName("danger")
        wipe.clicked.connect(self._sanitize_now)
        cl.addWidget(wipe)
        mb.setCornerWidget(self._menu_corner, Qt.Corner.TopRightCorner)

    def _build_body(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)

        side = QWidget()
        side.setObjectName("sidebar")
        sl = QVBoxLayout(side)
        sl.setContentsMargins(10, 10, 10, 10)
        sl.setSpacing(8)
        st = QLabel("자산")
        st.setObjectName("sidebar-title")
        sl.addWidget(st)
        self.filter = QLineEdit()
        self.filter.setClearButtonEnabled(True)
        self.filter.setPlaceholderText("필터 (이름·주소·그룹)")
        self.filter.textChanged.connect(self._refresh_assets)
        sl.addWidget(self.filter)
        self.tree = QTreeView()
        self.tree.setHeaderHidden(True)
        self.tree.setSelectionMode(QTreeView.SelectionMode.ExtendedSelection)
        self.model = AssetTreeModel()
        self.tree.setModel(self.model)
        self.tree.setItemDelegate(StatusDelegate())
        self.tree.doubleClicked.connect(self._edit_selected)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        sl.addWidget(self.tree, 1)
        brow = QHBoxLayout()
        add = QPushButton("+ 자산")
        imp = QPushButton("가져오기")
        add.clicked.connect(self._add_asset)
        imp.clicked.connect(self._import_assets)
        brow.addWidget(add)
        brow.addWidget(imp)
        sl.addLayout(brow)
        splitter.addWidget(side)

        self.tabs = QTabWidget()
        self.dashboard = DashboardPage()
        self.scan = ScanPage()
        self.result = ResultPage()
        self.manual = ManualBenchPage()
        # 탭 라벨은 폰트 의존 글리프를 쓰지 않는다(고객사 PC 폰트가 제각각). ▶ 는 맑은고딕에 있다.
        self.tabs.addTab(self.dashboard, "대시보드")
        self.tabs.addTab(self.scan, "▶ 진단")
        self.tabs.addTab(self.result, "결과")
        self.tabs.addTab(self.manual, "수동확인")
        self.rulepack = RulePackPage()
        self.rulepack.profiles_changed.connect(self._refresh_profiles)
        self.rulepack.import_requested.connect(self._import_rulepack)
        self.rulepack.pack_selected.connect(self._switch_rulepack)
        self.tabs.addTab(self.rulepack, "룰팩")
        pk_label = f"{self.pack.name} {self.pack.version}" if self.pack else "(없음)"
        self.settings = SettingsPage(self.ctx.config, self.ctx.workspace.layout,
                                     self._engine_version(), pk_label)
        self.settings.saved.connect(self._on_settings_saved)
        self.settings.sanitize_requested.connect(self._sanitize_now)
        self.tabs.addTab(self.settings, "설정")
        self.FIXED_TABS = self.tabs.count()          # 고정 탭은 닫히지 않는다
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)
        for i in range(self.FIXED_TABS):
            self.tabs.tabBar().setTabButton(i, self.tabs.tabBar().ButtonPosition.RightSide, None)

        # 브로드캐스트 툴바 (§7.4): 실수 위험이 커서 토글 + 대상 수 상시 표시
        self.bcast = QCheckBox("브로드캐스트")
        self.bcast.setToolTip("체크한 터미널 탭 전부에 같은 입력을 보냅니다")
        self.bcast_n = QLabel("")
        self.bcast_n.setObjectName("muted")
        self._tab_corner = QWidget(self.tabs)
        cl = QHBoxLayout(self._tab_corner)
        cl.setContentsMargins(4, 0, 8, 0)
        cl.addWidget(self.bcast)
        cl.addWidget(self.bcast_n)
        self.tabs.setCornerWidget(self._tab_corner, Qt.Corner.TopRightCorner)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 1080])
        splitter.setHandleWidth(1)
        self.setCentralWidget(splitter)

        self.dashboard.start_scan_requested.connect(self._start_scan)
        self.dashboard.filter_by_status.connect(self._jump_to_result_status)
        self.scan.start_requested.connect(self._run_scan)
        self.scan.cancel_requested.connect(self.controller.cancel)
        self.result.export_requested.connect(self._export)
        self.manual.verdict_saved.connect(self._save_verdict)

        self.sb_hosts = QLabel("")
        self.statusBar().addWidget(self.sb_hosts)
        pk = f"{self.pack.name} {self.pack.version}" if self.pack else "(룰팩 없음)"
        self.statusBar().addPermanentWidget(QLabel(f"룰팩 {pk} · 엔진 {self._engine_version()}"))

    def _wire_controller(self) -> None:
        c = self.controller
        c.scan_started.connect(lambda sid: self._set_scanning(True))
        c.scan_progress.connect(self._on_scan_progress)
        c.scan_finished.connect(self._on_scan_finished)
        c.host_started.connect(lambda hid: self.model.set_state(hid, "running"))
        c.host_stage.connect(self._on_host_stage)
        c.host_progress.connect(self._on_host_progress)
        c.host_result.connect(self._on_host_result)
        c.host_failed.connect(lambda hid, msg: self.model.set_state(hid, "failed"))

    # --------------------------------------------------------------- 자산 CRUD
    def _refresh_assets(self) -> None:
        hosts = self.ctx.assets.all()
        self.model.rebuild(hosts, self.filter.text())
        self.tree.expandAll()
        self.sb_hosts.setText(f"자산 {len(hosts)}대")

    def _selected_hosts(self) -> list[Host]:
        ids = []
        for idx in self.tree.selectionModel().selectedIndexes():
            hid = idx.data(HOST_ID_ROLE)
            if hid:
                ids.append(hid)
        hosts = [self.ctx.assets.get(h) for h in ids]
        return [h for h in hosts if h]

    def _param_hints(self) -> list[dict]:
        """룰팩의 모든 번들이 선언한 파라미터(중복 제거) — 자산 편집 힌트용."""
        seen: dict[str, dict] = {}
        for b in (self.pack.bundles.values() if self.pack else []):
            for p in b.params:
                seen.setdefault(str(p.get("name")), {**p, "bundle": b.id})
        return list(seen.values())

    def _add_asset(self) -> None:
        dlg = AssetEditDialog(parent=self, param_hints=self._param_hints())
        if dlg.exec():
            self.ctx.assets.upsert(dlg.host())
            self._refresh_assets()

    def _edit_selected(self, index) -> None:  # noqa: ANN001
        hid = index.data(HOST_ID_ROLE)
        if not hid:
            return
        host = self.ctx.assets.get(hid)
        if not host:
            return
        dlg = AssetEditDialog(host, parent=self, param_hints=self._param_hints())
        if dlg.exec():
            self.ctx.assets.upsert(dlg.host())
            self._refresh_assets()

    def _tree_menu(self, pos) -> None:  # noqa: ANN001
        from PySide6.QtWidgets import QMenu
        idx = self.tree.indexAt(pos)
        hid = idx.data(HOST_ID_ROLE) if idx.isValid() else None
        m = QMenu(self)
        if hid:
            host = self.ctx.assets.get(hid)
            if host:
                m.addAction("터미널 열기", lambda: self._open_terminal(host))
                m.addAction("파일 브라우저 열기", lambda: self._open_sftp(host))
                m.addSeparator()
                m.addAction("▶ 이 호스트 진단", self._start_scan)
                m.addAction("편집", lambda: self._edit_selected(idx))
                m.addAction("삭제", lambda: self._delete_host(host))
                m.addSeparator()
        m.addAction("+ 자산 추가", self._add_asset)
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _delete_host(self, host: Host) -> None:
        if QMessageBox.question(self, "자산 삭제", f"{host.label} ({host.address}) 을 삭제할까요?") \
                == QMessageBox.StandardButton.Yes:
            self.ctx.assets.delete(host.host_id)
            self._refresh_assets()

    # ------------------------------------------------------------ 터미널 · SFTP
    def _ensure_cred(self, host: Host):  # noqa: ANN202
        """세션에 없으면 입력받는다. 취소 시 None."""
        if self.ctx.creds.is_locked:
            self.ctx.creds.unlock()
        cred = self.ctx.creds.get(host.cred_id)
        if cred is None:
            dlg = CredPromptDialog(host.cred_id, host.username, parent=self)
            if not dlg.exec():
                return None
            self.ctx.creds.put(dlg.credential())
            cred = self.ctx.creds.get(host.cred_id)
            self._update_cred_label()
        return cred

    def _open_terminal(self, host: Host) -> None:
        cred = self._ensure_cred(host)
        if cred is None:
            return
        if not self._notice_shown:
            QMessageBox.information(self, "터미널 보안 경계", TERMINAL_NOTICE)
            self._notice_shown = True
        page = TerminalPage(host, cred, self.controller.host_key_bridge.ask,
                            self.ctx.workspace.layout.logs / "terminal",
                            record=bool(self.ctx.config.get("terminal_recording", True)))
        page.broadcast_input.connect(lambda b, src=page: self._broadcast(b, src))
        page.broadcast.toggled.connect(self._update_bcast_label)
        self._terminals.append(page)
        i = self.tabs.addTab(page, f"터미널 · {host.label}")
        self.tabs.setCurrentIndex(i)
        self._update_bcast_label()

    def _open_sftp(self, host: Host) -> None:
        cred = self._ensure_cred(host)
        if cred is None:
            return
        page = SftpPage(host, cred, self.controller.host_key_bridge.ask, self.ctx.workspace.layout)
        self._sftps.append(page)
        i = self.tabs.addTab(page, f"파일 · {host.label}")
        self.tabs.setCurrentIndex(i)

    def _broadcast(self, data: bytes, src: TerminalPage) -> None:
        if not self.bcast.isChecked():
            return
        for t in self._terminals:
            if t is not src and t.broadcast.isChecked():
                t.send(data)

    def _update_bcast_label(self) -> None:
        n = sum(1 for t in self._terminals if t.broadcast.isChecked())
        self.bcast_n.setText(f"대상 {n}개 탭" if n else "")

    def _close_tab(self, i: int) -> None:
        if i < self.FIXED_TABS:
            return
        w = self.tabs.widget(i)
        self.tabs.removeTab(i)
        if isinstance(w, TerminalPage):
            w.shutdown()
            self._terminals.remove(w)
            self._update_bcast_label()
        elif isinstance(w, SftpPage):
            w.shutdown()
            self._sftps.remove(w)
        w.deleteLater()

    def _shutdown_sessions(self) -> None:
        """터미널·SFTP 세션을 전부 닫는다. 로그 파일 핸들이 sanitize 를 막지 않게 먼저 호출."""
        for t in list(self._terminals):
            t.shutdown()
        for s in list(self._sftps):
            s.shutdown()
        for i in range(self.tabs.count() - 1, self.FIXED_TABS - 1, -1):
            w = self.tabs.widget(i)
            self.tabs.removeTab(i)
            w.deleteLater()
        self._terminals.clear()
        self._sftps.clear()
        self._update_bcast_label()

    def _on_settings_saved(self, values: dict) -> None:
        self.ctx.config.update(values)
        self.scan.concurrency.setValue(int(values.get("concurrency", 5)))
        self.scan.timeout.setValue(int(values.get("default_timeout", 1800)))
        self.statusBar().showMessage("설정 저장됨 (config.json)", 3000)

    def _import_assets(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "자산 가져오기", "", "JSON (*.json)")
        if not path:
            return
        import json
        try:
            data = json.loads(open(path, encoding="utf-8").read())
            rows = data if isinstance(data, list) else [data]
            for row in rows:
                self.ctx.assets.upsert(Host.model_validate(row))
            self._refresh_assets()
            QMessageBox.information(self, "가져오기", f"{len(rows)}건 반영")
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "가져오기 실패", str(e))

    # ------------------------------------------------------------------ 스캔
    def _start_scan(self) -> None:
        hosts = self._selected_hosts()
        if not hosts:
            QMessageBox.information(self, "진단", "사이드바에서 대상 호스트를 선택하세요.")
            return
        self.scan.set_targets(hosts)
        self._pending_hosts = hosts
        self.tabs.setCurrentWidget(self.scan)

    def _run_scan(self, concurrency: int, timeout: int) -> None:
        hosts = getattr(self, "_pending_hosts", None) or self._selected_hosts()
        if not hosts:
            return
        # 세션에 없는 크리덴셜만 입력받는다. 같은 cred_id 는 한 번만.
        needed: dict[str, Host] = {}
        for h in hosts:
            if h.cred_id not in self.ctx.creds.ids() and h.cred_id not in needed:
                needed[h.cred_id] = h
        if self.ctx.creds.is_locked:
            self.ctx.creds.unlock()
        for cred_id, h in needed.items():
            dlg = CredPromptDialog(cred_id, h.username, parent=self)
            if not dlg.exec():
                QMessageBox.information(self, "진단", "크리덴셜 입력이 취소되어 중단합니다.")
                return
            self.ctx.creds.put(dlg.credential())
        self._update_cred_label()

        if self.pack is None or not self.pack.runnable:
            QMessageBox.warning(self, "룰팩", "실행 가능한 룰팩이 없습니다. 룰팩 탭의 문제 목록을 확인하세요.")
            return
        pid = self.scan.current_profile()
        profile = self.pack.profiles.get(pid or "")
        if profile is None:
            QMessageBox.information(self, "진단", "프로파일을 선택하세요.")
            return
        jobs = []
        for h in hosts:
            cred = self.ctx.creds.get(h.cred_id)
            if cred is None:
                continue
            # 호스트별 파라미터(TOMCAT_HOME 등)가 다르므로 job 도 호스트별로 만든다
            jobs.append((h, cred, build_job(self.pack, profile, timeout=timeout, host_params=h.params)))

        self._scan_id = new_scan_id()
        self.ctx.results.start_scan(ScanResult(
            scan_id=self._scan_id, engine_version=self._engine_version(),
            rule_pack_version=f"{self.pack.name} {self.pack.version}", profile=profile.id,
            started_at=datetime.now(),
        ))
        self.scan.begin([h for h, _, _ in jobs])
        self._stages.clear()
        self._pcts.clear()
        self.controller.start(
            jobs, scan_id=self._scan_id, store=self.ctx.results,
            local_root=self.ctx.workspace.layout.scan_dir(self._scan_id),
            concurrency=concurrency,
        )

    def _on_host_stage(self, host_id: str, stage: str) -> None:
        self._stages[host_id] = stage
        self.scan.on_stage(host_id, stage)
        self._refresh_running()

    def _on_host_progress(self, host_id: str, done: int, total: int) -> None:
        self._pcts[host_id] = int(done / total * 100) if total else 0
        self.scan.on_progress(host_id, done, total)
        self._refresh_running()

    def _on_host_result(self, host_id: str, host: HostResult) -> None:
        self.scan.on_result(host_id, host)
        state = "warn" if (host.error or any(r.status is Status.FAIL for r in host.results)) else "connected"
        self.model.set_state(host_id, state)
        # 트리 배지 요약 되쓰기
        stored = self.ctx.assets.get(host_id)
        if stored:
            stored.last_summary = {k.value: v for k, v in host.summary().items()}
            stored.last_scan_id = self._scan_id
            self.ctx.assets.upsert(stored)
        self._stages[host_id] = "완료"
        self._pcts[host_id] = 100
        self._refresh_running()

    def _on_scan_progress(self, done: int, total: int) -> None:
        self.sb_hosts.setText(f"진단 {done}/{total}")

    def _on_scan_finished(self, scan: ScanResult) -> None:
        self._set_scanning(False)
        self._unexported = True
        self.scan.finished()
        self.result.load(scan)
        self.manual.load(scan)
        self._refresh_dashboard(scan)
        self._refresh_assets()
        QMessageBox.information(
            self, "진단 완료",
            f"{scan.scan_id} — 호스트 {len(scan.hosts)}대 완료. 결과 탭에서 확인하세요.",
        )

    def _refresh_running(self) -> None:
        rows = []
        for hid, stage in self._stages.items():
            if stage == "완료":
                continue
            host = self.ctx.assets.get(hid)
            rows.append((host.label if host else hid, stage, self._pcts.get(hid, 0)))
        self.dashboard.set_progress(rows)

    # ---------------------------------------------------------------- 호스트키
    def _on_host_key(self, host: str, key_type: str, fp: str) -> None:
        dlg = HostKeyDialog(host, key_type, fp, parent=self)
        self.controller.host_key_bridge.answer(bool(dlg.exec()))

    # ---------------------------------------------------------------- 수동확인
    def _save_verdict(self, host_id: str, rule_id: str, status: str, note: str, batch: bool) -> None:
        if not self._scan_id:
            return
        targets = [(host_id, rule_id)]
        if batch:
            scan = self.ctx.results.load_scan(self._scan_id)
            if scan:
                for h in scan.hosts:
                    for r in h.results:
                        if r.rule_id == rule_id and r.status is Status.UNKNOWN and h.host_id != host_id:
                            targets.append((h.host_id, rule_id))
        for hid, rid in targets:
            self.ctx.results.set_verdict(self._scan_id, hid, rid, status, note)
        scan = self.ctx.results.load_scan(self._scan_id)
        self.manual.load(scan)
        self.result.load(scan)
        self._refresh_dashboard(scan)
        self._unexported = True

    # ------------------------------------------------------------------ 내보내기
    def _export(self, fmt: str) -> None:
        if not self._scan_id:
            QMessageBox.information(self, "내보내기", "내보낼 진단 결과가 없습니다.")
            return
        scan = self.ctx.results.load_scan(self._scan_id)
        if not scan:
            return
        pending = sum(1 for h in scan.hosts for r in h.results if r.status is Status.UNKNOWN)
        if pending and QMessageBox.question(
            self, "미판정 항목", f"수동확인 미판정 {pending}건이 남았습니다. 그래도 내보낼까요?"
        ) != QMessageBox.StandardButton.Yes:
            return
        ext = "xlsx" if fmt == "xlsx" else "html"
        default = str(self.ctx.workspace.layout.exports / f"{scan.scan_id}.{ext}")
        path, _ = QFileDialog.getSaveFileName(self, "내보내기", default, f"*.{ext}")
        if not path:
            return
        from pathlib import Path
        try:
            rem = self.pack.remediation_map() if self.pack else {}
            if fmt == "xlsx":
                xlsx_report.build(scan, Path(path), rem)
            else:
                html_report.build(scan, Path(path), rem)
            self._unexported = False
            QMessageBox.information(self, "내보내기", f"저장됨: {path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "내보내기 실패", str(e))

    # ------------------------------------------------------------------ 대시보드
    def _refresh_dashboard(self, scan: ScanResult | None = None) -> None:
        if scan is None and self._scan_id:
            scan = self.ctx.results.load_scan(self._scan_id)
        if scan is None:
            recent = self.ctx.results.list_scans()
            if recent:
                scan = self.ctx.results.load_scan(recent[0][0])
        summ = scan.summary() if scan else {s: 0 for s in Status}
        self.dashboard.update_counts(summ)
        sev = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        host_rows: list[tuple[str, dict[Status, int]]] = []
        if scan:
            for h in scan.hosts:
                host_rows.append((h.hostname, h.summary()))
                for r in h.results:
                    if r.status is Status.FAIL and r.severity:
                        sev[r.severity] += 1
        self.dashboard.update_severity(sev[Severity.HIGH], sev[Severity.MEDIUM], sev[Severity.LOW])
        self.dashboard.update_hosts(host_rows)
        self.dashboard.set_progress([])
        self.dashboard.set_recent(self.ctx.results.list_scans())

    def _jump_to_result_status(self, status: Status) -> None:
        self.result.set_status_filter(status)
        self.tabs.setCurrentWidget(self.result)

    # ------------------------------------------------------------------ 상태
    def _set_scanning(self, on: bool) -> None:
        self._scanning = on

    def _update_cred_label(self) -> None:
        n = len(self.ctx.creds.ids()) if not self.ctx.creds.is_locked else 0
        self.cred_lbl.setText(f"● 크리덴셜 {n}건 (메모리)" if n else "● 크리덴셜 잠김")
        self.cred_lbl.setStyleSheet("color:#3FB950" if n else "color:#8B949E")

    def _engine_version(self) -> str:
        from infraguard import ENGINE_VERSION
        return ENGINE_VERSION

    # ------------------------------------------------------------------ 정리·종료
    def _sanitize_now(self) -> None:
        if QMessageBox.question(
            self, "완전삭제", "작업공간(assets.db·결과·로그)을 모두 삭제합니다. 계속할까요?"
        ) != QMessageBox.StandardButton.Yes:
            return
        self._shutdown_sessions()
        self.ctx.creds.lock()
        rep = self.ctx.workspace.sanitize()
        if rep.clean:
            QMessageBox.information(self, "완전삭제", "삭제 완료. 잔류물 없음.")
        else:
            QMessageBox.warning(
                self, "잔류물 발견",
                "다음 경로가 남았습니다:\n" + "\n".join(rep.leftovers + rep.errors),
            )
        self.ctx.workspace.create()
        self._scan_id = None
        self._unexported = False
        self.result.load(None)
        self.manual.load(None)
        self._refresh_assets()
        self._refresh_dashboard()
        self.settings.refresh_usage()

    def closeEvent(self, event) -> None:  # noqa: N802
        gate = exit_gate(ExitState(scanning=self._scanning, unexported=self._unexported))
        if gate == CONFIRM_SCANNING:
            if QMessageBox.question(
                self, "종료", "진단이 진행 중입니다. 중단하고 종료할까요?"
            ) != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.controller.cancel()
        elif gate == WARN_UNEXPORTED:
            resp = QMessageBox.question(
                self, "종료", "아직 내보내지 않은 결과가 있습니다.\n"
                "삭제하고 종료할까요? (아니오=취소)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if resp != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self._shutdown_sessions()
        self.ctx.creds.lock()
        rep = self.ctx.workspace.sanitize()
        if not rep.clean:
            QMessageBox.warning(
                self, "잔류물", "삭제되지 않은 경로:\n" + "\n".join(rep.leftovers + rep.errors),
            )
        event.accept()

    def _about(self) -> None:
        QMessageBox.information(
            self, "InfraGuard",
            f"InfraGuard {self._engine_version()}\n인프라 진단 실행·표준화 플랫폼\n폐쇄망 전용 · 무잔류",
        )
