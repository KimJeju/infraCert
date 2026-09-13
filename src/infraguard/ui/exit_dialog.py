"""세션 종료 다이얼로그 — 파괴적 동작(완전삭제)은 상시 버튼이 아니라 여기서만, 체크박스로 명시하고 실행한다."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class SessionEndDialog(QDialog):
    def __init__(self, *, unexported: bool, default_wipe: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("세션 종료")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<b>세션을 종료하시겠습니까?</b>"))
        if unexported:
            w = QLabel("⚠ 아직 내보내지 않은 결과가 있습니다. 보고서 → 세션 내보내기(zip) 로 남길 수 있습니다.")
            w.setStyleSheet("color:#D29922")
            w.setWordWrap(True)
            lay.addWidget(w)
        self.wipe_ws = QCheckBox("작업공간 삭제 (자산·결과·로그)")
        self.wipe_tmp = QCheckBox("임시 파일 삭제 (산출물·뷰어 사본)")
        self.wipe_cred = QCheckBox("크리덴셜 삭제 (메모리)")
        self.wipe_ws.setChecked(default_wipe)
        self.wipe_tmp.setChecked(True)
        self.wipe_cred.setChecked(True)
        self.wipe_cred.setEnabled(False)          # 항상 삭제 — 끌 수 없다
        for cb in (self.wipe_ws, self.wipe_tmp, self.wipe_cred):
            lay.addWidget(cb)
        note = QLabel("작업공간을 지우지 않으면 다음 실행에 결과·자산이 남습니다(자기 PC 검토용). 고객사 PC 에서는 켜 두십시오.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(note)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton("취소")
        cancel.clicked.connect(self.reject)
        self.ok = QPushButton("완전 삭제 후 종료" if default_wipe else "종료")
        self.ok.setObjectName("danger" if default_wipe else "primary")
        self.ok.clicked.connect(self.accept)
        self.wipe_ws.toggled.connect(lambda on: (self.ok.setText("완전 삭제 후 종료" if on else "종료"),
                                                 self.ok.setObjectName("danger" if on else "primary"),
                                                 self.ok.style().unpolish(self.ok), self.ok.style().polish(self.ok)))
        row.addWidget(cancel)
        row.addWidget(self.ok)
        lay.addLayout(row)

    @property
    def wipe_workspace(self) -> bool:
        return self.wipe_ws.isChecked()

    @property
    def wipe_temp(self) -> bool:
        return self.wipe_tmp.isChecked()
