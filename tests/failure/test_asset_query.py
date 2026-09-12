"""자산 쿼리(동적 그룹) — key=value AND, OR(,), 부정(!=), 자유 단어 부분일치, 트리 모델 연동."""

from __future__ import annotations

import os

from infraguard.assets import query
from infraguard.assets.models import Host

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

H = [
    Host(host_id="1", name="WEB-01", address="10.10.1.11", platform="linux", project="A은행", group="WEB",
         environment="PROD", criticality="CRITICAL", role="WEB", tags=["dmz"]),
    Host(host_id="2", name="DEV-WEB", address="10.30.1.11", platform="linux", project="A은행", group="WEB",
         environment="DEV", criticality="LOW", role="WEB"),
    Host(host_id="3", name="AD01", address="10.10.5.51", platform="windows", project="A은행", group="Windows",
         environment="PROD", criticality="CRITICAL", role="AD"),
    Host(host_id="4", name="wsl", address="127.0.0.1", platform="linux", project="테스트", group="Linux",
         environment="TEST", criticality="HIGH"),
]


def ids(text: str) -> list[str]:
    return [h.host_id for h in query.filter_hosts(H, text)]


def test_query_and_or_not_and_words() -> None:
    assert ids("") == ["1", "2", "3", "4"]
    assert ids("os=linux env=PROD") == ["1"]
    assert ids("crit=CRITICAL,HIGH") == ["1", "3", "4"]
    assert ids("env!=PROD") == ["2", "4"]
    assert ids("tag=dmz") == ["1"]
    assert ids("A은행 WEB") == ["1", "2"]                 # 자유 단어 = 부분일치 AND
    assert ids("os=linux 은행") == ["1", "2"]
    assert ids("role=web project=테스트") == []
    q = query.parse("bogus=1 os=linux")
    assert q.errors and ids("bogus=1 os=linux") == ["1", "2", "4"]   # 모르는 키는 무시하고 사유만 남긴다
    assert ids('"DEV-WEB"') == ["2"]


def test_tree_model_uses_query(qtbot) -> None:  # noqa: ANN001
    from infraguard.ui.models_qt import HOST_ID_ROLE, AssetTreeModel
    m = AssetTreeModel()
    m.rebuild(H, "env=PROD crit=CRITICAL")
    found = []

    def walk(it):  # noqa: ANN001,ANN202
        for i in range(it.rowCount()):
            c = it.child(i)
            if c.data(HOST_ID_ROLE):
                found.append(c.data(HOST_ID_ROLE))
            walk(c)
    walk(m.invisibleRootItem())
    assert sorted(found) == ["1", "3"]
