"""config.json 에 크리덴셜이 없어야 하고(§10·§14), 종료 관문 우선순위(§11)."""
from infraguard import config
from infraguard.ui.exit_flow import (
    CONFIRM_SCANNING,
    PROCEED,
    WARN_UNEXPORTED,
    ExitState,
    exit_gate,
)


def test_config_strips_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "config_path", lambda: tmp_path / "config.json")
    config.save({
        "concurrency": 8,
        "password": "hunter2", "username": "root", "host": "10.0.0.1",
        "bastion_host": "1.2.3.4", "api_key": "AKIA...", "token": "x",
    })
    raw = (tmp_path / "config.json").read_text(encoding="utf-8")
    for bad in ("hunter2", "root", "10.0.0.1", "AKIA", "password", "username", "host", "token"):
        assert bad not in raw, f"config 에 금지값이 남음: {bad}"
    loaded = config.load()
    assert loaded["concurrency"] == 8
    assert "password" not in loaded and "host" not in loaded


def test_exit_gate_priority():
    # 진행 중 진단이 최우선
    assert exit_gate(ExitState(scanning=True, unexported=True)) == CONFIRM_SCANNING
    assert exit_gate(ExitState(scanning=True, unexported=False)) == CONFIRM_SCANNING
    # 그다음 미반출 경고
    assert exit_gate(ExitState(scanning=False, unexported=True)) == WARN_UNEXPORTED
    # 둘 다 없으면 진행
    assert exit_gate(ExitState(scanning=False, unexported=False)) == PROCEED


def test_host_model_holds_no_secret():
    from infraguard.assets.models import Host
    dumped = Host(host_id="H1", name="w", address="10.0.0.1").model_dump()
    for bad in ("password", "secret", "passphrase", "token"):
        assert bad not in dumped


def test_every_default_key_survives_save(tmp_path, monkeypatch):
    """DEFAULTS 의 키가 금지 부분문자열(ip·key·host…)에 걸리면 조용히 안 저장된다(09-12 wipe_on_exit 가 'ip' 에 걸림)."""
    from infraguard import config
    monkeypatch.setattr(config, "config_path", lambda: tmp_path / "config.json")
    config.save(dict(config.DEFAULTS))
    saved = config.load()
    assert set(config.DEFAULTS) <= set(saved), sorted(set(config.DEFAULTS) - set(saved))
