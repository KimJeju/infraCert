"""원격 삭제 경로 안전장치 — rm -rf 사고 방지."""
import pytest
from infraguard.transport.ssh import _decode, _safe_remote_path

@pytest.mark.parametrize("p", ["/", "/etc", "/usr", "/var", "/tmp", "/home", "/root",
                               "", "relative/path", "/a/../../etc", "../x"])
def test_dangerous_paths_refused(p):
    assert not _safe_remote_path(p)

@pytest.mark.parametrize("p", ["/tmp/infraguard-abc123", "/var/tmp/ig-1/result",
                               "/tmp/infraguard-abc123.tar.gz"])
def test_workdir_paths_allowed(p):
    assert _safe_remote_path(p)

def test_decode_fallback():
    assert _decode("양호".encode("utf-8"))[0] == "양호"
    assert _decode("양호".encode("cp949"))[0] == "양호"
    text, err = _decode(b"\xff\xfe\xff\xfe")
    assert err is True
