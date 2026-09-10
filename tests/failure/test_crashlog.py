"""크래시 로그에 크리덴셜이 남지 않는다(아키텍처 §9). 파일은 workspace 안에만."""
import sys

from infraguard import crashlog

PLAIN_HASH = "root:$6$abcdefgh$ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:19000"
AWS = "AKIAIOSFODNN7EXAMPLE"


def _raise_with(msg: str):
    try:
        raise RuntimeError(msg)
    except RuntimeError:
        return sys.exc_info()


def test_crash_log_is_written_and_masked(tmp_path):
    log = tmp_path / "ws" / "logs" / "crash.log"
    notified = []
    old = sys.excepthook
    try:
        hook = crashlog.install(log, notify=notified.append)
        assert sys.excepthook is hook
        hook(*_raise_with(f"failed while reading {PLAIN_HASH} key={AWS}"))
    finally:
        sys.excepthook = old
    text = log.read_text(encoding="utf-8")
    assert "RuntimeError" in text and "failed while reading" in text
    assert "$6$" not in text and AWS not in text
    assert "***HASH***" in text
    assert notified == [str(log)]


def test_hook_survives_unwritable_path(tmp_path):
    bad = tmp_path / "file_not_dir"
    bad.write_text("x")
    old = sys.excepthook
    try:
        hook = crashlog.install(bad / "crash.log", notify=None)   # 부모가 파일 → mkdir 실패
        hook(*_raise_with("boom"))                                 # 예외를 다시 던지지 않는다
    finally:
        sys.excepthook = old
