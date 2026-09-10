"""터미널 기록 — 비밀번호가 로그에 남지 않는다(§7.3, §14)."""
from pathlib import Path

from infraguard.audit.terminal_recorder import TerminalRecorder


class _Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def _rec(tmp_path: Path):
    clk = _Clock()
    r = TerminalRecorder(tmp_path / "t.log", clock=clk, host_label="web01")
    return r, clk


def _type(r: TerminalRecorder, clk: _Clock, s: str, echo: bool = True, dt: float = 0.01):
    for ch in s:
        r.on_input(ch.encode())
        clk.t += dt
        if echo:
            r.on_output(ch.encode())


def test_sudo_prompt_masks_next_input_line(tmp_path):
    r, clk = _rec(tmp_path)
    _type(r, clk, "sudo -l")
    r.on_input(b"\r")
    r.on_output(b"\r\n[sudo] password for igtest: ")
    _type(r, clk, "S3cr3t!Passw0rd", echo=False)
    r.on_input(b"\r")
    r.on_output(b"\r\nMatching Defaults entries\r\n")
    r.close()
    log = (tmp_path / "t.log").read_text(encoding="utf-8")
    assert "S3cr3t" not in log
    assert "[IN] sudo -l" in log
    assert "[IN] ***" in log
    assert r.masked_inputs == 1


def test_echo_absence_masks_even_without_prompt(tmp_path):
    r, clk = _rec(tmp_path)
    # 프롬프트는 못 알아봤지만(외국어 프롬프트) 에코가 없고 200ms 넘게 지남
    r.on_output(b"Mot de passe : ")
    _type(r, clk, "hunter2", echo=False, dt=0.1)
    r.on_input(b"\r")
    r.close()
    log = (tmp_path / "t.log").read_text(encoding="utf-8")
    assert "hunter2" not in log and "[IN] ***" in log


def test_normal_command_is_recorded(tmp_path):
    r, clk = _rec(tmp_path)
    r.on_output(b"igtest@web01:~$ ")
    _type(r, clk, "ls -la /etc")
    r.on_input(b"\r")
    r.on_output(b"\r\ntotal 1\r\n")
    r.close()
    log = (tmp_path / "t.log").read_text(encoding="utf-8")
    assert "[IN] ls -la /etc" in log
    assert "[OUT] total 1" in log


def test_shadow_output_is_masked(tmp_path):
    r, clk = _rec(tmp_path)
    _type(r, clk, "cat /etc/shadow")
    r.on_input(b"\r")
    r.on_output(b"\r\nroot:$6$abcdefgh$ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:19000:0:99999:7:::\r\n")
    r.close()
    log = (tmp_path / "t.log").read_text(encoding="utf-8")
    assert "$6$" not in log and "***HASH***" in log


def test_pasted_password_is_masked(tmp_path):
    """붙여넣기(한 덩어리, 시간 경과 없음) + 패턴에 없는 프롬프트 — 그래도 마스킹돼야 한다.

    2026-09-10 리뷰: Enter 즉시판정은 이 케이스에서 평문을 남겼다.
    """
    r, clk = _rec(tmp_path)
    r.on_output(b"Enter your key> ")           # PROMPT_PATTERNS 에 없음
    r.on_input(b"Hunter2!Secret")              # 붙여넣기 — 한 번에
    r.on_input(b"\r")                          # 즉시 Enter
    r.on_output(b"\r\nAccess granted\r\n")     # 에코 없음
    r.close()
    log = (tmp_path / "t.log").read_text(encoding="utf-8")
    assert "Hunter2!Secret" not in log
    assert "[IN] ***" in log and r.masked_inputs == 1


def test_pasted_command_is_still_recorded(tmp_path):
    """붙여넣은 '명령어' 는 에코가 돌아오므로 평문으로 남아야 한다(감사 가치 유지)."""
    r, clk = _rec(tmp_path)
    r.on_output(b"igtest@web01:~$ ")
    r.on_input(b"ls -la /etc")                 # 붙여넣기
    r.on_output(b"ls -la /etc")                # 터미널 에코
    r.on_input(b"\r")
    r.on_output(b"\r\ntotal 1\r\n")
    r.close()
    log = (tmp_path / "t.log").read_text(encoding="utf-8")
    assert "[IN] ls -la /etc" in log and r.masked_inputs == 0


def test_pasted_command_echo_after_enter_is_recorded(tmp_path):
    """에코가 Enter 뒤에 늦게 와도(지연판정) 명령어는 평문으로 확정된다."""
    r, clk = _rec(tmp_path)
    r.on_output(b"$ ")
    r.on_input(b"uname -a\r")                  # 에코보다 Enter 가 먼저 도착
    r.on_output(b"uname -a\r\nLinux web01\r\n")
    r.close()
    log = (tmp_path / "t.log").read_text(encoding="utf-8")
    assert "[IN] uname -a" in log and "[IN] ***" not in log


def test_gt_terminated_and_pin_prompts_are_recognized(tmp_path):
    """':' 로 안 끝나는 프롬프트(장비 CLI)·PIN/OTP/인증번호도 패턴으로 잡는다."""
    for prompt in (b"Password> ", b"Enter PIN? ", b"OTP code: ", b"\xec\x9d\xb8\xec\xa6\x9d\xeb\xb2\x88\xed\x98\xb8: "):
        r, clk = _rec(tmp_path)
        r.on_output(prompt)
        _type(r, clk, "1234", echo=False)
        r.on_input(b"\r")
        r.close()
        assert "[IN] ***" in (tmp_path / "t.log").read_text(encoding="utf-8"), prompt
        (tmp_path / "t.log").unlink()


def test_ansi_sequences_do_not_break_prompt_detection(tmp_path):
    r, clk = _rec(tmp_path)
    r.on_output(b"\x1b[1;32m[sudo] password for igtest:\x1b[0m ")
    _type(r, clk, "pw", echo=False)
    r.on_input(b"\r")
    r.close()
    assert "[IN] ***" in (tmp_path / "t.log").read_text(encoding="utf-8")
