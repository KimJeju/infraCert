"""평문 크리덴셜 유출 경로 차단."""
import copy, io, json, logging, pickle
import pytest
from infraguard.credentials.secret import Secret
from infraguard.credentials.session import Credential, CredentialSession

PLAIN = "S3cr3t!Passw0rd"

def test_repr_str_format_mask():
    s = Secret(PLAIN)
    for rendered in (repr(s), str(s), f"{s}", "%s" % s, "{}".format(s), f"{s!r}", f"{s!s}"):
        assert PLAIN not in rendered

def test_pickle_blocked():
    with pytest.raises(TypeError):
        pickle.dumps(Secret(PLAIN))

def test_credential_pickle_blocked():
    with pytest.raises(TypeError):
        pickle.dumps(Credential(cred_id="c", username="root", password=Secret(PLAIN)))

def test_session_pickle_blocked():
    s = CredentialSession()
    s.put(Credential(cred_id="c", username="root", password=Secret(PLAIN)))
    with pytest.raises(TypeError):
        pickle.dumps(s)

def test_json_blocked():
    with pytest.raises(TypeError):
        json.dumps({"pw": Secret(PLAIN)})

def test_deepcopy_still_masked():
    assert PLAIN not in repr(copy.deepcopy(Secret(PLAIN)))

def test_logging_does_not_leak():
    buf = io.StringIO()
    lg = logging.getLogger("leaktest")
    lg.handlers.clear()
    lg.addHandler(logging.StreamHandler(buf))
    lg.setLevel(logging.DEBUG)
    cred = Credential(cred_id="c", username="root", password=Secret(PLAIN))
    lg.info("cred=%s pw=%s dict=%r", cred, cred.password, {"p": cred.password})
    assert PLAIN not in buf.getvalue()

def test_reveal_is_the_only_exit():
    assert Secret(PLAIN).reveal() == PLAIN

def test_reveal_confined_to_transport():
    """reveal() 호출 지점이 transport 계층 밖으로 새지 않았는지."""
    import pathlib, re
    src = pathlib.Path(__file__).resolve().parents[2] / "src" / "infraguard"
    allowed = {"transport"}
    offenders = []
    for f in src.rglob("*.py"):
        rel = f.relative_to(src)
        if rel.parts[0] in allowed or f.name == "secret.py":
            continue
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if ".reveal()" in line:
                offenders.append(f"{rel}:{i}")
    assert not offenders, f"transport 밖에서 reveal() 호출: {offenders}"

def test_session_lock_discards():
    s = CredentialSession()
    s.put(Credential(cred_id="c", username="root", password=Secret(PLAIN)))
    s.lock()
    assert s.is_locked
    with pytest.raises(RuntimeError):
        s.get("c")
