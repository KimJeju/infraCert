"""증적 마스킹 회귀 — 결과가 고객사 밖으로 나가므로 실패는 사고다."""
import pytest
from infraguard.result.masking import find_unmasked, mask

CASES = [
    ("shadow_sha512", "root:$6$abc123XY$Zq0123456789abcdefghijklmnop:19000:0:99999:7:::", "$6$"),
    ("shadow_md5",    "u:$1$abcd1234$XyZ9876543210abcdefgh:18000:0:99999",                "$1$"),
    ("private_key",   "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow"),
    ("aws_key",       "id = AKIAIOSFODNN7EXAMPLE",                                        "AKIAIOSFODNN7EXAMPLE"),
    ("jdbc",          "jdbc:oracle:thin:@h:1521/O?user=s&password=tiger123",              "tiger123"),
    ("kv_password",   "password=Adm1n!Pass",                                              "Adm1n!Pass"),
    ("kv_token",      "token: eyJhbGciOiJIUzI1NiJ9",                                      "eyJhbGciOiJIUzI1NiJ9"),
    ("snmp_com2sec",  "com2sec notConfigUser default publicSecret",                       "publicSecret"),
    ("snmp_ro",       "rocommunity mysecret123 10.0.0.0/8",                               "mysecret123"),
    ("basic_auth",    "Authorization: Basic YWRtaW46cGFzc3dvcmQ=",                        "YWRtaW46cGFzc3dvcmQ="),
]

@pytest.mark.parametrize("name,raw,secret", CASES, ids=[c[0] for c in CASES])
def test_secret_removed(name, raw, secret):
    out = mask(raw)
    assert secret not in out, f"{name}: 민감값이 남았다"

@pytest.mark.parametrize("name,raw,_s", CASES, ids=[c[0] for c in CASES])
def test_idempotent(name, raw, _s):
    once = mask(raw)
    assert mask(once) == once, f"{name}: 마스킹이 멱등하지 않다"
    assert find_unmasked(once) == [], f"{name}: 잔존 패턴 {find_unmasked(once)}"

def test_benign_text_untouched():
    ok = "PASS_MIN_LEN=8 (/etc/login.defs:25) 양호"
    assert mask(ok) == ok

def test_none_and_empty():
    assert mask(None) is None
    assert mask("") == ""
