"""파서 실패 케이스 — 추측하지 않고 실패한다."""
from infraguard.parsing.legacy_csv import parse_csv_bytes
from infraguard.result.engine import normalize
from infraguard.core.status import Status

H1 = "항목코드,점검항목,중요도,결과,코멘트\n"

def test_unknown_header_fails_loudly():
    r = parse_csv_bytes(b"a,b,c\n1,2,3\n", artifact="x.csv")
    assert not r.ok and "프로파일" in r.error

def test_empty_file():
    assert not parse_csv_bytes(b"", artifact="e.csv").ok

def test_row_without_rule_id_is_warned_not_dropped_silently():
    r = parse_csv_bytes((H1 + ',"이름",상,양호,"x"\n').encode(), artifact="n.csv")
    assert r.ok and not r.findings and any("항목코드" in w for w in r.warnings)

def test_cp949_and_bom_and_utf8():
    body = H1 + 'U-01,"root",상,양호,"ok"\n'
    for enc, expect in (("utf-8", "utf-8"), ("cp949", "cp949"), ("utf-8-sig", "utf-8-sig")):
        r = parse_csv_bytes(body.encode(enc), artifact=f"{enc}.csv")
        assert r.ok and r.encoding == expect and r.findings[0].rule_id == "U-01"

def test_undecodable_bytes_do_not_abort():
    r = parse_csv_bytes((H1 + 'U-01,"x",상,양호,"').encode() + b"\xff\xfe" + b'"\n',
                        artifact="bad.csv")
    assert r.ok and r.encoding_error

def test_unmapped_verdict_becomes_unknown_not_pass():
    r = parse_csv_bytes((H1 + 'U-01,"x",상,보류,"?"\n').encode(), artifact="u.csv")
    results, _ = normalize(r.findings)
    assert results[0].status is Status.UNKNOWN
    assert results[0].warnings

def test_missing_provides_surface_as_unknown():
    r = parse_csv_bytes((H1 + 'U-01,"x",상,양호,"ok"\n').encode(), artifact="p.csv")
    results, _ = normalize(r.findings, provides=["U-01", "U-02", "U-03"], bundle_id="B")
    by = {c.rule_id: c for c in results}
    assert by["U-01"].status is Status.PASS
    assert by["U-02"].status is Status.UNKNOWN and "not reported" in by["U-02"].reason
    assert by["U-03"].status is Status.UNKNOWN

def test_evidence_is_masked_in_results():
    row = 'U-01,"shadow",상,수동확인,"root:$6$abc123XY$Zq0123456789abcdefghij:19000"\n'
    r = parse_csv_bytes((H1 + row).encode(), artifact="m.csv")
    results, _ = normalize(r.findings)
    assert "$6$" not in (results[0].evidence or "")
    assert "***HASH***" in (results[0].evidence or "")
