import json
import os
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

_COV_PATH = os.environ.get("IG_RULE_COVERAGE")
_cov: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))


def pytest_configure(config):  # noqa: ANN001,ANN201
    """IG_RULE_COVERAGE=경로 면 룰 평가를 감싸 (rule_id → 판정 횟수) 를 기록한다(scripts/rule_coverage.py)."""
    if not _COV_PATH:
        return
    from infraguard.rules import REGISTRY, declarative, load_all

    real_eval = declarative.evaluate

    def eval_rec(spec, conn, env):  # noqa: ANN001,ANN202
        try:
            out = real_eval(spec, conn, env)
        except Exception:
            _cov[spec.id]["ERROR"] += 1
            raise
        _cov[spec.id][out.verdict_raw] += 1
        return out

    declarative.evaluate = eval_rec
    load_all()
    import dataclasses

    for rid, rule in list(REGISTRY.items()):
        if rule.collects:          # 선언형은 evaluate 가 잡는다
            continue

        def wrap(fn, rid=rid):  # noqa: ANN001,ANN202
            def check(conn, env):  # noqa: ANN001,ANN202
                try:
                    out = fn(conn, env)
                except Exception:
                    _cov[rid]["ERROR"] += 1
                    raise
                _cov[rid][out.verdict_raw] += 1
                return out
            return check

        REGISTRY[rid] = dataclasses.replace(rule, check=wrap(rule.check))


def pytest_sessionfinish(session, exitstatus):  # noqa: ANN001,ANN201
    if _COV_PATH:
        p = pathlib.Path(_COV_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({k: dict(v) for k, v in sorted(_cov.items())}, ensure_ascii=False, indent=1),
                     encoding="utf-8")
