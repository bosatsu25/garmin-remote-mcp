"""Bidirectional traceability (JSTQB FL §1.4.4): risk -> tests.

The reverse direction (test -> risk) is enforced at collection time in conftest.py.
Only meaningful on a full run; skipped when a subset is selected.
"""

import pytest

from .risks import RISKS

# A high-level risk (level >= 6) must be covered by at least this many tests.
MIN_TESTS_FOR_HIGH_RISK = 5


def _full_run(config: pytest.Config) -> bool:
    return not config.option.keyword and not config.option.markexpr and all(
        a in ("tests", "tests/") for a in config.args
    )


def test_every_risk_has_tests(request, risk_coverage):
    if not _full_run(request.config):
        pytest.skip("traceability is checked on full runs only")
    missing = [rid for rid in RISKS if not risk_coverage.get(rid)]
    assert not missing, f"risks without tests: {missing}"


def test_high_risks_are_tested_in_depth(request, risk_coverage):
    if not _full_run(request.config):
        pytest.skip("traceability is checked on full runs only")
    thin = {
        rid: len(risk_coverage.get(rid, []))
        for rid, r in RISKS.items()
        if r.level >= 6 and len(risk_coverage.get(rid, [])) < MIN_TESTS_FOR_HIGH_RISK
    }
    assert not thin, f"high risks with too few tests: {thin}"
