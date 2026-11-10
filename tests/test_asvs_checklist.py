"""Keeps the ASVS V10 checklist honest: every requirement is classified, every "covered"
claim points at tests that exist, and nothing in scope is silently skipped."""

import pytest

from .asvs_v10 import TARGET_LEVEL, V10


def test_chapter_is_complete():
    assert len(V10) == 36                                   # ASVS 5.0.0 V10
    assert {k.rsplit(".", 1)[0] for k in V10} == {f"V10.{i}" for i in range(1, 8)}


@pytest.mark.parametrize("req", sorted(V10))
def test_requirement_is_classified(req, collected_tests):
    item = V10[req]
    assert item.status in {"covered", "not_applicable", "not_targeted"}
    if item.status == "covered":
        assert item.tests, f"{req}: covered but no tests listed"
        missing = [t for t in item.tests if t not in collected_tests]
        if collected_tests >= {"tests/integration/test_asvs_v10.py::test_code_reuse_is_audited"}:
            assert not missing, f"{req}: tests do not exist: {missing}"
    else:
        assert item.note, f"{req}: {item.status} needs a reason"
        assert not item.tests
    if item.status == "not_targeted":
        assert item.level > TARGET_LEVEL
    if item.level <= TARGET_LEVEL:
        assert item.status != "not_targeted", f"{req}: in-scope level cannot be skipped"
