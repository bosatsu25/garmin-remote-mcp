"""Guard the test double itself: every Garmin method the fake implements must exist on the
real garminconnect.Garmin with a compatible signature (otherwise integration tests could
pass against an API that does not exist)."""

import inspect

import pytest
from garminconnect import Garmin

from ..conftest import FakeGarmin

pytestmark = pytest.mark.risk("R10", "R11")

FAKE_ONLY = {"fail_with"}


def _public_methods(cls):
    return {n for n, v in vars(cls).items() if callable(v) and not n.startswith("_")}


@pytest.mark.parametrize("name", sorted(_public_methods(FakeGarmin) - FAKE_ONLY))
def test_fake_method_exists_on_real_garmin(name):
    assert hasattr(Garmin, name), f"FakeGarmin.{name} is not a real Garmin API"


@pytest.mark.parametrize("name", sorted(_public_methods(FakeGarmin) - FAKE_ONLY))
def test_fake_signature_accepts_real_positional_arity(name):
    real = inspect.signature(getattr(Garmin, name))
    fake = inspect.signature(getattr(FakeGarmin, name))
    required_real = [p for p in real.parameters.values()
                     if p.default is p.empty and p.kind in (p.POSITIONAL_ONLY,
                                                            p.POSITIONAL_OR_KEYWORD)]
    positional_fake = [p for p in fake.parameters.values()
                       if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    assert len(positional_fake) >= len(required_real), (name, str(real), str(fake))


def test_fallback_rejects_unknown_and_misbound_calls():
    f = FakeGarmin()
    with pytest.raises(AttributeError):
        f.get_heart_rate  # noqa: B018 - real API is get_heart_rates
    with pytest.raises(TypeError):
        f.get_heart_rates()                        # missing cdate
    assert f.get_heart_rates("2026-11-09")["method"] == "get_heart_rates"
