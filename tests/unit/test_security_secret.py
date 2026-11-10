"""Component tests: owner secret hashing/verification (EP, BVA, error guessing)."""

import base64

import pytest

from garmin_mcp.security import OwnerSecret, SecretFormatError, hash_owner_password

pytestmark = pytest.mark.risk("R01")

PW = "correct horse battery staple"
N = 2**14


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make(n=N, r=8, p=1, salt=b"s" * 16, digest=b"d" * 32, prefix="scrypt") -> str:
    return f"{prefix}${n}${r}${p}${b64(salt)}${b64(digest)}"


def test_roundtrip_accepts_only_exact_password():
    s = OwnerSecret.from_hash(hash_owner_password(PW, n=N))
    assert s.verify(PW)
    for wrong in ["", PW[:-1], PW + " ", PW.upper(), " " + PW, PW + "\x00"]:
        assert not s.verify(wrong), repr(wrong)


def test_hash_is_salted():
    assert hash_owner_password(PW, n=N) != hash_owner_password(PW, n=N)


def test_unicode_passwords():
    pw = "パスワードは十六文字以上必要です"
    s = OwnerSecret.from_plaintext(pw, n=N)
    assert s.verify(pw)
    assert not s.verify(pw.replace("パ", "ハ"))


# BVA: candidate length cap (1024) bounds attacker-forced work
@pytest.mark.parametrize(("length", "can_match"), [(1023, True), (1024, True), (1025, False)])
def test_candidate_length_boundary(length, can_match):
    pw = "a" * length
    s = OwnerSecret.from_plaintext(pw, n=N)
    assert s.verify(pw) is can_match


@pytest.mark.parametrize(
    "encoded",
    [
        "",
        "scrypt",
        "scrypt$1$2$3$4",                              # too few parts
        make(prefix="bcrypt"),                          # wrong algorithm
        make() + "$extra",                              # too many parts
        "scrypt$x$8$1$c2FsdA$ZGln",                     # non-int N
        "scrypt$16384$8$1$!!!$ZGln",                    # bad base64
    ],
)
def test_malformed_hash_rejected(encoded):
    with pytest.raises(SecretFormatError):
        OwnerSecret.from_hash(encoded)


# BVA on each scrypt parameter's lower bound
@pytest.mark.parametrize(
    ("kwargs", "ok"),
    [
        ({"n": 2**13}, False), ({"n": 2**14}, True), ({"n": 2**15}, True),
        ({"n": 2**14 + 1}, False),                       # not a power of two
        ({"r": 7}, False), ({"r": 8}, True), ({"r": 9}, True),
        ({"p": 0}, False), ({"p": 1}, True), ({"p": 2}, True),
        ({"salt": b"s" * 15}, False), ({"salt": b"s" * 16}, True), ({"salt": b"s" * 17}, True),
        ({"digest": b"d" * 31}, False), ({"digest": b"d" * 32}, True),
        ({"digest": b"d" * 33}, False),
    ],
)
def test_parameter_boundaries(kwargs, ok):
    if ok:
        OwnerSecret.from_hash(make(**kwargs))
    else:
        with pytest.raises(SecretFormatError):
            OwnerSecret.from_hash(make(**kwargs))


@pytest.mark.risk("R06")
def test_repr_does_not_expose_salt_or_digest():
    s = OwnerSecret.from_hash(make(salt=b"SALTSALTSALTSALT", digest=b"D" * 32))
    assert "SALT" not in repr(s)
    assert "DDDD" not in repr(s)


@pytest.mark.parametrize("suffix", ["\x00", "\x00\x00", "\t", "\n", "\x7f"])
def test_control_char_variants_never_verify(suffix):
    """Regression: HMAC key zero-padding made PW + NUL verify as PW."""
    s = OwnerSecret.from_plaintext(PW, n=N)
    assert not s.verify(PW + suffix)


def test_hashing_rejects_control_chars():
    with pytest.raises(ValueError):
        hash_owner_password("a" * 20 + "\x00", n=N)


# ---- NFKC normalization (NIST SP 800-63B): same passphrase, different keyboards ----
@pytest.mark.parametrize(("stored", "typed"), [
    ("がぎぐげご-passphrase-123", "がぎぐげご-passphrase-123"),  # NFC vs NFD
    ("passphrase-ＡＢＣ-１２３-xyz", "passphrase-ABC-123-xyz"),                               # full-width
    ("café-au-lait-passphrase", "café-au-lait-passphrase"),
])
def test_equivalent_unicode_forms_verify(stored, typed):
    s = OwnerSecret.from_plaintext(stored, n=N)
    assert s.verify(typed)
    assert s.verify(stored)


def test_normalization_does_not_merge_distinct_passwords():
    s = OwnerSecret.from_plaintext("passphrase-abc-123-xyz", n=N)
    assert not s.verify("passphrase-ABC-123-xyz")       # case still matters
    assert not s.verify("passphrase-abc-123-xyz ")
