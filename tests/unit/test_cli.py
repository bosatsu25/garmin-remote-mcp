"""Component tests: CLIs (stdout carries exactly one secret line, prompts go to stderr)."""

import base64
import json
import os
import stat

import pytest

from garmin_mcp import hash_password, login_cli
from garmin_mcp.security import OwnerSecret

pytestmark = pytest.mark.risk("R06", "R09")


@pytest.fixture
def fast_hash(monkeypatch):
    real = hash_password.hash_owner_password
    monkeypatch.setattr(hash_password, "hash_owner_password", lambda pw: real(pw, n=2**14))


def run_hash(monkeypatch, answers):
    it = iter(answers)
    monkeypatch.setattr(hash_password.getpass, "getpass", lambda prompt="": next(it))
    hash_password.main()


def test_hash_password_outputs_import_line(monkeypatch, capsys, fast_hash):
    run_hash(monkeypatch, ["a" * 20, "a" * 20])
    out = capsys.readouterr().out.strip()
    assert out.startswith("OWNER_PASSWORD_HASH=scrypt$")
    assert out.count("\n") == 0
    assert OwnerSecret.from_hash(out.split("=", 1)[1]).verify("a" * 20)
    assert "a" * 20 not in out


@pytest.mark.parametrize(("answers", "msg"), [
    (["a" * 15], "16"),
    (["a" * 20, "b" * 20], "match"),
    (["a" * 19 + "\x00"], "control"),
])
def test_hash_password_rejects(monkeypatch, capsys, fast_hash, answers, msg):
    with pytest.raises(SystemExit) as e:
        run_hash(monkeypatch, answers)
    assert msg in str(e.value)
    assert capsys.readouterr().out == ""


class FakeLoginGarmin:
    def __init__(self, email, password, is_cn, prompt_mfa):
        self.args = (email, password, is_cn)
        self.client = self
        FakeLoginGarmin.last = self

    def login(self, tokenstore):
        if FakeLoginGarmin.error:
            raise FakeLoginGarmin.error

    def dumps(self):
        return json.dumps({"di_token": "t", "di_refresh_token": "r", "di_client_id": "c"})

    def get_full_name(self):
        return "Owner"


@pytest.fixture
def fake_login(monkeypatch):
    FakeLoginGarmin.error = None
    monkeypatch.setattr(login_cli, "Garmin", FakeLoginGarmin)
    monkeypatch.setattr(login_cli.getpass, "getpass", lambda prompt="": "garmin-pw")


def test_login_cli_stdout_is_single_import_line(monkeypatch, capsys, fake_login, tmp_path):
    out_file = tmp_path / "tok.json"
    monkeypatch.setattr("sys.argv", ["garmin-mcp-login", "--email", "o@example.com",
                                     "--out", str(out_file)])
    login_cli.main()
    cap = capsys.readouterr()
    line = cap.out.strip()
    assert line.startswith("GARMIN_TOKENS=")
    assert json.loads(base64.b64decode(line.split("=", 1)[1]))["di_refresh_token"] == "r"
    assert "garmin-pw" not in cap.out + cap.err          # password never printed
    assert "Owner" in cap.err
    assert stat.S_IMODE(os.stat(out_file).st_mode) == 0o600
    assert FakeLoginGarmin.last.args == ("o@example.com", "garmin-pw", False)


def test_login_cli_rate_limited_exits(monkeypatch, capsys, fake_login):
    from garminconnect import GarminConnectTooManyRequestsError

    FakeLoginGarmin.error = GarminConnectTooManyRequestsError("429")
    monkeypatch.setattr("sys.argv", ["garmin-mcp-login", "--email", "o@example.com"])
    with pytest.raises(SystemExit, match="Rate limited"):
        login_cli.main()
    assert "GARMIN_TOKENS" not in capsys.readouterr().out


def test_login_cli_prompts_on_stderr(monkeypatch, capsys, fake_login):
    import io

    monkeypatch.setattr("sys.argv", ["garmin-mcp-login"])
    monkeypatch.setattr("sys.stdin", io.StringIO("o@example.com\n"))
    login_cli.main()
    cap = capsys.readouterr()
    assert "Garmin email:" in cap.err
    assert "Garmin email:" not in cap.out


def test_login_cli_tty_tip(monkeypatch, capsys, fake_login):
    monkeypatch.setattr("sys.argv", ["garmin-mcp-login", "--email", "o@example.com"])
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    login_cli.main()
    assert "fly secrets import" in capsys.readouterr().err
