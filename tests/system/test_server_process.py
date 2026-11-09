"""System tests: the installed entry point, a real uvicorn process, real TCP."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from garmin_mcp.security import hash_owner_password

pytestmark = pytest.mark.system

PW = "system-test-passphrase-123"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(env_extra: dict[str, str], tmp_path: Path) -> tuple[subprocess.Popen, str]:
    port = free_port()
    env = {
        "PATH": os.environ.get("PATH", ""),
        # let coverage measure the subprocess (pyproject: [tool.coverage.run] patch)
        **{k: v for k, v in os.environ.items() if k.startswith("COVERAGE")},
        "PUBLIC_URL": f"http://127.0.0.1:{port}",
        "OWNER_PASSWORD_HASH": hash_owner_password(PW, n=2**14),
        "DATA_DIR": str(tmp_path / "data"),
        "HOST": "127.0.0.1",
        "PORT": str(port),
        **env_extra,
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "garmin_mcp.server"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc, f"http://127.0.0.1:{port}"


def wait_ready(base: str, proc: subprocess.Popen) -> None:
    for _ in range(100):
        if proc.poll() is not None:
            raise AssertionError(proc.stdout.read())
        try:
            if httpx.get(f"{base}/healthz", timeout=0.5).status_code == 200:
                return
        except httpx.TransportError:
            time.sleep(0.1)
    raise AssertionError("server did not start")


@pytest.fixture
def server(tmp_path):
    proc, base = start({}, tmp_path)
    try:
        wait_ready(base, proc)
        yield base, tmp_path
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.mark.risk("R04", "R08")
def test_running_server_basics(server):
    base, _ = server
    h = httpx.get(f"{base}/healthz")
    assert "server" not in h.headers                 # no version banner
    assert h.headers["x-content-type-options"] == "nosniff"
    assert "strict-transport-security" not in h.headers  # http://localhost: no HSTS
    r = httpx.post(f"{base}/mcp", json={}, headers={"Accept": "application/json"})
    assert r.status_code == 401


@pytest.mark.risk("R14")
def test_running_server_rejects_foreign_host(server):
    base, _ = server
    r = httpx.post(f"{base}/mcp", json={}, headers={"Host": "evil.example"})
    assert r.status_code in (401, 421)               # auth runs first; never 200


@pytest.mark.risk("R07")
def test_running_server_body_limit(server):
    base, _ = server
    r = httpx.post(f"{base}/register", content=b"x" * (512 * 1024),
                   headers={"content-type": "application/json"})
    assert r.status_code == 413


@pytest.mark.risk("R06", "R13")
def test_data_dir_permissions(server):
    base, tmp = server
    r = httpx.post(f"{base}/register", json={
        "redirect_uris": ["http://localhost:1/cb"], "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]})
    assert r.status_code == 201
    data = tmp / "data"
    assert oct(data.stat().st_mode & 0o777) == "0o700"
    assert oct((data / "oauth_state.json").stat().st_mode & 0o777) == "0o600"


@pytest.mark.risk("R09")
@pytest.mark.parametrize(("env", "message"), [
    ({"OWNER_PASSWORD_HASH": "", "OWNER_PASSWORD": "short"}, "at least 16"),
    ({"PUBLIC_URL": "http://example.com"}, "https://"),
    ({"GARMIN_ALLOW_WRITE": "maybe"}, "true/false"),
])
def test_insecure_config_refuses_to_start(tmp_path, env, message):
    proc, _ = start(env, tmp_path)
    out, _ = proc.communicate(timeout=20)
    assert proc.returncode != 0
    assert message in out
    assert "short" not in out.replace("at least", "")   # the secret itself is not echoed
