"""Targeted mutation testing (run: python tools/mutation_check.py).

Plants one realistic security bug at a time and requires the test suite to fail. Coverage
shows code was executed; this shows the tests would actually catch a regression."""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
M = [
 ("access token expiry off-by-one", "oauth.py",
  'if not rec or rec["expires_at"] <= self.clock():', 'if not rec or rec["expires_at"] < self.clock():'),
 ("refresh reuse detection disabled", "oauth.py",
  'n = self._revoke_family(retired["family"])', 'n = 0'),
 ("write scope check removed", "server.py",
  'if token is None or SCOPE_WRITE not in token.scopes:', 'if False:'),
 ("redirect userinfo check removed", "security.py",
  'if parts.username is not None or parts.password is not None or "@" in parts.netloc:', 'if False:'),
 ("rate limit off-by-one", "security.py",
  'len(self._hits.get(key, ())) >= self.per_key_max', 'len(self._hits.get(key, ())) > self.per_key_max'),
 ("NUL password collision reintroduced", "security.py",
  '        if has_control_chars(candidate):\n            return False', '        pass'),
 ("api path fullmatch -> match", "server.py",
  'not API_PATH_RE.fullmatch(path)', 'not API_PATH_RE.match(path)'),
 ("provider scope widening check removed", "oauth.py",
  'if scopes and any(s not in rec["scopes"] for s in scopes):', 'if False:'),
 ("pending store unbounded", "oauth.py",
  'if len(self._pending) >= MAX_PENDING:', 'if False:'),
 ("state file world-readable", "oauth.py",
  'fd = os.open(tmp, flags, 0o600)', 'fd = os.open(tmp, flags, 0o644)'),
 ("write checkbox ignored (always grant write)", "oauth.py",
  'if want_write and self.settings.allow_write:', 'if self.settings.allow_write:'),
 ("code not single-use", "oauth.py",
  'if self._codes.pop(authorization_code.code, None) is None:', 'if self._codes.get(authorization_code.code) is None:'),
 ("redaction disabled", "server.py",
  'raise ToolError(redact(str(e))) from e', 'raise ToolError(str(e)) from e'),
 ("Fly-Client-IP always trusted", "oauth.py",
  'if self.settings.trust_fly_client_ip:', 'if True:'),
 ("attempt counted only after the slow check (race)", "oauth.py",
  '''        reservation = self.limiter.record_failure(ip)
        if not await self.verify_owner(password):
            self.limiter.commit(reservation)''',
  '''        reservation = None
        if not await self.verify_owner(password):
            self.limiter.commit(self.limiter.record_failure(ip))'''),
 ("trailing-slash redirect re-enabled", "server.py",
  'starlette_app.router.redirect_slashes = False', 'starlette_app.router.redirect_slashes = True'),
 ("code_challenge length unchecked", "oauth.py",
  'CODE_CHALLENGE_RE = re.compile(r"[A-Za-z0-9._~-]{43,128}", re.ASCII)',
  'CODE_CHALLENGE_RE = re.compile(r"[A-Za-z0-9._~-]{43,}", re.ASCII)'),
 ("state length unchecked", "oauth.py",
  'if params.state is not None and len(params.state) > MAX_STATE_LENGTH:', 'if False:'),
 ("password normalization removed from verify", "security.py",
  'material = normalize_password(candidate) if self.normalize else candidate',
  'material = candidate'),
 ("legacy hashes normalized too (locks out old deployments)", "security.py",
  'material = normalize_password(candidate) if self.normalize else candidate',
  'material = normalize_password(candidate)'),
 ("success wipes in-flight reservations", "security.py",
  '''        pending = [t for k, t in self._inflight.values() if k == key]
        if pending:
            self._hits[key] = pending
        else:
            self._hits.pop(key, None)''',
  '        self._hits.pop(key, None)'),
 ("redeemed-code records not persisted", "oauth.py",
  '"used_codes": self._used_codes,', ''),
]
killed, survived = [], []
for name, f, old, new in M:
    p = ROOT / "src/garmin_mcp" / f
    src = p.read_text()
    assert src.count(old) == 1, (name, old)
    p.write_text(src.replace(old, new))
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "tests", "-x", "-q", "-m", "not system",
                            ], cwd=ROOT, capture_output=True, text=True)
    finally:
        p.write_text(src)
    (killed if r.returncode != 0 else survived).append(name)
    first = next((l for l in r.stdout.splitlines() if l.startswith("FAILED")), "")
    print(f"{'KILLED  ' if r.returncode else 'SURVIVED'} {name:45s} {first[:90]}")
print(f"\nmutation score: {len(killed)}/{len(M)}")
sys.exit(1 if survived else 0)
