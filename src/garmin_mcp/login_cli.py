"""Run on YOUR machine (not the server) to mint Garmin tokens.

Logs in once with email/password (+MFA if enabled), then prints the token
blob to set as the server's GARMIN_TOKENS secret. The password never leaves
this machine and is not stored anywhere.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import sys
import tempfile
from pathlib import Path

from garminconnect import Garmin, GarminConnectTooManyRequestsError


def _ask(prompt: str) -> str:
    # Prompts go to stderr so stdout stays clean for `| fly secrets import`.
    print(prompt, end="", file=sys.stderr, flush=True)
    return sys.stdin.readline().strip() if not sys.stdin.isatty() else input().strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", help="Garmin account email (prompted if omitted)")
    parser.add_argument("--cn", action="store_true", help="Use garmin.cn (China region)")
    parser.add_argument(
        "--out", type=Path, help="Also write raw token JSON to this file (keep it private)"
    )
    args = parser.parse_args()

    email = args.email or _ask("Garmin email: ")
    password = getpass.getpass("Garmin password: ")

    with tempfile.TemporaryDirectory() as tmp:
        g = Garmin(email, password, is_cn=args.cn, prompt_mfa=lambda: _ask("MFA code: "))
        try:
            g.login(tokenstore=tmp)
        except GarminConnectTooManyRequestsError as e:
            sys.exit(f"Rate limited by Garmin: {e}\nWait (possibly hours) before retrying.")
        token_json = g.client.dumps()

    if args.out:
        args.out.write_text(token_json, encoding="utf-8")
        args.out.chmod(0o600)

    blob = base64.b64encode(token_json.encode()).decode()
    print(f"Logged in as: {g.get_full_name()}", file=sys.stderr)
    if sys.stdout.isatty():
        print("Tip: pipe this command into `fly secrets import` instead of copying the value.",
              file=sys.stderr)
    # stdout: exactly one line in `fly secrets import` format.
    print(f"GARMIN_TOKENS={blob}")


if __name__ == "__main__":
    main()
