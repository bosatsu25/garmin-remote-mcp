"""Generate OWNER_PASSWORD_HASH so the server never holds the plaintext passphrase."""

from __future__ import annotations

import getpass
import sys

from .config import MAX_OWNER_PASSWORD_LENGTH, MIN_OWNER_PASSWORD_LENGTH
from .security import hash_owner_password


def main() -> None:
    pw = getpass.getpass("Owner passphrase: ")
    if not MIN_OWNER_PASSWORD_LENGTH <= len(pw) <= MAX_OWNER_PASSWORD_LENGTH:
        sys.exit(
            f"Passphrase must be {MIN_OWNER_PASSWORD_LENGTH}-{MAX_OWNER_PASSWORD_LENGTH} characters"
        )
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in pw):
        sys.exit("Passphrase must not contain control characters")
    if getpass.getpass("Repeat: ") != pw:
        sys.exit("Passphrases do not match")
    # stdout: one line in `fly secrets import` format.
    print(f"OWNER_PASSWORD_HASH={hash_owner_password(pw)}")


if __name__ == "__main__":
    main()
