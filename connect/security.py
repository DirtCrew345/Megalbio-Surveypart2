"""Helpers for passwords and login tokens. No database code in here."""

import hashlib
import hmac
import secrets

# How many rounds PBKDF2 runs. More rounds make password guessing slower.
# 600,000 is the number OWASP recommends for PBKDF2-HMAC-SHA256.
PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """Turn a plain password into a salted hash that is safe to store.

    The output looks like: pbkdf2_sha256$600000$<salt>$<hash>
    A new random salt is used every time, so two users with the same
    password still get different hashes.
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Return True if the typed password matches the stored hash."""
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
    except ValueError:
        # Not a valid hash, for example an old plain-text password
        return False

    # compare_digest takes the same amount of time wherever the mismatch is
    return hmac.compare_digest(actual, expected)


def new_session_token() -> str:
    """A long random string. The browser keeps it after login."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only this hash is saved in the database, never the token itself."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
