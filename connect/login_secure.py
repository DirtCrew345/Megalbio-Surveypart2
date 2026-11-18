import hashlib
import hmac
import secrets

ITERATIONS = 600_000  # slow on purpose, so guessing passwords is expensive


def hash_with_salt(password, salt):
    """Slow, salted hash. Same password + same salt always gives the same result."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)


# Register: save the salt and the hash in the database. Never save the password.
salt = secrets.token_bytes(16)  # random, different for every user
stored_hash = hash_with_salt("secure password", salt)
print("Stored salt:", salt.hex())
print("Stored hash:", stored_hash.hex())

# Login: hash the typed password with the SAME salt, then compare
typed = input("Enter password: ")
typed_hash = hash_with_salt(typed, salt)

if hmac.compare_digest(typed_hash, stored_hash):
    print("login success")
else:
    print("login failed")
