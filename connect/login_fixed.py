import hashlib

# Diri e Register: save only the hash of the password, never the password itself
pwd = 'secure password'
hashed = hashlib.sha256(pwd.encode()).hexdigest()
print("Stored hash:", hashed)

# Diri e Login: hash what the user types and compare the two hashes
input_password = input("Enter password: ")
input_hashed = hashlib.sha256(input_password.encode()).hexdigest()

if hashed == input_hashed:
    print("login success")
else:
    print("login failed")
