import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_jwt_secret(word):
    password = word.encode("utf-8")

    salt = b'\x01\x02\x03\x04\x05\x06\x07\x08'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key
        salt=salt,
        iterations=100000,  # Recommended number of iterations
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    return key.decode("utf-8")

if __name__ == "__main__":
    word = input("Enter a word to generate JWT secret: ")
    jwt_secret = generate_jwt_secret(word)
    print(f"Generated JWT secret: {jwt_secret}")