import os
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Constants
INPUT_FILE = "password-manager/deprecated/unencrypted_password.json"
OUTPUT_FILE = "password-manager/deprecated/vault.json"
PAT = "twistmywrist"  # Replace with the PAT you want to use

def derive_key(pat: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(pat.encode())

def encrypt_password(password: str, pat: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(pat, salt)
    aesgcm = AESGCM(key)
    cipher = aesgcm.encrypt(nonce, password.encode(), None)
    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "cipher": cipher.hex()
    }

def convert_unencrypted_to_encrypted(input_path, output_path, pat):
    with open(input_path, "r") as infile:
        data = json.load(infile)

    encrypted_vault = {
        "__auth_check__": encrypt_password("verified", pat)
    }

    for username, password in data.items():
        encrypted_vault[username] = encrypt_password(str(password), pat)

    with open(output_path, "w") as outfile:
        json.dump(encrypted_vault, outfile, indent=4)

    print(f"✅ Converted {len(data)} entries and saved to {output_path}")

# Run it
convert_unencrypted_to_encrypted(INPUT_FILE, OUTPUT_FILE, PAT)
