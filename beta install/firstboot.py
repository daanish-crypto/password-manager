import os, sys
import json
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QLineEdit, QPushButton, QLabel
)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Constants
INPUT_FILE = "_internals/frame.json"
OUTPUT_FILE = "_internals/vault.json"

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

class InputWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Input Window")
        self.setFixedSize(350, 180)

        self.value = None  # Store submitted value here

        # Layout
        layout = QVBoxLayout()

        self.label = QLabel("Enter your Personal Access Token (PAT):")
        layout.addWidget(self.label)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Type your PAT here...")
        layout.addWidget(self.input)

        self.submit_btn = QPushButton("Submit & Encrypt")
        layout.addWidget(self.submit_btn)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

        # Connect signals
        self.submit_btn.clicked.connect(self.submit_value)
        self.input.returnPressed.connect(self.submit_value)

    def submit_value(self):
        pat = self.input.text().strip()
        if not pat:
            self.status_label.setText("❌ Please enter a value!")
            return

        self.value = pat
        self.status_label.setText("Processing encryption... Please wait.")
        QApplication.processEvents()  # update GUI immediately

        try:
            convert_unencrypted_to_encrypted(INPUT_FILE, OUTPUT_FILE, self.value)
            self.status_label.setText(f"✅ Encryption done! Output saved to:\n{OUTPUT_FILE}")
        except Exception as e:
            self.status_label.setText(f"❌ Error: {str(e)}")

        self.input.clear()

    def get_value(self):
        return self.value

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = InputWindow()
    window.show()
    sys.exit(app.exec())
