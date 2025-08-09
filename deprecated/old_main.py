import sys
import json
import os
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFrame
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

# Constants
VAULT_PATH = "password-manager/vault.json"
AUTH_STRING = "verified"


class SecureVault(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureVault")
        self.setGeometry(100, 100, 200 , 250)
        #self.setMinimumSize(400, 500)
        self.pat = ""
        self.init_ui()


    def init_ui(self):
        self.setStyleSheet('''
            QLabel { color: blue; font-size: 20px; }
            ''')
        self.font_regular = QFont("Segoe UI", 10)
        self.font_bold = QFont("Segoe UI", 12, QFont.Weight.Bold)
        self.font_heading = QFont("Segoe UI", 16, QFont.Weight.Bold)

        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)

        self.setup_login_frame()
        self.setup_main_frame()

        self.main_layout.addWidget(self.login_frame)
        self.main_layout.addWidget(self.main_frame)
        self.login_frame.show()
        self.main_frame.hide()

    def setup_login_frame(self):
        self.login_frame = QFrame(self)
        login_layout = QVBoxLayout()
        self.login_frame.setLayout(login_layout)

        login_heading = QLabel("Welcome to SecureVault")
        login_heading.setFont(self.font_heading)
        login_heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_layout.addWidget(login_heading)

        pat_label = QLabel("Enter Personal Access Token (PAT)")
        pat_label.setFont(self.font_regular)
        pat_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_layout.addWidget(pat_label)

        self.pat_entry = QLineEdit()
        self.pat_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.pat_entry.setFont(self.font_regular)
        login_layout.addWidget(self.pat_entry)

        login_button = QPushButton("Login")
        login_button.setFont(self.font_bold)
        login_button.clicked.connect(self.verify_pat)
        login_layout.addWidget(login_button)

    def setup_main_frame(self):
        self.main_frame = QFrame(self)
        main_layout = QVBoxLayout()
        self.main_frame.setLayout(main_layout)

        heading = QLabel("Search Password")
        heading.setFont(self.font_heading)
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(heading)

        self.search_entry = QLineEdit()
        self.search_entry.setFont(self.font_regular)
        self.search_entry.setPlaceholderText("Enter username")
        main_layout.addWidget(self.search_entry)

        search_button = QPushButton("Search")
        search_button.clicked.connect(self.search_password)
        main_layout.addWidget(search_button)

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        main_layout.addWidget(separator)

        heading2 = QLabel("Add New Password")
        heading2.setFont(self.font_heading)
        heading2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(heading2)

        self.add_user_entry = QLineEdit()
        self.add_user_entry.setPlaceholderText("Enter username")
        main_layout.addWidget(self.add_user_entry)

        self.add_pass_entry = QLineEdit()
        self.add_pass_entry.setPlaceholderText("Enter password")
        main_layout.addWidget(self.add_pass_entry)

        add_button = QPushButton("Add Password")
        add_button.clicked.connect(self.add_password)
        main_layout.addWidget(add_button)

    def verify_pat(self):
        self.pat = self.pat_entry.text().strip()
        if not os.path.exists(VAULT_PATH):
            QMessageBox.critical(self, "Vault Missing", "vault.json not found. Use the converter first.")
            return
        try:
            with open(VAULT_PATH, 'r') as f:
                vault = json.load(f)
            if "__auth_check__" not in vault:
                raise ValueError("No auth_check found")
            self.decrypt(vault["__auth_check__"])
            self.login_frame.hide()
            self.main_frame.show()
        except Exception:
            QMessageBox.critical(self, "Login Failed", "Incorrect PAT or corrupted vault.")

    def search_password(self):
        user = self.search_entry.text().strip()
        try:
            with open(VAULT_PATH, 'r') as f:
                vault = json.load(f)
            if user not in vault:
                QMessageBox.information(self, "Not Found", f"No password for {user}.")
                return
            password = self.decrypt(vault[user])
            QMessageBox.information(self, "Found", f"{user}: {password}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def add_password(self):
        user = self.add_user_entry.text().strip()
        password = self.add_pass_entry.text().strip()
        if not user or not password:
            QMessageBox.warning(self, "Missing Info", "Username and password can't be empty.")
            return
        try:
            if os.path.exists(VAULT_PATH):
                with open(VAULT_PATH, 'r') as f:
                    vault = json.load(f)
            else:
                vault = {"__auth_check__": self.encrypt(AUTH_STRING)}
            vault[user] = self.encrypt(password)
            with open(VAULT_PATH, 'w') as f:
                json.dump(vault, f, indent=4)
            QMessageBox.information(self, "Saved", f"Password for {user} added.")
            self.add_user_entry.clear()
            self.add_pass_entry.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def derive_key(self, salt):
        kdf = Scrypt(
            salt=bytes.fromhex(salt),
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return kdf.derive(self.pat.encode())

    def encrypt(self, text):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self.derive_key(salt.hex())
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, text.encode(), None)
        return {
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "cipher": encrypted.hex()
        }

    def decrypt(self, data):
        salt = data['salt']
        nonce = bytes.fromhex(data['nonce'])
        cipher = bytes.fromhex(data['cipher'])
        key = self.derive_key(salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, cipher, None).decode()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SecureVault()
    window.show()
    sys.exit(app.exec())
