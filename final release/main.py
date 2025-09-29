import sys
import json
import os
import shutil
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QStackedWidget, QGraphicsOpacityEffect, QListWidget,
    QListWidgetItem, QSizePolicy
)
from PyQt6.QtGui import QFont, QIcon, QPixmap, QPainter, QColor
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QTimer

# --- Constants ---
VAULT_PATH = os.path.expanduser("~/Documents/SecureVault/local/vault.json")
AUTH_STRING = "verified"

# --- Theme Colors ---
COLOR_BLACK = "#000000"
COLOR_BACKGROUND = "#1e1e2f"
COLOR_PRIMARY = "#27293d"
COLOR_ACCENT = "#8a4fff"
COLOR_ACCENT_HOVER = "#a076f9"
COLOR_RED= "#fb5757"
COLOR_RED_HOVER = "#f97676"
COLOR_TEXT = "#e0e0e0"
COLOR_TEXT_SECONDARY = "#a0a0c0"
COLOR_SUCCESS = "#50fa7b"
COLOR_ERROR = "#ff5555"
COLOR_BORDER = "#44475a"

class SecureVault(QWidget):
    def __init__(self):
        super().__init__()
        self.pat = ""
        self.init_ui()
        self.load_styles()

    def init_ui(self):
        
        self.setWindowTitle("SecureVault")
        self.setWindowIcon(self.create_icon(COLOR_ACCENT))
        self.setGeometry(100, 100, 500, 600)
        self.setMinimumSize(450, 550)

        
        self.stacked_widget = QStackedWidget()
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.stacked_widget)

        
        self.login_page = self.create_login_page()
        self.main_page = self.create_main_page()

        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.main_page)

        
        self.notification_label = QLabel("", self)
        self.notification_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.notification_label.setObjectName("NotificationLabel")
        self.notification_label.setFixedHeight(0)
        main_layout.addWidget(self.notification_label)

    def create_login_page(self):
        
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        self.title = QLabel("SecureVault")
        self.title.setObjectName("TitleLabel")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.subtitle = QLabel("Enter your Personal Access Token to unlock.")
        self.subtitle.setObjectName("SubtitleLabel")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.pat_entry = QLineEdit()
        self.pat_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.pat_entry.setPlaceholderText("Your PAT")
        self.pat_entry.returnPressed.connect(self.verify_pat)
        self.pat_entry.setFixedWidth(300)

        login_button = QPushButton("Unlock Vault")
        login_button.clicked.connect(self.verify_pat)
        login_button.setFixedWidth(300)

        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)
        layout.addWidget(self.pat_entry, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(login_button, 0, Qt.AlignmentFlag.AlignCenter)

        return page

    def create_main_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # --- Header ---
        header_layout = QHBoxLayout()
        title = QLabel("Password Manager")
        title.setObjectName("HeaderLabel")
        logout_button = QPushButton("Logout")
        logout_button.setObjectName("LogoutButton")
        logout_button.setFixedWidth(100)
        logout_button.clicked.connect(self.logout)
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(logout_button)
        layout.addLayout(header_layout)

        # --- Search Section ---
        search_frame = QFrame()
        search_frame.setObjectName("CardFrame")
        search_layout = QVBoxLayout(search_frame)

        search_label = QLabel("Search Credentials")
        search_label.setObjectName("CardTitleLabel")

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Type to search for a username...")
        self.search_entry.textChanged.connect(self.filter_passwords)

        self.password_list = QListWidget()
        self.password_list.setObjectName("PasswordList")
        self.password_list.setAlternatingRowColors(True)

        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_entry)
        search_layout.addWidget(self.password_list)
        layout.addWidget(search_frame)

        # --- Add Section ---
        add_frame = QFrame()
        add_frame.setObjectName("CardFrame")
        add_layout = QVBoxLayout(add_frame)

        add_label = QLabel("Add New Credential")
        add_label.setObjectName("CardTitleLabel")

        self.add_user_entry = QLineEdit()
        self.add_user_entry.setPlaceholderText("Enter username")

        self.add_pass_entry = QLineEdit()
        self.add_pass_entry.setPlaceholderText("Enter password")

        add_button = QPushButton("Add Credential")
        add_button.clicked.connect(self.add_password)

        add_layout.addWidget(add_label)
        add_layout.addWidget(self.add_user_entry)
        add_layout.addWidget(self.add_pass_entry)
        add_layout.addWidget(add_button)
        layout.addWidget(add_frame)

        return page

    def load_styles(self):
        """Loads the stylesheet for the application."""
        stylesheet = f"""
            QWidget {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT};
                font-family: Segoe UI, sans-serif;
            }}
            #TitleLabel {{
                font-size: 53px;
                font-weight: bold;
                color: {COLOR_TEXT};
            }}
            #SubtitleLabel {{
                font-size: 15px;
                color: {COLOR_TEXT_SECONDARY};
            }}
            #HeaderLabel {{
                font-size: 24px;
                font-weight: bold;
                color: {COLOR_TEXT};
            }}
            #CardFrame {{
                background-color: {COLOR_PRIMARY};
                border-radius: 8px;
            }}
            #CardTitleLabel {{
                font-size: 16px;
                font-weight: bold;
                color: {COLOR_TEXT};
                padding-bottom: 5px;
            }}
            QLineEdit {{
                background-color: {COLOR_BACKGROUND};
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                padding: 8px 10px;
                font-size: 14px;
                min-height: 30px;
            }}
            QLineEdit:focus {{
                border: 1px solid {COLOR_ACCENT};
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
                padding: 6px 10px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_ACCENT_HOVER};
            }}
            #copy {{
                background-color: {COLOR_ACCENT};
                color: {COLOR_TEXT};
                font-size: 11px;
                font-weight: bold;
            }}
            #copy:hover {{
                background-color: {COLOR_ACCENT_HOVER};
            }}
            #delete {{
                background-color: {COLOR_RED};
                color: {COLOR_BLACK};
                font-size: 11px;
            }}
            #delete:hover {{
                background-color: {COLOR_RED_HOVER};
            }}
            #LogoutButton {{
                background-color: {COLOR_BORDER};
            }}
            #LogoutButton:hover {{
                background-color: {COLOR_ERROR};
            }}
            #NotificationLabel {{
                background-color: {COLOR_SUCCESS};
                color: {COLOR_BACKGROUND};
                font-weight: bold;
                padding: 5px;
            }}
            /* make the list a card so rows contrast with the window */
            QListWidget {{
                border: 3px solid {COLOR_BORDER};
                border-radius: 5px;
                background-color: {COLOR_PRIMARY};
            }}
            QListWidget::item {{
                padding: 6px 8px;
                margin: 1;
                background: transparent;
            }}
            /* alternate rows use a slightly lighter color so they are visible */
            QListWidget::item:alternate {{
                background: #323445; /* slightly different from COLOR_PRIMARY */
            }}
            QListWidget::item:selected {{
                background: {COLOR_ACCENT};
                color: white;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
            }}
        """
        self.setStyleSheet(stylesheet)

    def show_notification(self, message, is_error=False):
        """Displays a temporary notification message."""
        self.notification_label.setText(message)
        bg_color = COLOR_ERROR if is_error else COLOR_SUCCESS
        self.notification_label.setStyleSheet(f"background-color: {bg_color}; color: #111; font-weight: bold; padding: 5px;")
        self.notification_label.setFixedHeight(30)
        QTimer.singleShot(3000, lambda: self.notification_label.setFixedHeight(0))

    def switch_view(self, index):
        """Switches between the login and main pages with a fade animation."""
        self.stacked_widget.setCurrentIndex(index)
        new_widget = self.stacked_widget.currentWidget()

        opacity_effect = QGraphicsOpacityEffect(new_widget)
        new_widget.setGraphicsEffect(opacity_effect)

        # Store animation so it doesn't get garbage collected
        self.fade_animation = QPropertyAnimation(opacity_effect, b"opacity")
        self.fade_animation.setDuration(300)
        self.fade_animation.setStartValue(0.0)
        self.fade_animation.setEndValue(1.0)
        self.fade_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.fade_animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def verify_pat(self):
        """Verifies PAT or creates a new vault on first run."""
        self.pat = self.pat_entry.text().strip()
        if not self.pat:
            self.show_notification("PAT cannot be empty.", is_error=True)
            return

        # If vault doesn't exist, create it with the provided PAT
        if not os.path.exists(VAULT_PATH):

            try:
                self.title.setText("Creating Vault...")
                self.subtitle.setText("Please wait while we set up your vault.")
                QApplication.processEvents()
                vault = {"__auth_check__": self.encrypt(AUTH_STRING)}
                shutil.copy("vault authenticator.png", os.path.expanduser("~/Documents/SecureVault/packages")) 
                shutil.copy("codec.png", os.path.expanduser("~/Documents/SecureVault/packages"))
                os.makedirs(os.path.dirname(VAULT_PATH), exist_ok=True)
                with open(VAULT_PATH, 'w') as f:
                    json.dump(vault, f, indent=4)

                self.show_notification("Vault created successfully! Welcome.")
                self.load_passwords_to_list()
                self.switch_view(1)
                self.pat_entry.clear()
            except Exception as e:
                print(f"Vault creation error: {e}")
                self.show_notification("Could not create a new vault.", is_error=True)
            return

        # If vault exists, try to unlock it
        try:
            with open(VAULT_PATH, 'r') as f:
                vault = json.load(f)
            if "__auth_check__" not in vault:
                raise ValueError("No authentication record found in vault.")

            self.decrypt(vault["__auth_check__"]) # This will raise an exception on failure

            self.show_notification("Login successful!")
            self.load_passwords_to_list()
            self.switch_view(1)
            self.pat_entry.clear()
        except Exception as e:
            print(f"Login error: {e}")
            self.show_notification("Incorrect PAT or corrupted vault.", is_error=True)

    def logout(self):
        """Logs out and returns to the login screen."""
        self.pat = ""
        self.password_list.clear()
        self.search_entry.clear()
        self.switch_view(0)
        self.show_notification("Logged out successfully.")

    def load_passwords_to_list(self):
        """Loads all usernames from the vault into the list widget."""
        self.password_list.clear()
        try:
            with open(VAULT_PATH, 'r') as f:
                vault = json.load(f)

            usernames = [user for user in vault if user != "__auth_check__"]
            for user in sorted(usernames):
                # Create an empty item (we render our own widget for the row)
                item = QListWidgetItem()
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)

                # Custom widget for the list item
                item_widget = QWidget()
                item_widget.setFixedHeight(34)                 # consistent, compact row height that fits the text
                item_layout = QHBoxLayout(item_widget)
                item_layout.setContentsMargins(10, 0, 10, 0)   # vertical margins 0 so content is vertically centered
                item_layout.setSpacing(8)

                user_label = QLabel(user)
                user_label.setStyleSheet("font-size: 14px; background: transparent;")
                user_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                user_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

                copy_button = QPushButton("Copy Password")
                copy_button.setObjectName("copy")
                copy_button.setFixedWidth(120)
                copy_button.setFixedHeight(25)                 # force button height so text is visible
                copy_button.clicked.connect(lambda _, u=user: self.copy_password(u))

                delete_button = QPushButton("Delete")
                delete_button.setObjectName("delete")
                delete_button.setFixedWidth(58)
                delete_button.setFixedHeight(25)
                delete_button.clicked.connect(lambda _, u=user: self.delete_password(u))

                item_layout.addWidget(user_label)
                item_layout.addStretch()
                item_layout.addWidget(copy_button)
                item_layout.addWidget(delete_button)

                item.setSizeHint(item_widget.sizeHint())
                self.password_list.addItem(item)
                self.password_list.setItemWidget(item, item_widget)

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Could not load vault: {e}")
            # The vault might be empty or new, which is fine.

    def filter_passwords(self):
        """Filters the password list based on the search entry text."""
        filter_text = self.search_entry.text().lower()
        for i in range(self.password_list.count()):
            item = self.password_list.item(i)
            widget = self.password_list.itemWidget(item)
            # find the label we set earlier
            label = widget.findChild(QLabel)
            username = label.text() if label is not None else ""
            item.setHidden(filter_text not in username.lower())

    def copy_password(self, user):
        """Decrypts and copies a password to the clipboard."""
        try:
            with open(VAULT_PATH, 'r') as f:
                vault = json.load(f)
            password = self.decrypt(vault[user])
            QApplication.clipboard().setText(password)
            self.show_notification(f"Password for '{user}' copied to clipboard.")
        except Exception as e:
            self.show_notification(f"Could not retrieve password: {e}", is_error=True)

    def add_password(self):
        """Adds a new username and password to the vault."""
        user = self.add_user_entry.text().strip()
        password = self.add_pass_entry.text().strip()

        if not user or not password:
            self.show_notification("Username and password cannot be empty.", is_error=True)
            return

        try:
            # This function is only called from the main page, so vault must exist.
            with open(VAULT_PATH, 'r') as f:
                vault = json.load(f)

            vault[user] = self.encrypt(password)

            with open(VAULT_PATH, 'w') as f:
                json.dump(vault, f, indent=4)

            self.show_notification(f"Password for '{user}' added successfully.")
            self.add_user_entry.clear()
            self.add_pass_entry.clear()
            self.load_passwords_to_list() # Refresh the list

        except Exception as e:
            self.show_notification(f"Error saving to vault: {e}", is_error=True)

    def delete_password(self, user):
        """Deletes a username and password from the vault."""
        try:
            with open(VAULT_PATH, 'r') as f:
                vault = json.load(f)

            if user in vault:
                del vault[user]
                with open(VAULT_PATH, 'w') as f:
                    json.dump(vault, f, indent=4)
                self.show_notification(f"Deleted '{user}' successfully.")
                self.load_passwords_to_list()
            else:
                self.show_notification(f"'{user}' not found.", is_error=True)

        except Exception as e:
            self.show_notification(f"Error deleting '{user}': {e}", is_error=True)

    # --- Core Encryption/Decryption Logic (UNCHANGED) ---
    def derive_key(self, salt):
        kdf = Scrypt(
            salt=bytes.fromhex(salt), length=32, n=2**14, r=8, p=1,
            backend=default_backend()
        )
        return kdf.derive(self.pat.encode())

    def encrypt(self, text):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self.derive_key(salt.hex())
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, text.encode(), None)
        return {"salt": salt.hex(), "nonce": nonce.hex(), "cipher": encrypted.hex()}

    def decrypt(self, data):
        salt = data['salt']
        nonce = bytes.fromhex(data['nonce'])
        cipher = bytes.fromhex(data['cipher'])
        key = self.derive_key(salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, cipher, None).decode()

    def create_icon(self, color):
        """Creates a simple QIcon for the application window."""
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.GlobalColor.transparent)
        p = QPainter(pixmap)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor(color))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, 64, 64, 15, 15)
        p.setPen(QColor(Qt.GlobalColor.white))
        font = QFont("Arial", 32, QFont.Weight.Bold)
        p.setFont(font)
        p.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "SV")
        p.end()
        return QIcon(pixmap)

if __name__ == '__main__':
    #file_path = "password-manager/firstboot.py"
    #if os.path.exists(file_path):
        #firstboot.setup()
    #else:
        app = QApplication(sys.argv)
        window = SecureVault()
        window.show()
        sys.exit(app.exec())
    
