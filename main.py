import sys
import json
import os
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QFrame, QSizePolicy
)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt, QTimer

class PasswordManager(QWidget):
    PAT = "1234" # Personal Access Token
    PSWDS_PATH = "passwords.json" # Path to store passwords

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureVault") # A more engaging title
        self.setGeometry(100, 100, 450, 550) # Slightly larger window
        self.setMinimumSize(400, 500) # Minimum size to maintain layout integrity
        self.init_ui()
        self.apply_styles()

    def init_ui(self):
        # Define fonts for consistent styling
        self.font_regular = QFont("Segoe UI", 10)
        self.font_bold = QFont("Segoe UI", 12, QFont.Weight.Bold)
        self.font_heading = QFont("Segoe UI", 16, QFont.Weight.Bold)

        # Main layout for the entire window
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(30, 30, 30, 30) # Add padding around the edges
        self.main_layout.setSpacing(20) # Spacing between major sections
        self.setLayout(self.main_layout)

        self.setup_login_frame()
        self.setup_main_frame()

        # Initially show login frame and hide main frame
        self.main_layout.addWidget(self.login_frame)
        self.main_layout.addWidget(self.main_frame)
        self.login_frame.show()
        self.main_frame.hide()

        # Center the window on the screen
        self.center_window()

    def center_window(self):
        # Get the screen geometry
        screen_geometry = QApplication.primaryScreen().geometry()
        # Calculate the center point
        center_point = screen_geometry.center()
        # Move the window to the center
        self.move(center_point.x() - self.width() // 2, center_point.y() - self.height() // 2)

    def setup_login_frame(self):
        self.login_frame = QFrame(self)
        self.login_frame.setObjectName("loginFrame") # Object name for QSS
        login_layout = QVBoxLayout()
        login_layout.setContentsMargins(20, 20, 20, 20)
        login_layout.setSpacing(15)
        self.login_frame.setLayout(login_layout)

        # Login heading
        login_heading = QLabel("Welcome to SecureVault")
        login_heading.setFont(self.font_heading)
        login_heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_layout.addWidget(login_heading)

        pat_label = QLabel("Please enter your Personal Access Token (PAT)")
        pat_label.setFont(self.font_regular)
        pat_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_layout.addWidget(pat_label)

        self.pat_entry = QLineEdit()
        self.pat_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.pat_entry.setFont(self.font_regular)
        self.pat_entry.setPlaceholderText("Enter PAT")
        self.pat_entry.setClearButtonEnabled(True) # Clear button for convenience
        login_layout.addWidget(self.pat_entry)

        login_button = QPushButton("Login")
        login_button.setFont(self.font_bold)
        login_button.clicked.connect(self.verify_pat)
        login_layout.addWidget(login_button)

        login_layout.addStretch() # Push content to top

    def setup_main_frame(self):
        self.main_frame = QFrame(self)
        self.main_frame.setObjectName("mainFrame") # Object name for QSS
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        self.main_frame.setLayout(main_layout)

        # Search Section
        search_heading = QLabel("Search Passwords")
        search_heading.setFont(self.font_heading)
        search_heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(search_heading)

        search_input_layout = QHBoxLayout()
        self.search_entry = QLineEdit()
        self.search_entry.setFont(self.font_regular)
        self.search_entry.setPlaceholderText("Enter username to search")
        self.search_entry.setClearButtonEnabled(True)
        search_input_layout.addWidget(self.search_entry)

        search_button = QPushButton("Search")
        search_button.setFont(self.font_bold)
        search_button.clicked.connect(self.search_pswd)
        search_button.setFixedWidth(100) # Fixed width for the button
        search_input_layout.addWidget(search_button)
        main_layout.addLayout(search_input_layout)

        # Separator line (using a QFrame for a visual line)
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        main_layout.addWidget(separator)

        # Add New Password Section
        add_heading = QLabel("Add New Password")
        add_heading.setFont(self.font_heading)
        add_heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(add_heading)

        main_layout.addWidget(QLabel("Username:", font=self.font_regular))
        self.add_user_entry = QLineEdit()
        self.add_user_entry.setFont(self.font_regular)
        self.add_user_entry.setPlaceholderText("Enter username")
        self.add_user_entry.setClearButtonEnabled(True)
        main_layout.addWidget(self.add_user_entry)

        main_layout.addWidget(QLabel("Password:", font=self.font_regular))
        self.add_pass_entry = QLineEdit()
        self.add_pass_entry.setFont(self.font_regular)
        self.add_pass_entry.setEchoMode(QLineEdit.EchoMode.Password) # Mask password input
        self.add_pass_entry.setPlaceholderText("Enter password")
        self.add_pass_entry.setClearButtonEnabled(True)
        main_layout.addWidget(self.add_pass_entry)

        add_button = QPushButton("Add Password")
        add_button.setFont(self.font_bold)
        add_button.clicked.connect(self.add_pswd)
        main_layout.addWidget(add_button)

        main_layout.addStretch() # Push content to top

    def apply_styles(self):
        # QSS for a modern, clean look
        self.setStyleSheet("""
            QWidget {
                background-color: #f0f4f8; /* Light blue-gray background */
                color: #333333; /* Darker text for contrast */
                font-family: "Segoe UI";
            }

            QFrame#loginFrame, QFrame#mainFrame {
                background-color: #ffffff; /* White background for content frames */
                border-radius: 15px; /* Rounded corners */
                box-shadow: 0px 4px 15px rgba(0, 0, 0, 0.1); /* Subtle shadow */
            }

            QLabel {
                color: #333333;
                padding: 5px 0;
            }

            QLabel[font-size="16"] { /* Targeting heading labels */
                color: #2c3e50; /* Darker blue for headings */
                margin-bottom: 10px;
            }

            QLineEdit {
                border: 2px solid #bdc3c7; /* Light gray border */
                border-radius: 8px; /* Rounded corners for input fields */
                padding: 10px; /* Ample padding */
                background-color: #ecf0f1; /* Slightly darker background for input */
                selection-background-color: #3498db; /* Blue selection */
                selection-color: white;
            }

            QLineEdit:focus {
                border: 2px solid #3498db; /* Blue border on focus */
                background-color: #ffffff;
            }

            QPushButton {
                background-color: #3498db; /* Flat blue button */
                color: white;
                border: none;
                border-radius: 10px; /* Rounded corners */
                padding: 12px 25px; /* Generous padding */
                margin-top: 10px;
                font-weight: bold;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            QPushButton:hover {
                background-color: #2980b9; /* Darker blue on hover */
                cursor: pointer; /* Indicate clickable */
            }

            QPushButton:pressed {
                background-color: #21618c; /* Even darker blue when pressed */
                padding-top: 13px; /* Slight press effect */
                padding-bottom: 11px;
            }

            QFrame[frameShape="4"] { /* Targeting the separator HLine */
                border-top: 1px solid #cccccc;
                margin: 15px 0;
            }
        """)

    def load_pswds(self):
        """Loads passwords from the JSON file."""
        if not os.path.exists(self.PSWDS_PATH):
            return {}
        try:
            with open(self.PSWDS_PATH, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            QMessageBox.warning(self, "File Error", "Error decoding passwords.json. File might be corrupted or empty.")
            return {}
        except IOError as e:
            QMessageBox.critical(self, "File Error", f"Could not read passwords.json: {e}")
            return {}

    def save_pswds(self, data):
        """Saves passwords to the JSON file."""
        try:
            with open(self.PSWDS_PATH, "w") as f:
                json.dump(data, f, indent=4) # Use indent for pretty printing
        except IOError as e:
            QMessageBox.critical(self, "File Error", f"Could not save passwords.json: {e}")

    def verify_pat(self):
        """Verifies the Personal Access Token (PAT)."""
        if self.pat_entry.text() == self.PAT:
            self.login_frame.hide()
            self.main_frame.show()
            self.setWindowTitle("SecureVault - Main") # Change title after login
        else:
            QMessageBox.critical(self, "Authentication Failed", "Incorrect PAT. Please try again.")
            self.pat_entry.clear() # Clear incorrect entry

    def search_pswd(self):
        """Searches for a password based on the username."""
        data = self.load_pswds()
        username = self.search_entry.text().strip()
        if not username:
            QMessageBox.warning(self, "Input Required", "Please enter a username to search.")
            return

        if username in data:
            QMessageBox.information(self, "Password Found", f"Username: {username}\nPassword: {data[username]}")
        else:
            QMessageBox.information(self, "Not Found", f"No password saved for username: '{username}'.")
        self.search_entry.clear()

    def add_pswd(self):
        """Adds a new username and password entry."""
        data = self.load_pswds()
        username = self.add_user_entry.text().strip()
        pswd = self.add_pass_entry.text().strip()

        if not username or not pswd:
            QMessageBox.warning(self, "Input Required", "Username and password fields cannot be empty.")
            return

        if username in data:
            reply = QMessageBox.question(
                self, "Overwrite Confirmation",
                f"A password for '{username}' already exists. Do you want to overwrite it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        data[username] = pswd
        self.save_pswds(data)
        QMessageBox.information(self, "Success", "Password saved successfully!")
        self.add_user_entry.clear()
        self.add_pass_entry.clear()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    manager = PasswordManager()
    manager.show()
    sys.exit(app.exec())
