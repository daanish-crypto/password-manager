#password manager
import json

pswd = {}

def load_passwords():
    try:
        with open("passwords.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print("⚠️ Error: JSON file is empty or corrupted. Starting fresh.")
        return {}


def save_passwords(pswd):
    with open("passwords.json", "w") as f:
        json.dump(pswd, f)

PAT = "1234"

def pswd_check(verifier):
    pswd = load_passwords()
    user = input("Enter the username: ")
    if user in pswd:
        for attempt in range(3):
            verify = input("Enter your PAT: ")
            if verify == verifier:
                print(f" Username: {user}, Password: {pswd[user]}")
                return
            else:
                print("Incorrect. Try again.")
        print("Access denied")
    else:
        print("Username not found.")

    
def add_pswd():
    pswd = load_passwords()
    user = input("Enter the username: ")
    if user in pswd:
        print("Username already exists.")
    else:
        password = input("Enter the password: ")
        pswd[user] = password
        save_passwords(pswd)
        print(f"Password for {user} added successfully.")


if __name__ == "__main__":
    print("Welcome to the Password Manager")
    operation = input("Choose an operation: (1) Check Password (2) Add Password: ")
    match operation:
        case "1":
            pswd_check(PAT)
        case "2":
            add_pswd()
        case _:
            print("Invalid operation selected.")
    print("Thank you for using the Password Manager!")
