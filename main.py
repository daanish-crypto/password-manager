#password manager
PAT = "1234"
pswd = {"alexriver@gmail.com": "alexisgreat22",
        "locker": 230996,
        "alecs@gmail.com": "ALTaccount55",
        "geek-hacker": "hacktheplanet99",
        "admin": "admin1234",
        "monkey": "banana123",
        "perfumepoint": "sandalwood2023",
        "alexs_pvt": "instagram2023",
        "University Of Colorado - 329492": "alecscollege2023",
        "nintendoalex": "marioalex",
        "vscode": "010101010",
        }

def pswd_check(verifier):
    user = input("Enter the username: ")
    if user in pswd:
        verify = input("enter your PAT: ")
        if verify == verifier:
            print(f" Username: {user}, Password: {pswd[user]}")
        else:
            print("try again")
            verify = input("enter your PAT: ")
            if verify == verifier:
                print(f" Username: {user}, Password: {pswd[user]}")
            else:
                print("last attempt")
                erify = input("enter your PAT: ")
                if verify == verifier:
                    print(f" Username: {user}, Password: {pswd[user]}")
                else:
                    print("Access denied")
    else:
        print("Username not found.")
    
def add_pswd():
    user = input("Enter the username: ")
    if user in pswd:
        print("Username already exists.")
    else:
        password = input("Enter the password: ")
        pswd[user] = password
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
    print(pswd)