import tkinter as tk
from tkinter import messagebox
import json
import os

PAT = "1234"
PSWDS_PATH = "passwords.json"
FONT = "assets/PixelifySans-Bold.ttf"

# json handler ------------

def load_pswds():
    if not os.path.exists(PSWDS_PATH):
        return {}
    try:
        with open(PSWDS_PATH, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_pswds(data):
    with open(PSWDS_PATH, "w") as f:
        json.dump(data, f)

# main stuff ------------

def verify_pat():
    if pat_entry.get() == PAT:
        login_frame.pack_forget()
        main_frame.pack()
    else:
        messagebox.showerror("Error", "incorrect PAT")

def search_pswd():
    data = load_pswds()
    username = search_entry.get()
    if username in data:
        messagebox.showinfo("Found", f"{username}: {data[username]}")
    else:
        messagebox.showerror("Not Found", "this username and password is not saved")

def add_pswd():
    data = load_pswds()
    username = add_user_entry.get()
    pswd = add_pass_entry.get()
    if not username or not pswd:
        messagebox.showerror("Error", "user and password cannot be empty.")
        return
    if username in data:
        messagebox.showwarning("Exists", "this username is already being used by you")
    else:
        data[username] = pswd
        save_pswds(data)
        messagebox.showinfo("Success", "saved successfully.")
        add_user_entry.delete(0, tk.END)
        add_pass_entry.delete(0, tk.END)

# i added gui (tkinter)

root = tk.Tk()
root.title("Password Manager")
root.geometry("400x50")
root.resizable(True, True)

# login with personal access token (PAT) --- (yes i stole the idea of a PAT from github)
login_frame = tk.Frame(root)
tk.Label(login_frame, text="i would kindly reguest for your PAT", font=(FONT, 11)).pack(pady=10)
pat_entry = tk.Entry(login_frame, show="*", font=(FONT, 12))
pat_entry.pack()
tk.Button(login_frame, text="Login", command=verify_pat, font=(FONT, 12)).pack(pady=10)
login_frame.pack()

root.geometry("400x300")
main_frame = tk.Frame(root)


tk.Label(main_frame, text="Search pswd", font=(FONT, 14)).pack(pady=5)
search_entry = tk.Entry(main_frame, font=(FONT, 12))
search_entry.pack()
tk.Button(main_frame, text="Search", command=search_pswd, font=(FONT, 12)).pack(pady=5)


tk.Label(main_frame, text="---------------------------").pack(pady=5)


tk.Label(main_frame, text="Add New pswd", font=(FONT, 14)).pack(pady=5)
tk.Label(main_frame, text="Username:").pack()
add_user_entry = tk.Entry(main_frame, font=(FONT, 12))
add_user_entry.pack()

tk.Label(main_frame, text="pswd:").pack()
add_pass_entry = tk.Entry(main_frame, font=(FONT, 12))
add_pass_entry.pack()

tk.Button(main_frame, text="Add", command=add_pswd, font=(FONT, 12)).pack(pady=5)

# tkinter frameloop
root.mainloop()
