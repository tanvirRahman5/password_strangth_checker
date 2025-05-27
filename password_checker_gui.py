import tkinter as tk
from tkinter import messagebox
import re

# Common weak passwords (expand as needed)
common_passwords = [
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", 
    "monkey", "123456789", "1234567", "111111", "123123"
]

# Function to check strength
def check_password_strength(password):
    if password.lower() in common_passwords:
        return "Very Weak - Common password!"

    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None

    errors = [length_error, digit_error, uppercase_error, lowercase_error, symbol_error]

    if all(not e for e in errors):
        return "Strong 💪"
    elif sum(errors) == 1:
        return "Moderate 👍"
    else:
        return "Weak ⚠️"

# Button callback
def on_check():
    pwd = entry.get()
    if not pwd:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    result = check_password_strength(pwd)
    result_label.config(text=f"Password Strength: {result}")

# GUI Setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x200")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
entry.pack()

tk.Button(root, text="Check Strength", command=on_check, font=("Arial", 11), bg="#4CAF50", fg="white").pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12, "bold"))
result_label.pack(pady=5)

root.mainloop()
