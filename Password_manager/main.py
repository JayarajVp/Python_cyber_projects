import os
from cryptography.fernet import Fernet
import getpass

def load_key():
    with open("key.key","rb") as key_file:
        return key_file.read()
key = load_key()
cipher= Fernet(key)

def add_password():
    website = input("enter website name ")
    username = input("Enter username ")
    password = getpass.getpass("enter password ")
    enc_pass = cipher.encrypt(password.encode())
    with open ("password.txt", "a") as file:
        file.write(f"{website} | {username} | {enc_pass.decode()}\n")
    print("saved password")
def view_password():
    if not os.path.exists("password.txt"):
        print("password not saved")
        return
    with open("password.txt", "r") as file:
        for line in file.readlines():
            website, username, enc_pass = line.strip().split(" | ")
            dec_password = cipher.decrypt(enc_pass.encode()).decode()
            print(f"Website/App: {website}")
            print(f"Username: {username}")
            print(f"Password: {dec_password}")
            print("-" * 30)
def main():
    while True:
        print("\nPASSWORD MANAGER")
        print("1. Add a new password")
        print("2. View stored passwords")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            add_password()
        elif choice == "2":
            view_password()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main()


