from cryptography.fernet import Fernet
import getpass
import os

try:
    with open("key.key", "rb") as key_file:
        key = key_file.read()
    f = Fernet(key)
except FileNotFoundError:
    print("Encryption key not found! Generate one first.")
    exit()

def encode_and_save(user, website, pword):
    E_pword = f.encrypt(pword.encode()).decode()
    with open("password.txt", "a") as write_file:
        write_file.write(f"{user} | {website} | {E_pword}\n")
    print("Password saved successfully!")

def get_info_from_user():
    user = input("Enter username: ").strip()
    website = input("Enter website: ").strip()
    password = getpass.getpass("Enter password: ").strip()
    encode_and_save(user, website, password)

def auth(s_user, s_website):
    if not os.path.exists("password.txt"):
        print("No password file found. Please save a password first.")
        return

    with open("password.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            try:
                user, website, enc_password = line.strip().split(" | ")
                if user.lower() == s_user.lower() and website.lower() == s_website.lower():
                    try:
                        password = f.decrypt(enc_password.encode()).decode()
                        print(f"Match Found: {user} | {website} | Password: {password}")
                        return
                    except Exception as e:
                        print(f"Error decrypting password: {e}")
                        return
            except ValueError:
                print(f"Skipping invalid entry: {line.strip()}")
                
    print("No match found.")

def ask_user():
    while True:
        print("\n PASSWORD MANAGER MENU")
        print("1 Store a new password")
        print("2 Retrieve a saved password")
        print("3 Exit")

        ch = input("Enter your choice: ").strip()
        
        if ch == "1":
            get_info_from_user()
        elif ch == "2":
            user = input("Enter username to search: ").strip()
            website = input("Enter website name: ").strip()
            auth(user, website)
        elif ch == "3":
            print("Exiting Password Manager. Stay safe!")
            break
        else:
            print("Invalid choice! Please enter 1, 2, or 3.")

ask_user()