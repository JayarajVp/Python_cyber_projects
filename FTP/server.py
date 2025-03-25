import socket
from cryptography.fernet import Fernet
import os
from datetime import datetime

STORAGE_FOLDER = "stored_files"  # Folder to store received files

def start_server_and_receive(ip, port):
    """Starts the server, receives an encrypted file, and processes it."""
    os.makedirs(STORAGE_FOLDER, exist_ok=True)  # Ensure storage folder exists

    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_socket.bind((ip, port))
    s_socket.listen(1)
    print(f"Server listening on {ip}:{port}...")

    conn, addr = s_socket.accept()
    print(f"Connection received from {addr}")

    e_file = conn.recv(10 * 1024 * 1024)  # Receive up to 10MB
    c_decode(e_file, addr)

    conn.send(b"received")  # Send acknowledgment

    while True:
        ch = input("Wanna send something? If yes, press 1. If no, press 0: ")
        if ch == "1":
            send_file(conn)
        elif ch == "0":
            print("Closing connection...")
            break

    conn.close()
    s_socket.close()

def c_decode(e_file, addr):
    """Decrypts the received file using a stored key."""
    try:
        with open("main_key.key", "rb") as key_file:
            key = key_file.read()
        f = Fernet(key)
        decrypted_file = f.decrypt(e_file)
        store(decrypted_file, addr)
    except Exception as e:
        print(f"Decryption failed: {e}")

def store(file_data, addr):
    """Stores the decrypted file in a structured folder."""
    file_name = f"{STORAGE_FOLDER}/{addr[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(file_name, "wb") as file_a:
        file_a.write(file_data)

    print(f"Saved as {file_name}")

def send_file(conn):
    """Sends a file to the connected client."""
    file_path = input("Enter the path of the file you want to send: ")
    
    if not os.path.exists(file_path):
        print(f"File '{file_path}' not found!")
        return

    with open(file_path, "rb") as f:
        file_data = f.read()
        conn.sendall(file_data)

    print(f"File '{file_path}' sent to client.")

# Example usage
if __name__ == "__main__":
    start_server_and_receive("127.0.0.1", 12345)
