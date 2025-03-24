import socket
from cryptography.fernet import Fernet

def start_receiver(server_ip, port):
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.connect((server_ip, port))
    print(f"Connected to server: {server_ip}")
    session_key = receive_key(receiver_socket)
    print("Key exchanged successfully.")

    while True:
        message = input("You: ")
        encrypted_message = encrypt_message(message, session_key)
        receiver_socket.send(encrypted_message)

        if message.lower() == "exit":
            print("Exiting chat.")
            break

        server_response = receiver_socket.recv(1024)
        decrypted_response = decrypt_message(server_response, session_key)
        print(f"Server: {decrypted_response}")  

    receiver_socket.close()
    print("Connection closed.")

def receive_key(sock):
    with open("main_key.key", "rb") as key_file:
        main_key = key_file.read()

    fernet_main = Fernet(main_key)
    encrypted_session_key = sock.recv(1024)
    session_key = fernet_main.decrypt(encrypted_session_key)
    return session_key

def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.decrypt(message).decode()

if __name__ == "__main__":
    start_receiver("192.168.31.28", 5050)
