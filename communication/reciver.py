import socket
import threading
from cryptography.fernet import Fernet

def start_receiver(server_ip, port):
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.connect((server_ip, port))
    print(f"Connected to server: {server_ip}")

    # Receive the encrypted session key from server
    session_key = receive_key(receiver_socket)
    print(" Key exchanged successfully! Now you can start the conversation.")

    def receive_messages():
        while True:
            try:
                server_response = receiver_socket.recv(1024)
                if not server_response:
                    break
                decrypted_response = decrypt_message(server_response, session_key)
                print(f"Server: {decrypted_response}")

                if decrypted_response.lower() == "exit":
                    print("Server exited. Closing connection...")
                    receiver_socket.close()
                    return

            except ConnectionResetError:
                print("Connection lost!")
                break

    def send_messages():
        while True:
            message = input("\nYou: ")
            encrypted_message = encrypt_message(message, session_key)
            receiver_socket.send(encrypted_message)

            if message.lower() == "exit":
                print("Client exiting.")
                receiver_socket.close()
                return

    receive_thread = threading.Thread(target=receive_messages)
    send_thread = threading.Thread(target=send_messages)

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()

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
