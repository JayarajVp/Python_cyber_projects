import socket
import threading
from cryptography.fernet import Fernet

def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server started, waiting for connection.")

    conn, addr = server_socket.accept()
    print(f"Connected to {addr}")

    send_key(conn)  
    print("🔑 Key exchanged successfully.")

    def receive_messages():
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                decrypted_data = c_decrypt(data)
                print(f"Client: {decrypted_data}")

                if decrypted_data.lower() == "exit":
                    print("Client exited. Closing connection.")
                    conn.close()
                    server_socket.close()
                    return

            except ConnectionResetError:
                print("Connection lost!")
                break

    def send_messages():
        while True:
            message = input("\nServer: ")
            encrypted_message = c_encrypt(message)
            conn.send(encrypted_message)

            if message.lower() == "exit":
                print("Server exiting...")
                conn.close()
                server_socket.close()
                return

    receive_thread = threading.Thread(target=receive_messages)
    send_thread = threading.Thread(target=send_messages)

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()

def send_key(conn):
    with open("main_key.key", "rb") as key_file:
        main_key = key_file.read()
    with open("key.key", "rb") as session_key_file:
        session_key = session_key_file.read()

    fernet = Fernet(main_key)
    encrypted_session_key = fernet.encrypt(session_key)
    conn.sendall(encrypted_session_key)

def c_encrypt(data):
    with open("key.key", "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

def c_decrypt(data):
    with open("key.key", "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

if __name__ == "__main__":
    start_server("192.168.31.28", 5050)
