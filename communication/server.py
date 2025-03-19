import socket

def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("started")
    conn, add = server_socket.accept()
    print(f"connected to {add}")
    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                break
            print(f"clint {data}")
            if data.lower() == "exit":
                print("exiting")
                break
            server_responce = input("Server: ")
            conn.send(server_responce.encode())
            
        except ConnectionResetError:
            print("somthing happned retry")
            break
    conn.close()
    server_socket.close()
    print("server closed ")
if __name__ == "__main__":
    start_server("192.168.31.28",5050)