import socket
def start_reciver(server_ip, port):
    reciver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reciver_socket.connect((server_ip, port))
    print(f"connected to {server_ip}")
    while True:
        message = input("You:")
        reciver_socket.send(message.encode())
        if message.lower() == "exit":
            print("tata")
            break
        server_responce = reciver_socket.recv(1040).decode()
        print(f"server: {server_responce}") 
    reciver_socket.close()
    print("final tata")
if __name__ == "__main__":
    start_reciver("192.168.31.28",5050)

