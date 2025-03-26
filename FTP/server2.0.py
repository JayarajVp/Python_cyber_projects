import os
import re
import socket

STORAGE_FOLDER = "stored_files"

def ask():
    ch = input("To send press 1, to receive press 2: ")
    if ch == "1":
        si = search_ip()
        if si:
            send_file(si)
    elif ch == "2":
        print("Receiving mode not implemented yet.")
    else:
        print("Invalid choice. Please enter 1 or 2.")

def send_file(si):
    s_ip = "192.168.31.28"  
    s_port = 5151
    os.makedirs(STORAGE_FOLDER, exist_ok=True)

    s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_socket.bind((s_ip, s_port))
    s_socket.listen(1)
    print("Waiting for sender...")

    conn, addr = s_socket.accept()
    print(f"Connected with {addr[0]}")

    if addr[0] == si:
        files_name = list_files()
        print("Available files:", files_name)

        s_file = input("Select file: ")
        file_path = os.path.join(STORAGE_FOLDER, s_file)

        if os.path.exists(file_path):
            with open(file_path, "rb") as file_:
                file_data = file_.read()
                conn.sendall(file_data)
            print("File sent successfully.")
        else:
            print("File not found!")

    conn.close()

def get_IP_MAC():
    print("Scanning network for devices...")

    arp_output = os.popen("arp -a").read()
    devices = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9:-]+)", arp_output)

    if not devices:
        print("No devices found. Try running as Admin or disabling firewall.")
    
    return devices  

def search_ip():
    devices = get_IP_MAC()
    if not devices:
        return None

    ip_list = [ip for ip, _ in devices]
    print("Available IPs:", ip_list)

    selected_ip = input("Enter the IP you want to connect to: ")
    
    if selected_ip in ip_list:
        return selected_ip
    else:
        print("Invalid IP selected.")
        return None

def list_files():
    if not os.path.exists(STORAGE_FOLDER):
        print("Storage folder not found.")
        return []
    
    return [f for f in os.listdir(STORAGE_FOLDER) if os.path.isfile(os.path.join(STORAGE_FOLDER, f))]

ask()
