from scapy.all import ARP, sniff, IP, Ether, srp
from collections import defaultdict, deque
import time
import os
import threading
import queue

packet_rate_threshold = 100
scan_duration = 10
malformed_ttl_threshold = 1
arp_table ={}
traffic_count = defaultdict(int)
traffic_log = deque(maxlen= 1000)
packet_queue = queue.Queue()

def detect_arp_poison(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            print(f"[ALERT] ARP Spoofing detected! IP {ip} is now at {mac}, was {arp_table[ip]}")
            flush_arp_cache()
            restore_arp(ip)
            return
        arp_table[ip] = mac
def flush_arp_cache():
    print("[INFO] Flushing ARP cache to remove spoofed entries.")
    os.system("netsh interface ip delete arpcache") 
def restore_arp(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=2, verbose=False)
    for _, rcv in ans:
        print(f"[INFO] Restoring correct ARP entry: {ip} → {rcv.hwsrc}")
        arp_table[ip] = rcv.hwsrc
def detect_malformed_packets(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        if ip_layer.len < len(bytes(packet)) or ip_layer.ttl <= malformed_ttl_threshold:
            print(f"[ALERT] Malformed Packet Detected! Source: {ip_layer.src}, TTL: {ip_layer.ttl}")

def monitor_traffic(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        traffic_count[src_ip] += 1
        traffic_log.append((time.time(), src_ip))
def check_traffic_patterns():
    while True:
        time.sleep(scan_duration)
        current_time = time.time()
        packet_counts = defaultdict(int)
        while traffic_log and (current_time - traffic_log[0][0]) < scan_duration:
            _, ip = traffic_log.popleft()
            packet_counts[ip] += 1
        for ip, count in packet_counts.items():
            if count > packet_rate_threshold:
                print(f"[ALERT] Possible DDoS: {ip} sent {count} packets in {scan_duration} sec")
        while traffic_log and (current_time - traffic_log[0][0]) > scan_duration:
            traffic_log.popleft()

def process_packets():
    while True:
        try:
            packet = packet_queue.get(timeout=1)  
            detect_arp_poison(packet)
            detect_malformed_packets(packet)
            monitor_traffic(packet)
            packet_queue.task_done()
        except queue.Empty:
            pass
if __name__ == "__main__":
    print("Starting network attack detection...")
    threading.Thread(target=check_traffic_patterns, daemon=True).start()
    threading.Thread(target=process_packets, daemon=True).start()
    sniff(prn=lambda packet: packet_queue.put(packet), store=False)

        