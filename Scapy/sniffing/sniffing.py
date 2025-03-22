from scapy.all import sniff, wrpcap, get_if_list
import argparse
import time
def list_interfaces():
    interfaces = get_if_list()
    print("\nAvailable Network Interfaces:")
    for iface in interfaces:
        print(f"  - {iface}")
    print("\nChoose the correct interface for sniffing!\n")
def packet_handler(packet):
    print(f"\n[+] Packet Captured at {time.strftime('%H:%M:%S')}")
    print(packet.summary())
    
    if packet.haslayer('IP'):
        print(f"Source IP: {packet['IP'].src} -> Destination IP: {packet['IP'].dst}")
    
    if packet.haslayer('TCP'):
        print(f"TCP Packet - Src Port: {packet['TCP'].sport}, Dst Port: {packet['TCP'].dport}")
    
    if packet.haslayer('UDP'):
        print(f"UDP Packet - Src Port: {packet['UDP'].sport}, Dst Port: {packet['UDP'].dport}")
    
    if packet.haslayer('Raw'):
        print(f"Payload: {packet['Raw'].load}")
def start_sniffing(interface, filter_exp, count, save_file):
    print(f"\n[*] Listening on {interface} with filter: '{filter_exp}'")
    packets = sniff(iface=interface, filter=filter_exp, count=count, prn=packet_handler)
    
    if save_file:
        wrpcap(save_file, packets)
        print(f"Packets saved to {save_file}")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer for Windows")
    parser.add_argument("-l", "--list", action="store_true", help="List available network interfaces")
    parser.add_argument("-i", "--interface", help="Specify network interface for capturing packets")
    parser.add_argument("-f", "--filter", default="", help="Packet filter expression (e.g., 'tcp', 'udp', 'port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-s", "--save", help="Filename to save captured packets")
    
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
    elif args.interface:
        start_sniffing(args.interface, args.filter, args.count, args.save)
    else:
        print("\nUse -l to list interfaces or specify an interface with -i")
