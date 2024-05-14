from scapy.all import sniff, Ether, IP, TCP, UDP

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")

        payload = packet[IP].payload
        print(f"Payload: {payload}")

def main():
    print("Packet Sniffer started...")

    # Sniff packets
    sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    main()