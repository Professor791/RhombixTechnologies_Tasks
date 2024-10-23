from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

# Packet Analysis Function
def process_packet(packet):
    # Check if the packet has an Ethernet layer
    if Ether in packet:
        print("\nEthernet Frame:")
        print(f'\tSource MAC: {packet[Ether].src}, Destination MAC: {packet[Ether].dst}')
        if IP in packet:
            print(f'\tProtocol: IPv4')
            print(f'\tSource IP: {packet[IP].src}, Destination IP: {packet[IP].dst}')

            # Check if it's ICMP, TCP, or UDP
            if ICMP in packet:
                print(f'\tICMP Packet: Type={packet[ICMP].type} Code={packet[ICMP].code}')
            elif TCP in packet:
                print(f'\tTCP Segment: Source Port={packet[TCP].sport}, Destination Port={packet[TCP].dport}')
            elif UDP in packet:
                print(f'\tUDP Segment: Source Port={packet[UDP].sport}, Destination Port={packet[UDP].dport}')
        else:
            print("\tProtocol: Non-IP")

# Main function to start sniffing
def main():
    # Capture packets, apply a filter for only IP packets, and process them with process_packet function
    print("Starting network sniffer...")
    sniff(filter="ip", prn=process_packet)

if __name__ == "__main__":
    main()
