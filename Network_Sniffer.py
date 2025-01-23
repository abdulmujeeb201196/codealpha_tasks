import time
from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}")

        # Check for TCP packets
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP, Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

        # Check for UDP packets
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP, Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

        # Check for ICMP packets
        elif ICMP in packet:
            print("Protocol: ICMP")

        print("-" * 50)

# Duration is attribute from time library, used to stop the sniffer after defined time rather than running in infinite loop and stopping manually with keypress
def start_sniffer(interface=None, duration=5): 
    print(f"Starting packet sniffer for {duration} seconds...")
    start_time = time.time()
    
    # Start sniffing packets
    while time.time() - start_time < duration:
        sniff(iface=interface, prn=packet_callback, store=0, timeout=1)

if __name__ == "__main__":
    
    # Interface set to None, Sniff all the interfaces
    start_sniffer(interface=None, duration=5)  # Run for 5 seconds
    print("Sniffer Stopped")