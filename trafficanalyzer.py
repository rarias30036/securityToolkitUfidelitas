import scapy.all as scapy

class TrafficAnalyzer:
    def __init__(self):
        self.traffic_results = ""

    def analyze_traffic(self):
        print("\nStarting network traffic analysis...")
        try:
            # Sniff 50 packets and analyze each packet using the _analyze_packet method
            packets = scapy.sniff(count=50, prn=self._analyze_packet)
            # Format the traffic results and print them
            self.traffic_results = self._format_traffic_results(packets)
            print(self.traffic_results)
        except KeyboardInterrupt:
            # Handle user interruption (Ctrl+C)
            print("\nTraffic analysis stopped by user.")
        except Exception as e:
            print(f"\nError during traffic analysis: {e}")

    def _analyze_packet(self, packet):
        # Check if the packet has an IP layer
        if packet.haslayer(scapy.IP):
            # Get the source and destination IP addresses
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            # Check if the packet has a TCP, UDP, ICMP or ARP layer
            if packet.haslayer(scapy.TCP):
                flags = packet[scapy.TCP].flags
                # Check if the SYN flag is set (potential SYN flood attack)
                if flags == 'S':
                    print(f"Potential SYN flood attack detected from {src_ip} to {dst_ip}")
            elif packet.haslayer(scapy.UDP):
                print(f"UDP packet detected from {src_ip} to {dst_ip}")
            elif packet.haslayer(scapy.ICMP):
                print(f"ICMP (ping) packet detected from {src_ip} to {dst_ip}")
        elif packet.haslayer(scapy.ARP):
            print(f"ARP packet detected: {packet[scapy.ARP].op} from {packet[scapy.ARP].psrc} to {packet[scapy.ARP].pdst}")

    def _format_traffic_results(self, packets):
        result = "********************** Traffic Analysis Report **********************\n"
        result += f"Analyzed {len(packets)} packets.\n"
        return result