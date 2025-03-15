import scapy.all as scapy
import threading

class TrafficAnalyzer:
    def __init__(self):
        self.traffic_results = ""  # Store traffic analysis results
        self.is_monitoring = False  # Flag to check if monitoring is ongoing
        self.stop_sniffing = threading.Event()  # Event to stop monitoring

    def analyze_traffic(self):
        print("Starting network traffic analysis...")
        self.is_monitoring = True
        self.stop_sniffing.clear()  # Reset the stop event
        try:
            sniff_thread = threading.Thread(target=self._start_sniffing)  # Start sniffing in a separate thread
            sniff_thread.start()
        except Exception as e:
            print(f"Error during traffic analysis: {e}")

    def _start_sniffing(self):
        scapy.sniff(prn=self._analyze_packet, stop_filter=self._stop_monitoring)  # Start sniffing packets

    def _analyze_packet(self, packet):
        result = ""
        if packet.haslayer(scapy.IP):  # Check if packet has an IP layer
            src_ip = packet[scapy.IP].src  # Get source IP
            dst_ip = packet[scapy.IP].dst  # Get destination IP

            if packet.haslayer(scapy.TCP):  # Check if packet has a TCP layer
                flags = packet[scapy.TCP].flags  # Get TCP flags
                if flags == 'S':  # Check for SYN flag (potential SYN flood attack)
                    result = f"Potential SYN flood attack detected from {src_ip} to {dst_ip}"
            elif packet.haslayer(scapy.UDP):  # Check if packet has a UDP layer
                result = f"UDP packet detected from {src_ip} to {dst_ip}"
            elif packet.haslayer(scapy.ICMP):  # Check if packet has an ICMP layer
                result = f"ICMP (ping) packet detected from {src_ip} to {dst_ip}"
        elif packet.haslayer(scapy.ARP):  # Check if packet has an ARP layer
            result = f"ARP packet detected: {packet[scapy.ARP].op} from {packet[scapy.ARP].psrc} to {packet[scapy.ARP].pdst}"

        if result:
            print(result)  # Print the analysis result

    def _stop_monitoring(self, packet):
        return self.stop_sniffing.is_set()  # Stop monitoring if the stop event is set

    def stop_analysis(self):
        self.stop_sniffing.set()  # Set the stop event
        self.is_monitoring = False
        print("Traffic analysis stopped by user request.")