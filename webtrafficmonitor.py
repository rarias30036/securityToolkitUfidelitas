import scapy.all as scapy

class WebTrafficMonitor:
    def __init__(self):
        self.traffic_results = ""

    def monitor_http_traffic(self):
        print("\nMonitoring HTTP traffic...")
        try:
            # Sniff 20 HTTP packets and analyze each packet using the _analyze_http method
            scapy.sniff(filter="tcp port 80", prn=self._analyze_http, count=20)
            self.traffic_results = "HTTP traffic monitoring completed."
            print(self.traffic_results)
        except KeyboardInterrupt:
            # Handle user interruption (Ctrl+C)
            print("\nHTTP traffic monitoring stopped by user.")

    def _analyze_http(self, packet):
        # Check if the packet has a Raw layer (contains the payload)
        if packet.haslayer(scapy.Raw):
            # Decode the payload and ignore any decoding errors
            load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            # Check if the payload contains suspicious keywords like "sql" or "script"
            if "sql" in load.lower() or "script" in load.lower():
                # Print a warning if suspicious traffic is detected
                print(f"\nSuspicious HTTP traffic detected from {packet[scapy.IP].src}")