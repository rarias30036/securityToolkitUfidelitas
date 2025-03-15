import scapy.all as scapy
import threading
from bs4 import BeautifulSoup
import requests

class WebTrafficMonitor:
    def __init__(self):
        self.traffic_results = ""  # Store HTTP traffic monitoring results
        self.is_monitoring = False  # Flag to check if monitoring is ongoing
        self.stop_sniffing = threading.Event()  # Event to stop monitoring

    def monitor_http_traffic(self):
        print("Monitoring HTTP traffic...")
        self.is_monitoring = True
        self.stop_sniffing.clear()  # Reset the stop event
        try:
            sniff_thread = threading.Thread(target=self._start_sniffing)  # Start sniffing in a separate thread
            sniff_thread.start()
        except Exception as e:
            print(f"Error during HTTP traffic monitoring: {e}")

    def _start_sniffing(self):
        scapy.sniff(filter="tcp port 80", prn=self._analyze_http, stop_filter=self._stop_monitoring)  # Sniff HTTP traffic on port 80

    def _analyze_http(self, packet):
        if packet.haslayer(scapy.Raw):  # Check if packet has raw data (HTTP payload)
            load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')  # Decode the payload
            if "sql" in load.lower() or "script" in load.lower():  # Check for suspicious keywords
                print(f"Suspicious HTTP traffic detected from {packet[scapy.IP].src}")  # Print suspicious traffic

    def _stop_monitoring(self, packet):
        return self.stop_sniffing.is_set()  # Stop monitoring if the stop event is set

    def stop_monitoring(self):
        self.stop_sniffing.set()  # Set the stop event
        self.is_monitoring = False
        print("HTTP traffic monitoring stopped by user request.")

    def perform_web_scraping(self, url):
        try:
            print(f"Performing web scraping on {url}...")
            response = requests.get(url)  # Send HTTP request to the URL
            soup = BeautifulSoup(response.text, 'html.parser')  # Parse the HTML content
            title = soup.title.string  # Get the page title
            print(f"Title: {title}")
            links = soup.find_all('a')  # Find all links on the page
            print("Links found on the page:")
            for link in links:
                print(link.get('href'))  # Print each link
        except Exception as e:
            print(f"Error during web scraping: {e}")