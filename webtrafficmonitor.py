import scapy.all as scapy
from bs4 import BeautifulSoup
import requests

class WebTrafficMonitor:
    def __init__(self):
        self.traffic_results = ""

    def monitor_http_traffic(self):
        print("\n--- Web Traffic Monitor ---")
        print("1. Monitor HTTP Traffic")
        print("2. Perform Web Scraping")
        choice = input("Select an option: ")

        if choice == '1':
            print("\nMonitoring HTTP traffic...")
            try:
                # Sniff 20 HTTP packets and analyze each packet using the _analyze_http method
                scapy.sniff(filter="tcp port 80", prn=self._analyze_http, count=20)
                self.traffic_results = "HTTP traffic monitoring completed."
                print(self.traffic_results)
            except KeyboardInterrupt:
                # Handle user interruption (Ctrl+C)
                print("\nHTTP traffic monitoring stopped by user.")
        elif choice == '2':
            url = input("Enter the URL to scrape: ")
            self._perform_web_scraping(url)
        else:
            print("Invalid option. Please try again.")

    def _analyze_http(self, packet):
        # Check if the packet has a Raw layer (contains the payload)
        if packet.haslayer(scapy.Raw):
            # Decode the payload and ignore any decoding errors
            load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            # Check if the payload contains suspicious keywords like "sql" or "script"
            if "sql" in load.lower() or "script" in load.lower():
                # Print a warning if suspicious traffic is detected
                print(f"\nSuspicious HTTP traffic detected from {packet[scapy.IP].src}")

    def _perform_web_scraping(self, url):
        try:
            print(f"\nPerforming web scraping on {url}...")
            # Send a GET request to the URL
            response = requests.get(url)
            # Parse the HTML content using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            # Extract and print the title of the webpage
            title = soup.title.string
            print(f"Title: {title}")
            # Extract and print all the links on the webpage
            links = soup.find_all('a')
            print("\nLinks found on the page:")
            for link in links:
                print(link.get('href'))
            self.traffic_results = f"Web scraping completed for {url}."
            print(self.traffic_results)
        except Exception as e:
            print(f"\nError during web scraping: {e}")
