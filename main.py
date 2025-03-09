from portscanner import PortScanner
from trafficanalyzer import TrafficAnalyzer
from penetrationtester import PenetrationTester
from systemprotector import SystemProtector
from webtrafficmonitor import WebTrafficMonitor
from reporter import Reporter
from database import Database

class SecurityToolkit:
    def __init__(self):
        self.port_scanner = PortScanner()
        self.traffic_analyzer = TrafficAnalyzer() 
        self.penetration_tester = PenetrationTester() 
        self.system_protector = SystemProtector()  
        self.web_traffic_monitor = WebTrafficMonitor()  
        self.reporter = Reporter()  
        self.database = Database()  

    def system_protection_menu(self):
        while True:
            print("\n--- System Protection ---")
            print("1. Block suspicious IP")
            print("2. Unblock IP")
            print("3. List blocked IPs")
            print("4. Return to main menu")
            choice = input("Select an option: ")

            if choice == '1':
                ip = input("Enter the IP to block: ")
                self.system_protector.block_ip(ip) 
                self.reporter.add_result("System Protector", f"Blocked IP: {ip}") 
            elif choice == '2':
                ip = input("Enter the IP to unblock: ")
                self.system_protector.unblock_ip(ip) 
                self.reporter.add_result("System Protector", f"Unblocked IP: {ip}") 
            elif choice == '3':
                self.system_protector.list_blocked_ips() 
            elif choice == '4':
                break 
            else:
                print("Invalid option. Please try again.")

    def menu(self):
        while True:
            print("\n--- Security Toolkit ---")
            print("1. Scan ports")
            print("2. Analyze network traffic")
            print("3. Perform penetration testing")
            print("4. System Protection")
            print("5. Monitor web traffic")
            print("6. Generate security reports")
            print("7. Exit")
            choice = input("Select an option: ")

            if choice == '1':
                print("\n--- Port Scanning Options ---")
                print("1. Auto Scan")
                print("2. Execute Custom Nmap Command")
                scan_choice = input("Select a port scanning option: ")
                if scan_choice == '1':
                    target = input("Enter IP or hostname to scan: ")
                    self.port_scanner.autoScan(target) 
                    self.reporter.add_result("Port Scanner", self.port_scanner.scan_results) 
                elif scan_choice == '2':
                    command = input("Enter the Nmap command to execute: ")
                    self.port_scanner.scan_with_nmap(command) 
                    self.reporter.add_result("Custom Nmap Command", f"Command executed: {command}") 
                else:
                    print("Invalid option. Please try again.")
            elif choice == '2':
                self.traffic_analyzer.analyze_traffic() 
                self.reporter.add_result("Traffic Analyzer", self.traffic_analyzer.traffic_results) 
            elif choice == '3':
                url = input("Enter the URL to test: ")
                self.penetration_tester.test_website(url) 
                self.reporter.add_result("Penetration Tester", self.penetration_tester.test_results) 
            elif choice == '4':
                self.system_protection_menu()  
            elif choice == '5':
                self.web_traffic_monitor.monitor_http_traffic() 
                self.reporter.add_result("Web Traffic Monitor", self.web_traffic_monitor.traffic_results)  
            elif choice == '6':
                self.reporter.generate_report() 
            elif choice == '7':
                break 
            else:
                print("Invalid option. Please try again.") 

if __name__ == "__main__":
    toolkit = SecurityToolkit() 
    toolkit.menu()