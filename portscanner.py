import nmap
import subprocess

class PortScanner:
    def __init__(self):
        self.scan_results = ""

    def autoScan(self, target):
        if not target.strip():
            print("Invalid target. Please enter a valid IP or hostname.")
            return

        nmap_scanner = nmap.PortScanner()
        try:
            print(f"Scanning target: {target}...")
            nmap_scanner.scan(target, arguments="-p- -sT")
            self.scan_results = self._format_scan_results(nmap_scanner)
            print(self.scan_results)
        except Exception as e:
            print(f"Error during scanning: {e}")

    def scan_with_nmap(self, command):
        if not command.strip().startswith("nmap"):
            print("Invalid command. Please enter a valid Nmap command.")
            return

        try:
            print(f"Executing custom Nmap command: {command}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            self.scan_results = result.stdout
            print(self.scan_results)
        except Exception as e:
            print(f"Error executing Nmap: {e}")

    def _format_scan_results(self, nmap_scanner):
        result = "********************** Scan Report **********************\n"
        for host in nmap_scanner.all_hosts():
            result += f"\nHost: {host} | State: {nmap_scanner[host].state()}\n"
            for protocol in nmap_scanner[host].all_protocols():
                result += f"\nProtocol: {protocol}\n"
                result += "Port\t\tState\t\tService\n"
                for port in nmap_scanner[host][protocol].keys():
                    name = nmap_scanner[host][protocol][port]['name']
                    state = nmap_scanner[host][protocol][port]['state']
                    result += f"{port}\t\t{state}\t\t{name}\n"
        return result